# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-License-Identifier: MIT

"""Tests for sequence-number persistence of
:class:`aiocoap.oscore.FilesystemSecurityContext`.

The security property under test is the OSCORE requirement that a sender must
never protect two messages with the same sequence number (and thus the same
nonce) under one set of keys. After an abnormal process shutdown, unused
sequence numbers inside a previously reserved chunk may be skipped, but a
sequence number that was used to build an actually sent ciphertext must never
be handed out again.

The tests therefore do not only check that a counter after restart is larger
than zero. They protect real messages, extract the partial IV (the sequence
number) from the actual ciphertext's Object-Security option, keep a ledger of
every sequence number that ever went into a ciphertext, and assert that no
rebuilt context ever reuses one of them. Failures are injected at every step
of the atomic sequence-file update (temporary file creation, writing,
flushing/fsync, replacement, and the write-back on graceful shutdown).
"""

import gc
import io
import json
import os
import shutil
import tempfile
import unittest

import aiocoap
import aiocoap.defaults
import aiocoap.message

oscore_modules = aiocoap.defaults.oscore_missing_modules()

if not oscore_modules:
    import filelock

    import aiocoap.oscore

_skip_unless_oscore = unittest.skipIf(
    oscore_modules, "Modules missing for running OSCORE tests: %s" % (oscore_modules,)
)


# Fixed test-vector material (same as in the OSCORE plug test common context)
SETTINGS = {
    "sender-id_hex": "00",
    "recipient-id_hex": "01",
    "secret_hex": "0102030405060708090a0b0c0d0e0f10",
    "salt_hex": "9e7ca92223786340",
}


def make_context_dir(basedir):
    """Populate a directory with the static OSCORE parameters.

    The sequence file is deliberately not created, so the first context starts
    at sequence number zero.
    """
    with open(os.path.join(basedir, "settings.json"), "w") as f:
        json.dump(SETTINGS, f)


def protect_and_extract(secctx, payload=b"hello"):
    """Protect a real outgoing request and return the sequence number that
    went into the ciphertext, together with the raw ciphertext bytes.

    The sequence number is read back from the protected message's partial IV,
    not from any in-memory counter, so it reflects what would actually be put
    on the wire.
    """
    message = aiocoap.Message(
        code=aiocoap.POST, uri="coap://oscore.example/test", payload=payload
    )
    message.direction = aiocoap.message.Direction.OUTGOING

    outer_message, _ = secctx.protect(message)

    _, _, unprotected, ciphertext = (
        aiocoap.oscore.CanUnprotect._extract_encrypted0(outer_message)
    )
    seqno = int.from_bytes(unprotected[aiocoap.oscore.COSE_PIV], "big")
    return seqno, bytes(ciphertext)


def read_sequence_file(basedir):
    with open(os.path.join(basedir, "sequence.json")) as f:
        return json.load(f)


def crash(secctx):
    """Emulate an abnormal process shutdown of a security context.

    A real crash never runs ``_destroy``, so the precise in-memory counter is
    not written back. The operating system does release the advisory lock when
    the process dies, and a stale lock file does not block the next holder.
    Both effects are reproduced here without touching sequence.json.
    """
    lockfile = secctx.lockfile
    # Stop __del__ from performing the graceful write-back on garbage collection.
    secctx.lockfile = None
    lockfile.release(force=True)
    if os.path.exists(lockfile.lock_file):
        os.unlink(lockfile.lock_file)


class SequenceNumberLedger:
    """Bookkeeping of every sequence number and ciphertext that was actually
    produced, spanning any number of rebuilt contexts."""

    def __init__(self):
        self.seqnos = []
        self.ciphertexts = set()

    def record(self, seqno, ciphertext):
        # The central security invariant: no sequence number may ever be used
        # in two protected messages.
        if seqno in self.seqnos:
            raise AssertionError(
                "Sequence number %d was reused in a second ciphertext: %r"
                % (seqno, self.seqnos)
            )
        if ciphertext in self.ciphertexts:
            raise AssertionError(
                "Identical ciphertext produced twice (nonce reuse): %r"
                % (ciphertext,)
            )
        self.seqnos.append(seqno)
        self.ciphertexts.add(ciphertext)


@_skip_unless_oscore
class TestFilesystemSecurityContextSequenceNumbers(unittest.TestCase):
    def setUp(self):
        self.basedir = tempfile.mkdtemp()
        make_context_dir(self.basedir)
        self.ledger = SequenceNumberLedger()

    def tearDown(self):
        # Every context created in a test goes through crash() or _destroy(),
        # both of which leave lockfile at None, so the resulting __del__ is a
        # no-op. Run two collection passes while the directory still exists so
        # any context still referenced by a torn-down frame is finalized there
        # rather than after the directory has been removed.
        gc.collect()
        gc.collect()
        shutil.rmtree(self.basedir, ignore_errors=True)

    def send(self, secctx, payload=None):
        if payload is None:
            payload = b"message-%d" % len(self.ledger.seqnos)
        seqno, ciphertext = protect_and_extract(secctx, payload)
        self.ledger.record(seqno, ciphertext)
        return seqno

    def open_context(self, *args, **kwargs):
        return aiocoap.oscore.FilesystemSecurityContext(
            self.basedir, *args, **kwargs
        )

    def open_context_expecting_failure(self, *args, **kwargs):
        """Open a context that is expected to fail in its constructor, and
        return the raised exception.

        The lock is acquired before the failing load runs, so the partially
        constructed object would otherwise complain from ``__del__`` during
        garbage collection. Its lock is released explicitly here instead.
        """

        class ContextFactory(aiocoap.oscore.FilesystemSecurityContext):
            last_partial_instance = None

            def __init__(self, *inner_args, **inner_kwargs):
                try:
                    super().__init__(*inner_args, **inner_kwargs)
                except Exception:
                    ContextFactory.last_partial_instance = self
                    raise

        try:
            ContextFactory(self.basedir, *args, **kwargs)
        except Exception as exception:
            partial = ContextFactory.last_partial_instance
            if partial is not None and partial.lockfile is not None:
                lockfile = partial.lockfile
                partial.lockfile = None
                lockfile.release(force=True)
                if os.path.exists(lockfile.lock_file):
                    os.unlink(lockfile.lock_file)
            return exception

        raise AssertionError("Context construction unexpectedly succeeded")

    def test_first_reservation_persists_a_chunk_boundary(self):
        # The first ever send must persist a reservation boundary ahead of the
        # actually used sequence number, so that a crash right after the send
        # cannot make the number reusable.
        secctx = self.open_context()
        seqno = self.send(secctx)

        self.assertEqual(seqno, 0)
        self.assertEqual(secctx.sender_sequence_number, 1)
        self.assertEqual(secctx.sequence_number_persisted, 10)
        on_disk = read_sequence_file(self.basedir)
        self.assertEqual(on_disk["next-to-send"], 10)
        # The boundary is strictly above every number actually used.
        self.assertGreater(on_disk["next-to-send"], max(self.ledger.seqnos))

    def test_crash_allows_gaps_but_never_reuses_sent_numbers(self):
        secctx = self.open_context()
        for _ in range(3):
            self.send(secctx)
        self.assertEqual(self.ledger.seqnos, [0, 1, 2])
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 10)

        crash(secctx)
        del secctx

        # Rebuilding starts at the persisted boundary: numbers 3..9 are
        # skipped (allowed), number 10 is the first usable one.
        rebuilt = self.open_context()
        self.assertEqual(rebuilt.sender_sequence_number, 10)
        seqno = self.send(rebuilt)
        self.assertEqual(seqno, 10)
        self.assertEqual(self.ledger.seqnos, [0, 1, 2, 10])

        # Another round of sends and a crash still never repeats a number.
        for _ in range(4):
            self.send(rebuilt)
        crash(rebuilt)
        del rebuilt

        again = self.open_context()
        for _ in range(5):
            self.send(again)
        self.assertEqual(len(set(self.ledger.seqnos)), len(self.ledger.seqnos))

    def test_graceful_shutdown_persists_exact_counter_without_gap(self):
        secctx = self.open_context()
        for _ in range(3):
            self.send(secctx)
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 10)

        # A controlled shutdown writes back the exact next-to-send value.
        secctx._destroy()
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 3)

        rebuilt = self.open_context()
        seqno = self.send(rebuilt)
        self.assertEqual(seqno, 3)
        self.assertEqual(self.ledger.seqnos, [0, 1, 2, 3])
        rebuilt._destroy()

    def test_failure_during_temp_file_creation_keeps_old_boundary(self):
        secctx = self.open_context()

        original_mkstemp = tempfile.mkstemp

        def failing_mkstemp(*args, **kwargs):
            raise OSError("injected mkstemp failure")

        tempfile.mkstemp = failing_mkstemp
        try:
            with self.assertRaises(OSError):
                self.send(secctx)
        finally:
            tempfile.mkstemp = original_mkstemp

        # No sequence file was ever created, and nothing was sent successfully.
        self.assertFalse(
            os.path.exists(os.path.join(self.basedir, "sequence.json"))
        )
        crash(secctx)
        del secctx

        rebuilt = self.open_context()
        self.assertEqual(rebuilt.sender_sequence_number, 0)
        seqno = self.send(rebuilt)
        self.assertEqual(seqno, 0)

    def test_failure_during_temp_file_write_leaves_main_file_intact(self):
        class WriteFailingContext(aiocoap.oscore.FilesystemSecurityContext):
            def _store(self):
                tmphand, tmpnam = tempfile.mkstemp(
                    dir=self.basedir, prefix=".sequence-", suffix=".json", text=True
                )
                with io.open(tmphand, "wb"):
                    raise OSError("injected write failure")

        secctx = self.open_context()
        # Consume the whole first reservation (boundary 10) so the durable
        # state has real ciphertexts for 0..9.
        for _ in range(10):
            self.send(secctx)
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 10)
        before = read_sequence_file(self.basedir)
        crash(secctx)
        del secctx

        failing = WriteFailingContext(self.basedir)
        # A rebuilt context starts exactly at the persisted boundary, so its
        # very first send already needs a fresh reservation and hits the
        # failing write before any ciphertext is returned.
        ledger_size_before = len(self.ledger.seqnos)
        with self.assertRaises(OSError):
            self.send(failing)
        self.assertEqual(len(self.ledger.seqnos), ledger_size_before)

        # The atomic replacement never happened: the main file is unchanged.
        self.assertEqual(read_sequence_file(self.basedir), before)
        leftovers = [
            name
            for name in os.listdir(self.basedir)
            if name.startswith(".sequence-")
        ]
        self.assertTrue(leftovers, "expected the leaked temporary file")
        crash(failing)
        del failing

        rebuilt = self.open_context()
        self.assertEqual(rebuilt.sender_sequence_number, 10)
        # The failed protection produced no message, so 10 is still fresh.
        seqno = self.send(rebuilt)
        self.assertEqual(seqno, 10)
        crash(rebuilt)

    def test_failure_during_fsync_keeps_old_boundary(self):
        secctx = self.open_context()
        for _ in range(10):
            self.send(secctx)
        before = read_sequence_file(self.basedir)
        self.assertEqual(before["next-to-send"], 10)

        original_fsync = os.fsync

        class FsyncFailingContext(aiocoap.oscore.FilesystemSecurityContext):
            def _store(self):
                def failing_fsync(fd):
                    raise OSError("injected fsync failure")

                os.fsync = failing_fsync
                try:
                    super()._store()
                finally:
                    os.fsync = original_fsync

        crash(secctx)
        del secctx

        failing = FsyncFailingContext(self.basedir)
        # The rebuilt context starts at the boundary, so its first send already
        # requires a new reservation and fails inside fsync.
        ledger_size_before = len(self.ledger.seqnos)
        with self.assertRaises(OSError):
            self.send(failing)
        # No ciphertext came back from the failed protection.
        self.assertEqual(len(self.ledger.seqnos), ledger_size_before)
        self.assertEqual(read_sequence_file(self.basedir), before)
        crash(failing)
        del failing

        rebuilt = self.open_context()
        self.assertEqual(rebuilt.sender_sequence_number, 10)
        self.assertEqual(self.send(rebuilt), 10)
        crash(rebuilt)

    def test_failure_during_replacement_never_revives_a_sent_number(self):
        secctx = self.open_context()
        for _ in range(10):
            self.send(secctx)
        # All of 0..9 are now used in real ciphertexts; disk boundary is 10.
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 10)
        sent_before_crash = list(self.ledger.seqnos)
        self.assertEqual(sent_before_crash, list(range(10)))

        class ReplaceFailingContext(aiocoap.oscore.FilesystemSecurityContext):
            def _store(self):
                tmphand, tmpnam = tempfile.mkstemp(
                    dir=self.basedir, prefix=".sequence-", suffix=".json", text=True
                )
                data = {
                    "next-to-send": self.sequence_number_persisted,
                    "received": self.recipient_replay_window.persist(),
                }
                with io.open(tmphand, "wb") as tmpfile:
                    tmpfile.write(json.dumps(data).encode("utf8"))
                    tmpfile.flush()
                    os.fsync(tmpfile.fileno())
                raise OSError("injected os.replace failure")

        crash(secctx)
        del secctx

        failing = ReplaceFailingContext(self.basedir)
        # The eleventh message reaches seqno 10 in memory, but protect() aborts
        # when the replacement of sequence.json fails. Crucially, no ciphertext
        # is returned to the caller, so seqno 10 is never actually sent and
        # must not enter the ledger.
        ledger_size_before = len(self.ledger.seqnos)
        with self.assertRaises(OSError):
            self.send(failing)
        self.assertEqual(len(self.ledger.seqnos), ledger_size_before)
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 10)
        crash(failing)
        del failing

        # The rebuilt context starts at the still-durable boundary 10. The
        # number 10 is safe to reuse because its earlier protection never
        # produced a deliverable message; every number below it is forbidden.
        rebuilt = self.open_context()
        self.assertEqual(rebuilt.sender_sequence_number, 10)
        for previously_sent in sent_before_crash:
            self.assertLess(previously_sent, rebuilt.sender_sequence_number)
        seqno = self.send(rebuilt)
        self.assertEqual(seqno, 10)
        self.assertNotIn(seqno, sent_before_crash)
        crash(rebuilt)

    def test_failure_during_graceful_shutdown_falls_back_to_last_boundary(self):
        secctx = self.open_context()
        for _ in range(3):
            self.send(secctx)
        durable_boundary = read_sequence_file(self.basedir)["next-to-send"]
        self.assertEqual(durable_boundary, 10)

        original_store = aiocoap.oscore.FilesystemSecurityContext._store

        def failing_store(self):
            raise OSError("injected shutdown store failure")

        aiocoap.oscore.FilesystemSecurityContext._store = failing_store
        try:
            with self.assertRaises(OSError):
                secctx._destroy()
        finally:
            aiocoap.oscore.FilesystemSecurityContext._store = original_store

        # The failed graceful shutdown leaves the lock held; emulate the
        # process dying before it could retry.
        lockfile = secctx.lockfile
        secctx.lockfile = None
        lockfile.release(force=True)
        if os.path.exists(lockfile.lock_file):
            os.unlink(lockfile.lock_file)
        del secctx

        # Only the last durable boundary is available again -- potentially
        # skipping in-memory progress, but never repeating a sent number.
        rebuilt = self.open_context()
        self.assertEqual(rebuilt.sender_sequence_number, durable_boundary)
        for previously_sent in self.ledger.seqnos:
            self.assertLess(previously_sent, rebuilt.sender_sequence_number)
        self.assertGreaterEqual(self.send(rebuilt), durable_boundary)
        crash(rebuilt)

    def test_two_instances_on_one_directory_are_serialized_by_the_lock(self):
        first = self.open_context()
        self.send(first)

        # A second process must not be able to open the same context while the
        # first one holds it: two live senders would have no shared in-memory
        # counter and could hand out identical sequence numbers.
        with self.assertRaises(filelock.Timeout):
            self.open_context()

        crash(first)
        del first

        # Once the holder is gone, the directory can be opened again and the
        # persisted state is picked up.
        second = self.open_context()
        self.assertEqual(second.sender_sequence_number, 10)
        self.assertEqual(self.send(second), 10)
        second._destroy()

    def test_corrupted_sequence_json_is_rejected(self):
        secctx = self.open_context()
        self.send(secctx)
        crash(secctx)
        del secctx

        sequence_path = os.path.join(self.basedir, "sequence.json")
        with open(sequence_path, "w") as f:
            f.write("{this is not json")
        self.assertIsInstance(
            self.open_context_expecting_failure(),
            (json.JSONDecodeError, ValueError),
        )
        # A failed constructor must not leave a lock behind.
        self.assertFalse(os.path.exists(os.path.join(self.basedir, "lock")))

        # Structurally invalid content is rejected as well.
        with open(sequence_path, "w") as f:
            json.dump({"next-to-send": 0}, f)
        self.assertIsInstance(
            self.open_context_expecting_failure(),
            aiocoap.oscore.FilesystemSecurityContext.LoadError,
        )
        self.assertFalse(os.path.exists(os.path.join(self.basedir, "lock")))

        # And tampering must not silently reset the counter: restore a valid
        # file and ensure the high-water mark is still respected.
        with open(sequence_path, "w") as f:
            json.dump({"next-to-send": 42, "received": "unknown"}, f)
        rebuilt = self.open_context()
        self.assertEqual(rebuilt.sender_sequence_number, 42)
        self.assertEqual(self.send(rebuilt), 42)
        crash(rebuilt)

    def test_chunk_size_one_persists_every_single_number(self):
        # With a chunk size of one, every send is its own durable reservation,
        # so even an immediate crash loses no more than the in-flight number.
        secctx = self.open_context(
            sequence_number_chunksize_start=1, sequence_number_chunksize_limit=1
        )
        for expected in range(5):
            seqno = self.send(secctx)
            self.assertEqual(seqno, expected)
            self.assertEqual(
                read_sequence_file(self.basedir)["next-to-send"], expected + 1
            )

        crash(secctx)
        del secctx
        rebuilt = self.open_context(
            sequence_number_chunksize_start=1, sequence_number_chunksize_limit=1
        )
        self.assertEqual(rebuilt.sender_sequence_number, 5)
        self.assertEqual(self.send(rebuilt), 5)
        crash(rebuilt)

    def test_exhausting_a_reservation_extends_without_reuse(self):
        # Use a tiny fixed chunk so the moment of exhaustion is reached quickly.
        # The first reservation covers 0..2 (boundary 3); the send that would
        # cross it must atomically persist the next boundary first.
        secctx = self.open_context(
            sequence_number_chunksize_start=3, sequence_number_chunksize_limit=3
        )
        first = [self.send(secctx) for _ in range(3)]
        self.assertEqual(first, [0, 1, 2])
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 3)
        self.assertEqual(secctx.sender_sequence_number, 3)

        # Exactly at the exhausted boundary, the next send reserves 3..5.
        crossing = self.send(secctx)
        self.assertEqual(crossing, 3)
        self.assertEqual(read_sequence_file(self.basedir)["next-to-send"], 6)

        # A crash right at the exhaustion point must not make the number that
        # crossed the boundary reusable.
        crash(secctx)
        del secctx
        rebuilt = self.open_context(
            sequence_number_chunksize_start=3, sequence_number_chunksize_limit=3
        )
        self.assertEqual(rebuilt.sender_sequence_number, 6)
        self.assertEqual(self.send(rebuilt), 6)
        self.assertEqual(len(set(self.ledger.seqnos)), len(self.ledger.seqnos))
        crash(rebuilt)

    def test_repeated_crashes_across_growing_chunks_never_reuse(self):
        # With a chunk size that doubles from 2 up to a limit of 8, three sends
        # per round always exhaust the current reservation, so each round ends
        # by persisting a new boundary that the next rebuilt context resumes at.
        secctx = self.open_context(
            sequence_number_chunksize_start=2, sequence_number_chunksize_limit=8
        )
        expected_resume = 0
        for round_index in range(6):
            batch = [self.send(secctx) for _ in range(3)]
            # Every batch starts exactly where the previous durable boundary
            # left off, and uses three consecutive numbers.
            self.assertEqual(batch[0], expected_resume)
            self.assertEqual(batch, [expected_resume, expected_resume + 1,
                                     expected_resume + 2])
            on_disk = read_sequence_file(self.basedir)["next-to-send"]
            # The persisted boundary is always strictly above every number
            # that actually went into a ciphertext.
            self.assertGreater(on_disk, max(self.ledger.seqnos))
            crash(secctx)
            del secctx

            secctx = self.open_context(
                sequence_number_chunksize_start=2,
                sequence_number_chunksize_limit=8,
            )
            # Restart resumes at the durable boundary, never at an already used
            # number; the in-between digits are merely skipped.
            self.assertEqual(secctx.sender_sequence_number, on_disk)
            expected_resume = on_disk

        for _ in range(5):
            self.send(secctx)
        crash(secctx)
        # Global ledger invariant across all six rebuilds.
        self.assertEqual(len(set(self.ledger.seqnos)), len(self.ledger.seqnos))
        self.assertEqual(
            len(self.ledger.ciphertexts), len(set(self.ledger.ciphertexts))
        )

    def test_unknown_received_marker_loads_with_uninitialized_window(self):
        # B.1.2 recovery: an abnormal shutdown while receive state was dirty
        # persists "received": "unknown". The sender counter must still load
        # exactly, while the replay window stays uninitialized for Echo
        # recovery.
        secctx = self.open_context()
        for _ in range(3):
            self.send(secctx)
        secctx._replay_window_changed()
        self.assertEqual(
            read_sequence_file(self.basedir)["received"], "unknown"
        )
        crash(secctx)
        del secctx

        rebuilt = self.open_context()
        self.assertFalse(rebuilt.recipient_replay_window.is_initialized())
        self.assertEqual(rebuilt.sender_sequence_number, 10)
        self.assertEqual(self.send(rebuilt), 10)
        crash(rebuilt)

    def test_sequence_numbers_in_ciphertexts_match_durable_boundaries(self):
        # End-to-end ledger test with a graceful shutdown and a crash mixed,
        # asserting on the actual wire sequence numbers at every step rather
        # than on a restarted counter being nonzero.
        secctx = self.open_context()
        first_batch = [self.send(secctx) for _ in range(4)]
        self.assertEqual(first_batch, [0, 1, 2, 3])

        secctx._destroy()
        secctx = self.open_context()
        self.assertEqual(self.send(secctx), 4)

        for _ in range(8):
            self.send(secctx)
        crash(secctx)
        del secctx

        rebuilt = self.open_context()
        boundary = read_sequence_file(self.basedir)["next-to-send"]
        self.assertEqual(boundary, rebuilt.sender_sequence_number)
        self.send(rebuilt)

        # Every produced ciphertext used a unique number, and every durable
        # boundary was strictly above the numbers protected before it.
        self.assertEqual(len(self.ledger.seqnos), len(set(self.ledger.seqnos)))
        self.assertEqual(
            len(self.ledger.ciphertexts), len(set(self.ledger.ciphertexts))
        )
        crash(rebuilt)


if __name__ == "__main__":
    unittest.main()
