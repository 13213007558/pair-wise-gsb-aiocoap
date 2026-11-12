# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Blockwise (Block2) notification handling of an observed large resource.

These tests drive a client-side :class:`~aiocoap.protocol.BlockwiseRequest`
through a fully in-memory, scripted :class:`~aiocoap.interfaces.TokenInterface`
that never touches a socket. Every CoAP response -- first blocks, late
follow-up blocks, retransmissions and terminal messages -- is pushed in a
deterministic order, so the exact block sequence that the client emits and
assembles can be asserted.

The property under test is that whatever the application receives as one
notification is always assembled from blocks of a *single* resource version
(identified by its ETag): blocks belonging to an older, overtaken notification
must never be spliced into a newer body, an aborted representation must be
discarded rather than mixed, and a stalled or terminated transfer must not
freeze the observation for later notifications.
"""

import asyncio
import contextlib
import gc
import sys
import unittest

import aiocoap
from aiocoap import Message, error, interfaces
from aiocoap.numbers.constants import MAX_REGULAR_BLOCK_SIZE_EXP
from aiocoap.optiontypes import BlockOption

from .fixtures import IsolatedAsyncioTestCase

B = BlockOption.BlockwiseTuple
CONTENT = aiocoap.CONTENT
GET = aiocoap.GET


class ScriptedRemote(interfaces.EndpointAddress):
    """The only remote the in-memory transport ever talks to."""

    is_multicast = False
    is_multicast_locally = False
    scheme = "coap"
    blockwise_key = "scripted"

    def __init__(self, max_exp=MAX_REGULAR_BLOCK_SIZE_EXP):
        self._max_exp = max_exp

    @property
    def maximum_block_size_exp(self):
        return self._max_exp

    @maximum_block_size_exp.setter
    def maximum_block_size_exp(self, value):
        self._max_exp = value

    @property
    def hostinfo(self):
        return "scripted"

    @property
    def hostinfo_local(self):
        return "scripted-local"

    @property
    def uri_base(self):
        return "coap://scripted"

    @property
    def uri_base_local(self):
        return "coap://scripted-local"

    def as_response_address(self):
        return self

    def __hash__(self):
        return 1

    def __eq__(self, other):
        return isinstance(other, ScriptedRemote)


class ScriptedTokenInterface(interfaces.TokenInterface):
    """Remembers every request the client sends and lets the test inject
    responses onto an arbitrary token. This stands in for the TokenManager's
    transport, so MID/ACK handling is intentionally out of scope here."""

    def __init__(self, token_manager):
        self.token_manager = token_manager
        #: Every request message handed down by the client, in send order.
        self.sent = []

    async def shutdown(self):
        pass

    async def recognize_remote(self, message):
        return isinstance(message.remote, ScriptedRemote)

    async def determine_remote(self, message):
        return None

    def send_message(self, message, messageerror_monitor):
        self.sent.append(message)
        return None

    def deliver(self, response, token):
        """Feed a response to the client as if it had arrived on `token`."""
        response.remote = ScriptedRemote()
        response.token = token
        self.token_manager.process_response(response)


def make_message(payload=b"", block2=None, observe=None, etag=None, code=CONTENT):
    message = Message(code=code, payload=payload)
    if block2 is not None:
        message.opt.block2 = block2
    if observe is not None:
        message.opt.observe = observe
    if etag is not None:
        message.opt.etag = etag
    return message


@contextlib.contextmanager
def suppress_observation_finalizer_error(expected):
    """Swallow the redundant GC-time report of an observation iterator whose
    stored exception was already consumed through the public API.

    ClientObservation._Iterator.__del__ only neutralizes a fixed set of
    aiocoap errors; errors such as ResourceChanged/NotImplemented reach the
    unraisable hook even though the application already observed them.
    """
    seen = []
    previous_hook = sys.unraisablehook

    def hook(argument):
        if (
            argument.object is not None
            and getattr(argument.object, "__qualname__", "")
            == "ClientObservation._Iterator.__del__"
            and isinstance(argument.exc_value, expected)
        ):
            seen.append(argument.exc_value)
        else:
            previous_hook(argument)

    sys.unraisablehook = hook
    try:
        yield seen
    finally:
        sys.unraisablehook = previous_hook


class BlockwiseObserveTestCase(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.context = aiocoap.Context(loop=asyncio.get_running_loop())
        self.token_manager = aiocoap.tokenmanager.TokenManager(self.context)
        self.transport = ScriptedTokenInterface(self.token_manager)
        self.token_manager.token_interface = self.transport
        self.context.request_interfaces.append(self.token_manager)

    async def asyncTearDown(self):
        await asyncio.wait_for(self.context.shutdown(), 2)
        await super().asyncTearDown()

    async def _pump(self, iterations=5):
        """Let queued callbacks and the blockwise runner make progress."""
        for _ in range(iterations):
            await asyncio.sleep(0.01)

    async def _wait_sent(self, count):
        deadline = asyncio.get_running_loop().time() + 2
        while asyncio.get_running_loop().time() < deadline:
            if len(self.transport.sent) >= count:
                return self.transport.sent[count - 1]
            await asyncio.sleep(0.01)
        self.fail(
            "expected %d sent messages, only got %d"
            % (count, len(self.transport.sent))
        )

    def _observe_request(self):
        request = Message(code=GET, uri="coap://scripted/big", observe=0)
        request.remote = ScriptedRemote()
        return self.context.request(request)

    # -- the five scenarios -------------------------------------------------

    async def test_late_old_block_with_new_first_block(self):
        """An old block that arrives after the next notification's first block
        still completes only the old version; the new version is assembled
        independently afterwards."""
        request = self._observe_request()
        observation = request.observation
        initial = await self._wait_sent(1)
        token = initial.token

        # Notification observe=10 / ETag v1: block 0 of a 168-byte body.
        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), observe=10, etag=b"v1"), token
        )
        sub_v1 = await self._wait_sent(2)
        self.assertEqual(sub_v1.opt.block2, B(1, False, 3))
        self.assertNotEqual(sub_v1.token, token)

        # Before v1 block 1 returns, notification observe=11 / ETag v2 starts.
        self.transport.deliver(
            make_message(b"C" * 128, B(0, True, 3), observe=11, etag=b"v2"), token
        )
        await self._pump()

        # The late v1 block 1 completes the *old* representation only.
        self.transport.deliver(
            make_message(b"B" * 40, B(1, False, 3), etag=b"v1"), sub_v1.token
        )
        first = await asyncio.wait_for(request.response, 2)
        self.assertEqual(first.opt.observe, 10)
        self.assertEqual(first.opt.etag, b"v1")
        self.assertEqual(first.payload, b"A" * 128 + b"B" * 40)

        iterator = observation.__aiter__()
        # v2 must not be handed out before its own blocks are complete.
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(iterator.__anext__(), 0.3)

        sub_v2 = await self._wait_sent(3)
        self.assertEqual(sub_v2.opt.block2, B(1, False, 3))
        self.assertNotIn(sub_v2.token, (token, sub_v1.token))
        self.transport.deliver(
            make_message(b"D" * 60, B(1, False, 3), etag=b"v2"), sub_v2.token
        )
        await self._pump()
        second = await asyncio.wait_for(iterator.__anext__(), 2)
        self.assertEqual(second.opt.observe, 11)
        self.assertEqual(second.opt.etag, b"v2")
        self.assertEqual(second.payload, b"C" * 128 + b"D" * 60)
        # No byte of the abandoned-in-transit ordering leaks into the new body.
        self.assertNotIn(b"A", second.payload)
        self.assertNotIn(b"B", second.payload)

    async def test_etag_change_mid_transfer_is_aborted_not_merged(self):
        """If the ETag differs between two blocks of one notification the
        partial representation is abandoned with ResourceChanged instead of
        joining two versions into one body."""
        with suppress_observation_finalizer_error(
            error.ResourceChanged
        ) as suppressed:
            await self._etag_change_mid_transfer()
        self.assertEqual(len(suppressed), 1)
        self.assertIsInstance(suppressed[0], error.ResourceChanged)

    async def _etag_change_mid_transfer(self):
        request = self._observe_request()
        observation = request.observation
        initial = await self._wait_sent(1)
        token = initial.token

        # Drain the observation in a long-lived pull task so the error is
        # consumed through the public iteration API (the iterator's finalizer
        # otherwise re-raises the stored exception during GC).
        observed_errors = []

        async def pull():
            try:
                async for _ in observation:
                    pass
            except Exception as exc:  # noqa: BLE001 - recorded for assertion
                observed_errors.append(exc)

        pull_task = asyncio.create_task(pull())

        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), observe=20, etag=b"v1"), token
        )
        sub = await self._wait_sent(2)

        # Follow-up block belongs to a changed representation (ETag v2).
        self.transport.deliver(
            make_message(b"B" * 40, B(1, False, 3), etag=b"v2"), sub.token
        )

        await asyncio.wait_for(pull_task, 2)
        self.assertEqual(len(observed_errors), 1)
        self.assertIsInstance(observed_errors[0], error.ResourceChanged)
        with self.assertRaises(error.ResourceChanged):
            await asyncio.wait_for(request.response, 2)

        # The observation has terminated: a later notification on the same
        # token cannot resurrect a half-assembled body or restart the stream.
        self.assertTrue(observation.cancelled)
        self.transport.deliver(
            make_message(b"Z" * 30, observe=21, etag=b"v3"), token
        )
        await self._pump()
        self.assertTrue(pull_task.done())
        self.assertEqual(len(observed_errors), 1)
        # Force the iterator finalizer while our hook is still installed.
        gc.collect()

    async def test_distinct_versions_remain_isolated(self):
        """Two complete, separately versioned notifications that overlap in
        time are each delivered whole with their own Observe/ETag/body."""
        request = self._observe_request()
        observation = request.observation
        initial = await self._wait_sent(1)
        token = initial.token

        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), observe=30, etag=b"v1"), token
        )
        sub_v1 = await self._wait_sent(2)
        # v4 first block overtakes while v1 block 1 is still outstanding.
        self.transport.deliver(
            make_message(b"Q" * 128, B(0, True, 3), observe=31, etag=b"v4"), token
        )
        await self._pump()
        self.transport.deliver(
            make_message(b"B" * 40, B(1, False, 3), etag=b"v1"), sub_v1.token
        )
        first = await asyncio.wait_for(request.response, 2)
        self.assertEqual(
            (first.opt.observe, first.opt.etag), (30, b"v1")
        )
        self.assertEqual(first.payload, b"A" * 128 + b"B" * 40)

        iterator = observation.__aiter__()
        sub_v4 = await self._wait_sent(3)
        self.transport.deliver(
            make_message(b"R" * 30, B(1, False, 3), etag=b"v4"), sub_v4.token
        )
        await self._pump()
        second = await asyncio.wait_for(iterator.__anext__(), 2)
        self.assertEqual((second.opt.observe, second.opt.etag), (31, b"v4"))
        self.assertEqual(second.payload, b"Q" * 128 + b"R" * 30)
        self.assertNotIn(b"A", second.payload)
        self.assertNotIn(b"B", second.payload)

    async def test_block_size_renegotiation_mid_transfer(self):
        """A smaller Block2 size announced on a later block re-numbers the
        requests but keeps a single, contiguous body."""
        request = self._observe_request()
        initial = await self._wait_sent(1)
        token = initial.token

        # Block 0 uses size exponent 3 (128 bytes) and has more.
        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), observe=40, etag=b"v1"), token
        )
        first_sub = await self._wait_sent(2)
        self.assertEqual(first_sub.opt.block2, B(1, False, 3))

        # Server shrinks to exponent 2 (64 bytes): block 2 starts at byte 128.
        self.transport.deliver(
            make_message(b"B" * 64, B(2, True, 2), etag=b"v1"), first_sub.token
        )
        second_sub = await self._wait_sent(3)
        self.assertEqual(second_sub.opt.block2, B(3, False, 2))
        self.assertEqual(second_sub.opt.block2.start, 192)

        self.transport.deliver(
            make_message(b"C" * 30, B(3, False, 2), etag=b"v1"), second_sub.token
        )
        assembled = await asyncio.wait_for(request.response, 2)
        self.assertEqual(assembled.opt.observe, 40)
        self.assertEqual(assembled.opt.etag, b"v1")
        self.assertEqual(
            assembled.payload, b"A" * 128 + b"B" * 64 + b"C" * 30
        )

    async def test_duplicate_first_block_is_not_duplicated(self):
        """A retransmitted first block of a notification must not append its
        payload twice or trigger a second block request."""
        request = self._observe_request()
        observation = request.observation
        initial = await self._wait_sent(1)
        token = initial.token

        # A small initial representation establishes the observation.
        self.transport.deliver(
            make_message(b"init" * 5, observe=50, etag=b"v0"), token
        )
        await asyncio.wait_for(request.response, 2)
        iterator = observation.__aiter__()

        # Notification 51, block 0 -- delivered twice, byte-identical.
        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), observe=51, etag=b"v1"), token
        )
        sub = await self._wait_sent(2)
        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), observe=51, etag=b"v1"), token
        )
        await self._pump()
        # The duplicate is absorbed by the observation layer (identical Observe
        # value): still only one outstanding block request, no new send.
        self.assertEqual(len(self.transport.sent), 2)

        self.transport.deliver(
            make_message(b"B" * 40, B(1, False, 3), etag=b"v1"), sub.token
        )
        await self._pump()
        notification = await asyncio.wait_for(iterator.__anext__(), 2)
        self.assertEqual(notification.opt.observe, 51)
        self.assertEqual(notification.opt.etag, b"v1")
        # 168 bytes proves block 0 was counted once, not 296.
        self.assertEqual(notification.payload, b"A" * 128 + b"B" * 40)

    async def test_duplicate_block0_at_assembly_layer_is_rejected(self):
        """Without the observation de-duplication layer (a plain GET), a
        retransmitted block 0 arriving on the block-1 sub-request is a block
        number mismatch: the transfer is aborted rather than re-inserting the
        bytes, so no body is ever produced out of duplicated blocks."""
        request = Message(code=GET, uri="coap://scripted/big")
        request.remote = ScriptedRemote()
        request = self.context.request(request)
        initial = await self._wait_sent(1)
        token = initial.token

        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), etag=b"v1"), token
        )
        sub = await self._wait_sent(2)
        self.assertEqual(sub.opt.block2, B(1, False, 3))

        # A block 0 answer where block 1 was requested: gap/overlap, refused.
        self.transport.deliver(
            make_message(b"A" * 128, B(0, True, 3), etag=b"v1"), sub.token
        )
        with self.assertRaises(error.NotImplemented):
            await asyncio.wait_for(request.response, 2)

    async def test_terminal_notification_ends_observation_after_full_body(self):
        """A notification that ends the observation still delivers its complete
        blockwise body first, then stops the iterator cleanly."""
        request = self._observe_request()
        observation = request.observation
        initial = await self._wait_sent(1)
        token = initial.token

        self.transport.deliver(
            make_message(b"init" * 5, observe=60, etag=b"v0"), token
        )
        await asyncio.wait_for(request.response, 2)
        iterator = observation.__aiter__()

        # Final notification: block 0 carries the last Observe value ...
        self.transport.deliver(
            make_message(b"T" * 128, B(0, True, 3), observe=61, etag=b"v9"), token
        )
        sub = await self._wait_sent(2)
        # ... and the last block completes the representation.
        self.transport.deliver(
            make_message(b"U" * 32, B(1, False, 3), etag=b"v9"), sub.token
        )
        await self._pump()
        terminal = await asyncio.wait_for(iterator.__anext__(), 2)
        self.assertEqual(terminal.opt.observe, 61)
        self.assertEqual(terminal.opt.etag, b"v9")
        self.assertEqual(terminal.payload, b"T" * 128 + b"U" * 32)

        # A subsequent response without an Observe option ends the observation.
        self.transport.deliver(make_message(b"END" * 3, etag=b"v9"), token)
        await self._pump()
        with self.assertRaises(StopAsyncIteration):
            await asyncio.wait_for(iterator.__anext__(), 1)
        self.assertTrue(observation.cancelled)


if __name__ == "__main__":
    unittest.main()
