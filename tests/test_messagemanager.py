# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests for the MessageManager's NSTART backlog, retransmission handling and
the propagation of request cancellation into the transmission wait queue.

These run against a controllable in-process MessageInterface so that the exact
wire send list, the token registry and the timer state can be inspected while
ACK, RST, retransmission-timeout, cancellation and shutdown events are
interleaved."""

import asyncio
import types
import unittest

from .fixtures import IsolatedAsyncioTestCase

from aiocoap import Context, Message, POST
from aiocoap import error
from aiocoap.interfaces import MessageInterface
from aiocoap.messagemanager import MessageManager
from aiocoap.numbers.codes import EMPTY, CONTENT
from aiocoap.numbers.constants import TransportTuning
from aiocoap.numbers.types import CON, NON, ACK, RST
from aiocoap.pipe import Pipe
from aiocoap.protocol import Request
from aiocoap.tokenmanager import TokenManager


class FastTuning(TransportTuning):
    ACK_TIMEOUT = 0.02
    ACK_RANDOM_FACTOR = 1.0


class GiveUpQuicklyTuning(TransportTuning):
    ACK_TIMEOUT = 0.01
    ACK_RANDOM_FACTOR = 1.0
    MAX_RETRANSMIT = 1


class FakeRemote:
    """Minimal hashable EndpointAddress stand-in; identity is the remote name."""

    def __init__(self, name):
        self.name = name
        self.hostinfo = name
        self.hostinfo_local = "local"
        self.uri_base = "coap://" + name
        self.uri_base_local = "coap://local"
        self.is_multicast = False
        self.is_multicast_locally = False
        self.scheme = "coap"
        self.blockwise_key = ("fake", name)

    def as_response_address(self):
        return self

    def __eq__(self, other):
        return isinstance(other, FakeRemote) and other.name == self.name

    def __hash__(self):
        return hash(("FakeRemote", self.name))

    def __repr__(self):
        return "<FakeRemote %s>" % self.name


class ControllableMessageInterface(MessageInterface):
    """MessageInterface that never loses anything: every send is recorded, and
    nothing is ever delivered unless the test feeds it back itself."""

    def __init__(self):
        self.sent = []
        self.shutdown_called = False

    async def shutdown(self):
        self.shutdown_called = True

    def send(self, message):
        self.sent.append(message)

    async def recognize_remote(self, remote):
        return False

    async def determine_remote(self, message):
        return None


class MessageManagerTest(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.loop = asyncio.get_running_loop()
        self.context = Context(loop=self.loop)
        self.token_manager = TokenManager(self.context)
        self.manager = MessageManager(self.token_manager)
        self.interface = ControllableMessageInterface()
        self.manager.message_interface = self.interface
        self.token_manager.token_interface = self.manager
        self.context.request_interfaces.append(self.token_manager)

        self.remote_a = FakeRemote("device-a")
        self.remote_b = FakeRemote("device-b")

        self.monitor_calls = []

    def monitor(self, label):
        def _monitor():
            self.monitor_calls.append(label)

        return _monitor

    def make_con(self, remote, label, tuning=FastTuning):
        message = Message(code=POST, payload=label.encode(), transport_tuning=tuning())
        message.remote = remote
        return message

    def send_con(self, remote, label, tuning=FastTuning):
        message = self.make_con(remote, label, tuning)
        canceller = self.manager.send_message(message, self.monitor(label))
        self.assertIsNotNone(canceller, "CON messages must provide a send canceller")
        return message, canceller

    def empty_message(self, mtype, remote, mid):
        message = Message(_mtype=mtype, code=EMPTY, payload=b"")
        message.remote = remote
        message.mid = mid
        return message

    def piggybacked_response(self, request):
        response = Message(
            code=CONTENT,
            _mtype=ACK,
            _mid=request.mid,
        )
        response.token = request.token
        response.remote = request.remote.as_response_address()
        return response

    def test_backlogged_cancel_prevents_later_send(self):
        # One CON in flight blocks the NSTART slot; the later commands queue up.
        first, _ = self.send_con(self.remote_a, "first")
        second, cancel_second = self.send_con(self.remote_a, "second")
        third, _ = self.send_con(self.remote_a, "third")

        self.assertEqual(self.interface.sent, [first])
        self.assertEqual(
            [entry[0] for entry in self.manager._backlogs[self.remote_a]],
            [second, third],
        )

        # Operator cancels the command that has never touched the wire.
        cancel_second()

        # It must be gone from the queue but must not have disturbed its neighbors.
        self.assertEqual(
            [entry[0] for entry in self.manager._backlogs[self.remote_a]],
            [third],
        )
        self.assertEqual(self.interface.sent, [first])

        # When the in-flight exchange concludes, only the still-valid request goes out.
        self.manager.dispatch_message(self.empty_message(ACK, self.remote_a, first.mid))

        self.assertEqual(self.interface.sent, [first, third])
        self.assertNotIn(second, self.interface.sent)
        # The surviving request is now in flight; an empty backlog key remains
        # (it is recreated by _add_exchange) and holds no cancelled message.
        self.assertEqual(self.manager._backlogs[self.remote_a], [])
        self.assertEqual(self.monitor_calls, [])

    def test_backlog_cancel_is_precise_and_idempotent(self):
        first, _ = self.send_con(self.remote_a, "first")
        second, cancel_second = self.send_con(self.remote_a, "second")
        third, cancel_third = self.send_con(self.remote_a, "third")

        cancel_second()
        # A second cancellation must be a harmless no-op.
        cancel_second()
        cancel_third()

        self.assertEqual(
            [entry[0] for entry in self.manager._backlogs[self.remote_a]], []
        )

        self.manager.dispatch_message(self.empty_message(ACK, self.remote_a, first.mid))

        # Nothing queued remains, so the ACK empties (and removes) the backlog.
        self.assertEqual(self.interface.sent, [first])
        self.assertNotIn(self.remote_a, self.manager._backlogs)
        # The congestion slot was not released early: the third request never sent.
        self.assertNotIn(third, self.interface.sent)

    def test_inflight_cancel_keeps_exchange_and_retransmits(self):
        first, cancel_first = self.send_con(self.remote_a, "first")
        key = (self.remote_a, first.mid)
        original_handle = self.manager._active_exchanges[key][1]

        # Cancelling an already transmitted command only ends the local wait.
        cancel_first()

        self.assertIn(key, self.manager._active_exchanges)
        self.assertFalse(original_handle.cancelled())

        # Let the retransmission timer expire: the exchange must still be alive
        # and the message must get retransmitted with a fresh timer.
        async def run():
            await asyncio.sleep(FastTuning.ACK_TIMEOUT * 1.25)

        self.loop.run_until_complete(run())

        self.assertEqual(self.interface.sent, [first, first])
        self.assertIn(key, self.manager._active_exchanges)
        self.assertTrue(original_handle.cancelled())
        new_handle = self.manager._active_exchanges[key][1]
        self.assertFalse(new_handle.cancelled())

        # The exchange still concludes normally on ACK and frees the slot.
        self.manager.dispatch_message(self.empty_message(ACK, self.remote_a, first.mid))
        self.assertNotIn(key, self.manager._active_exchanges)
        self.assertNotIn(self.remote_a, self.manager._backlogs)

    def test_rst_after_inflight_cancel_does_not_notify_abandoned_request(self):
        first, cancel_first = self.send_con(self.remote_a, "first")

        cancel_first()
        self.manager.dispatch_message(self.empty_message(RST, self.remote_a, first.mid))

        # The guarded monitor swallows the RST instead of raising into the
        # cancelled request, and the exchange is still cleaned up.
        self.assertEqual(self.monitor_calls, [])
        self.assertNotIn(
            (self.remote_a, first.mid), self.manager._active_exchanges
        )
        self.assertNotIn(self.remote_a, self.manager._backlogs)

    def test_rst_without_cancel_calls_monitor_and_continues_backlog(self):
        first, _ = self.send_con(self.remote_a, "first")
        second, _ = self.send_con(self.remote_a, "second")

        self.manager.dispatch_message(self.empty_message(RST, self.remote_a, first.mid))

        self.assertEqual(self.monitor_calls, ["first"])
        # The RST removed the exchange, so the backlog advances immediately.
        self.assertEqual(self.interface.sent, [first, second])
        self.assertEqual(self.manager._backlogs[self.remote_a], [])

    def test_other_remote_is_not_blocked_by_cancel(self):
        first_a, _ = self.send_con(self.remote_a, "first-a")
        second_a, cancel_second_a = self.send_con(self.remote_a, "second-a")

        # A different device has its own exchange/backlog pair and goes straight out.
        first_b, _ = self.send_con(self.remote_b, "first-b")
        self.assertEqual(self.interface.sent, [first_a, first_b])

        cancel_second_a()
        self.manager.dispatch_message(
            self.empty_message(ACK, self.remote_a, first_a.mid)
        )
        self.manager.dispatch_message(
            self.empty_message(ACK, self.remote_b, first_b.mid)
        )

        self.assertEqual(self.interface.sent, [first_a, first_b])
        self.assertNotIn(self.remote_a, self.manager._backlogs)
        self.assertNotIn(self.remote_b, self.manager._backlogs)
        self.assertEqual(
            self.manager._active_exchanges,
            {} if self.manager._active_exchanges is not None else None,
        )

    def test_non_messages_have_no_canceller(self):
        message = self.make_con(self.remote_a, "non")
        message.mtype = NON
        self.assertIsNone(self.manager.send_message(message, self.monitor("non")))
        self.assertEqual(self.interface.sent, [message])

    def test_canceller_after_conclusion_is_noop(self):
        first, cancel_first = self.send_con(self.remote_a, "first")
        self.manager.dispatch_message(self.empty_message(ACK, self.remote_a, first.mid))

        # The exchange has concluded before cancellation arrives.
        cancel_first()
        self.assertEqual(self.interface.sent, [first])
        self.assertEqual(self.monitor_calls, [])

    def test_retransmission_exhaustion_clears_backlog_and_reports_error(self):
        first, _ = self.send_con(
            self.remote_a, "first", tuning=GiveUpQuicklyTuning
        )
        second, cancel_second = self.send_con(
            self.remote_a, "second", tuning=GiveUpQuicklyTuning
        )

        async def run():
            # Initial transmit plus one retransmission, then give-up.
            await asyncio.sleep(GiveUpQuicklyTuning.ACK_TIMEOUT * 4)

        self.loop.run_until_complete(run())

        # The failed exchange and the whole per-remote backlog are gone, and the
        # queued message was neither sent nor cancelled by its owner.
        self.assertEqual(self.manager._active_exchanges, {})
        self.assertNotIn(self.remote_a, self.manager._backlogs)
        self.assertNotIn(second, self.interface.sent)
        self.assertEqual(self.interface.sent, [first, first])
        # Cancelling afterwards must not resurrect anything.
        cancel_second()

    def test_shutdown_cancels_timers_and_cancellers_stay_safe(self):
        first, cancel_first = self.send_con(self.remote_a, "first")
        second, cancel_second = self.send_con(self.remote_a, "second")
        key = (self.remote_a, first.mid)
        handle = self.manager._active_exchanges[key][1]

        async def run():
            await self.manager.shutdown()

        self.loop.run_until_complete(run())

        self.assertTrue(self.interface.shutdown_called)
        self.assertTrue(handle.cancelled())
        self.assertIsNone(self.manager._active_exchanges)

        # Cancellation after teardown must not raise.
        cancel_first()
        cancel_second()
        # Nothing queued was ever transmitted.
        self.assertEqual(self.interface.sent, [first])


class RequestCancellationIntegrationTest(IsolatedAsyncioTestCase):
    """End-to-end propagation through TokenManager (token registry) and the
    Request/Pipe cancellation path."""

    async def asyncSetUp(self):
        self.loop = asyncio.get_running_loop()
        self.context = Context(loop=self.loop)
        self.token_manager = TokenManager(self.context)
        self.manager = MessageManager(self.token_manager)
        self.interface = ControllableMessageInterface()
        self.manager.message_interface = self.interface
        self.token_manager.token_interface = self.manager
        self.context.request_interfaces.append(self.token_manager)

        self.remote = FakeRemote("device")

    def start_request(self, label):
        message = Message(
            code=POST, payload=label.encode(), transport_tuning=FastTuning()
        )
        message.remote = self.remote
        pipe = Pipe(message, self.context.log)
        request = Request(pipe, self.loop, self.context.log)
        self.token_manager.request(pipe)
        return message, request

    def respond(self, request_message):
        response = Message(code=CONTENT, _mtype=ACK, _mid=request_message.mid)
        response.token = request_message.token
        response.remote = self.remote.as_response_address()
        self.manager.dispatch_message(response)

    async def test_cancelled_queued_request_never_sends_and_deregisters_token(self):
        first, first_request = self.start_request("first")
        second, second_request = self.start_request("second")
        third, third_request = self.start_request("third")

        self.assertEqual(len(self.token_manager.outgoing_requests), 3)
        self.assertEqual(self.interface.sent, [first])

        second_request.response.cancel()
        await asyncio.sleep(0)

        # Token registry no longer knows the cancelled request.
        self.assertEqual(len(self.token_manager.outgoing_requests), 2)
        self.assertNotIn(
            (second.token, self.remote), self.token_manager.outgoing_requests
        )

        # Concluding the first exchange sends the third, never the second.
        self.respond(first)
        await asyncio.sleep(0)

        self.assertTrue(first_request.response.done())
        self.assertEqual(self.interface.sent, [first, third])

        self.respond(third)
        await asyncio.sleep(0)
        self.assertTrue(third_request.response.done())

        # All exchanges, backlogs and timers are cleaned up.
        self.assertEqual(self.manager._active_exchanges, {})
        self.assertEqual(self.manager._backlogs, {})
        self.assertEqual(self.token_manager.outgoing_requests, {})

    async def test_context_shutdown_with_cancelled_and_pending_requests(self):
        first, first_request = self.start_request("first")
        second, second_request = self.start_request("second")

        second_request.response.cancel()
        await asyncio.sleep(0)

        await self.context.shutdown()

        # The still-pending request is terminated with LibraryShutdown rather
        # than dangling; no queued message was transmitted.
        self.assertTrue(first_request.response.done())
        with self.assertRaises(error.LibraryShutdown):
            first_request.response.result()
        self.assertEqual(self.interface.sent, [first])


if __name__ == "__main__":
    unittest.main()
