# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests for multicast requests (Context.multicast_request).

No actual multicast networking is involved here: A fake token interface
simulates a small network of devices that answer a single multicast
request. The tests thus double as an example of what an application sees
when devices respond whole, in blocks, twice, or too late.
"""

import asyncio

from aiocoap import Message, Context
from aiocoap.numbers import GET, CONTENT, NON
from aiocoap.numbers.constants import MAX_REGULAR_BLOCK_SIZE_EXP
from aiocoap.message import Direction
from aiocoap.tokenmanager import TokenManager
from aiocoap import interfaces

from .fixtures import WithLogMonitoring, no_warnings, precise_warnings


class FakeRemote:
    """Duck-typed stand-in for an interfaces.EndpointAddress of a simulated
    device (or of the multicast group itself)."""

    def __init__(self, name, is_multicast=False):
        self.name = name
        self._is_multicast = is_multicast

    @property
    def is_multicast(self):
        return self._is_multicast

    @property
    def is_multicast_locally(self):
        return False

    @property
    def maximum_block_size_exp(self):
        return MAX_REGULAR_BLOCK_SIZE_EXP

    @property
    def maximum_payload_size(self):
        return 1124

    def as_response_address(self):
        return self

    def __eq__(self, other):
        return isinstance(other, FakeRemote) and other.name == self.name

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return "<FakeRemote %s>" % self.name


MULTICAST_REMOTE = FakeRemote("all-devices", is_multicast=True)


class FakeMulticastNetwork(interfaces.TokenInterface):
    """A TokenInterface that, instead of sending anything on a network,
    hands outgoing messages to simulated devices and feeds their responses
    back into the token manager."""

    def __init__(self, loop):
        self.loop = loop
        self.devices = []
        self.token_manager = None  # set by the test once both exist
        self._mid = 0

    def next_mid(self):
        self._mid += 1
        return self._mid

    # TokenInterface implementation

    async def shutdown(self):
        pass

    async def recognize_remote(self, message):
        return isinstance(message.remote, FakeRemote)

    async def determine_remote(self, message):
        return MULTICAST_REMOTE

    def send_message(self, message, messageerror_monitor):
        if message.remote.is_multicast:
            for device in self.devices:
                device.on_multicast_request(message)
        else:
            for device in self.devices:
                if device.remote == message.remote:
                    device.on_unicast_request(message, messageerror_monitor)
                    break
            else:
                raise AssertionError("Request to unknown device %r" % message.remote)

    # device side helper

    def inject_response(self, device, request, payload, block2=None, mid=None):
        """Deliver a response message from a device, like the transport
        would."""
        response = Message(
            code=CONTENT,
            payload=payload,
            _mtype=NON,
            _mid=mid if mid is not None else self.next_mid(),
            _token=request.token,
        )
        response.remote = device.remote
        response.direction = Direction.INCOMING
        if block2 is not None:
            response.opt.block2 = block2
        return self.token_manager.process_response(response)


class SimulatedDevice:
    def __init__(self, network, name):
        self.network = network
        self.remote = FakeRemote(name)

    def on_multicast_request(self, request):
        raise NotImplementedError

    def on_unicast_request(self, request, messageerror_monitor):
        raise AssertionError("%s got an unexpected unicast request" % self.remote)


class BlockwiseDevice(SimulatedDevice):
    """Answers with a payload that only fits into several Block2 blocks;
    every follow-up request is answered with the next block."""

    def __init__(self, network, name, chunks):
        super().__init__(network, name)
        self.chunks = chunks

    def on_multicast_request(self, request):
        self._send_block(request, 0)

    def on_unicast_request(self, request, messageerror_monitor):
        self._send_block(request, request.opt.block2.block_number)

    def _send_block(self, request, number):
        more = number + 1 < len(self.chunks)
        self.network.inject_response(
            self, request, self.chunks[number], block2=(number, more, 0)
        )


class DuplicateResponseDevice(SimulatedDevice):
    """Sends the very same response datagram twice (eg. because an ACK got
    lost, or the network duplicated the NON message)."""

    def __init__(self, network, name, payload):
        super().__init__(network, name)
        self.payload = payload

    def on_multicast_request(self, request):
        mid = self.network.next_mid()
        for _ in range(2):
            self.network.inject_response(self, request, self.payload, mid=mid)


class LateDevice(SimulatedDevice):
    """Only responds after the discovery window has closed."""

    def __init__(self, network, name, payload, delay):
        super().__init__(network, name)
        self.payload = payload
        self.delay = delay
        self.response_was_accepted = None

    def on_multicast_request(self, request):
        self.network.loop.call_later(self.delay, self._respond, request)

    def _respond(self, request):
        self.response_was_accepted = self.network.inject_response(
            self, request, self.payload
        )


class FailingBlockwiseDevice(SimulatedDevice):
    """Starts a blockwise response, but resets the follow-up exchange (eg.
    because it is overloaded); its failure must not affect other devices."""

    def __init__(self, network, name, first_chunk):
        super().__init__(network, name)
        self.first_chunk = first_chunk

    def on_multicast_request(self, request):
        self.network.inject_response(
            self, request, self.first_chunk, block2=(0, True, 0)
        )

    def on_unicast_request(self, request, messageerror_monitor):
        messageerror_monitor()


def block_chunks(payload, block_size=16):
    """Split a payload into chunks as a BlockwiseDevice would send them."""
    return [payload[i : i + block_size] for i in range(0, len(payload), block_size)]


class WithSimulatedNetwork(WithLogMonitoring):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.context = Context()
        self.token_manager = TokenManager(self.context)
        self.network = FakeMulticastNetwork(self.context.loop)
        self.token_manager.token_interface = self.network
        self.network.token_manager = self.token_manager
        self.context.request_interfaces.append(self.token_manager)

    async def asyncTearDown(self):
        await self.context.shutdown()
        await super().asyncTearDown()

    @staticmethod
    def discovery_request():
        return Message(code=GET, uri="coap://[ff02::fd]/.well-known/core")


class TestMulticastDiscovery(WithSimulatedNetwork):
    @no_warnings
    async def test_discovery(self):
        """The three-device example: one answers in blocks, one answers
        twice, one answers too late. The application sees one assembled
        response per in-window device, each attributed to its sender."""
        blockwise_payload = b"</sensors/temp>;ct=40,</sensors/hum>;ct=40"
        blockwise = BlockwiseDevice(
            self.network, "blockwise-device", block_chunks(blockwise_payload)
        )
        duplicate = DuplicateResponseDevice(
            self.network, "duplicate-device", b"</status>"
        )
        late = LateDevice(self.network, "late-device", b"</late>", delay=0.4)
        self.network.devices += [blockwise, duplicate, late]

        responses = {}
        async for response in self.context.multicast_request(
            self.discovery_request(), timeout=0.2
        ):
            # No device may be reported twice ...
            self.assertNotIn(response.remote, responses)
            responses[response.remote] = response.payload

        # ... the blockwise device's blocks were assembled into its payload,
        # the duplicate device shows up exactly once, and the late device not
        # at all:
        self.assertEqual(
            responses,
            {
                blockwise.remote: blockwise_payload,
                duplicate.remote: b"</status>",
            },
        )

        await asyncio.sleep(0.3)  # let the late device's response come in
        self.assertFalse(
            late.response_was_accepted,
            "Response that arrived after the window was still processed",
        )

        # The discovery left no state behind
        self.assertEqual(self.token_manager.outgoing_requests, {})

    @no_warnings
    async def test_blockwise_chains_are_per_device(self):
        """Two devices answer blockwise at the same time; their blocks must
        not be assembled into each other's responses."""
        payload1 = b"1:first device with a long payload"
        payload2 = b"2:second device, also long"
        device1 = BlockwiseDevice(self.network, "device-1", block_chunks(payload1))
        device2 = BlockwiseDevice(self.network, "device-2", block_chunks(payload2))
        self.network.devices += [device1, device2]

        responses = {}
        async for response in self.context.multicast_request(
            self.discovery_request(), timeout=0.2
        ):
            responses[response.remote] = response.payload

        self.assertEqual(
            responses,
            {device1.remote: payload1, device2.remote: payload2},
        )

    @precise_warnings(
        [
            # (the RST-like failure of the follow-up request surfaces through
            # the generic Request error handling first)
            "An exception that is not an aiocoap Error was raised from a transport; please report this as a bug in aiocoap: ...",
            "Dropping response from <FakeRemote failing-device>: blockwise completion failed: ...",
        ]
    )
    async def test_failing_device(self):
        """A device whose blockwise follow-up fails is dropped; the other
        devices' responses are still reported, and the token stays
        registered until the window ends."""
        failing = FailingBlockwiseDevice(self.network, "failing-device", b"x" * 16)
        ok = DuplicateResponseDevice(self.network, "ok-device", b"</ok>")
        self.network.devices += [failing, ok]

        responses = {}
        async for response in self.context.multicast_request(
            self.discovery_request(), timeout=0.2
        ):
            responses[response.remote] = response.payload

        self.assertEqual(responses, {ok.remote: b"</ok>"})
        self.assertEqual(self.token_manager.outgoing_requests, {})

    @no_warnings
    async def test_early_break_releases_state(self):
        """Leaving the iteration before the window ends releases the
        discovery state (in particular the token registration)."""
        device = DuplicateResponseDevice(self.network, "some-device", b"</a>")
        blockwise = BlockwiseDevice(
            self.network, "blockwise-device", block_chunks(b"some longer payload here")
        )
        self.network.devices += [device, blockwise]

        request = self.context.multicast_request(self.discovery_request(), timeout=10)
        async for response in request:
            break

        # The async generator is finalized by the loop's asyncgen finalizer
        await asyncio.sleep(0.1)
        self.assertEqual(self.token_manager.outgoing_requests, {})


if __name__ == "__main__":
    import unittest

    unittest.main()
