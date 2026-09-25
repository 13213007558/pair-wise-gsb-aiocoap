# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio

from aiocoap import Context, Message
from aiocoap.numbers import GET, CONTENT
from aiocoap.numbers.constants import TransportTuning
from aiocoap.optiontypes import BlockOption
from aiocoap.tokenmanager import TokenManager
from aiocoap.transports.udp6 import UDP6EndpointAddress

from .fixtures import no_warnings, WithLogMonitoring


class _FastTuning(TransportTuning):
    """TransportTuning with the discovery related times scaled down so
    that tests run fast (the discovery window is 0.2s here)."""

    DEFAULT_LEISURE = 0.1
    MAX_LATENCY = 0.1


class MockMulticastNetwork:
    """A TokenInterface that emulates a multicast group of devices without
    actual networking.

    Requests to the multicast remote are fanned out to all registered
    devices; requests to a device's unicast remote (eg. blockwise follow-up
    requests) are delivered to that device only.
    """

    def __init__(self, token_manager):
        self.token_manager = token_manager
        self.multicast_remote = UDP6EndpointAddress(("ff02::fd", 5683, 0, 0), self)
        self.devices = {}
        """remote -> handler(request_message) of the emulated devices"""

    async def recognize_remote(self, message):
        remote = message.remote
        if not isinstance(remote, UDP6EndpointAddress):
            return False
        return remote == self.multicast_remote or remote in self.devices

    async def determine_remote(self, message):
        if message.remote.hostinfo == "[ff02::fd]:5683":
            return self.multicast_remote
        return None

    def send_message(self, message, messageerror_monitor):
        if message.remote == self.multicast_remote:
            for handler in list(self.devices.values()):
                handler(message)
        else:
            self.devices[message.remote](message)
        # All messages are NON here, so there is no send canceller
        return None

    def respond(self, request, response):
        response.token = request.token
        self.token_manager.process_response(response)

    async def shutdown(self):
        pass

    def add_device(self, host, handler):
        remote = UDP6EndpointAddress((host, 5683, 0, 0), self)
        self.devices[remote] = handler
        return remote


class SimpleDevice:
    """Emulates a device that responds to the multicast request with a
    single response.

    With copies > 1, the response is delivered that many times (as happens
    when datagrams are duplicated or retransmitted on the way).
    """

    def __init__(self, network, host, payload, *, copies=1, delay=0.01):
        self.network = network
        self.payload = payload
        self.copies = copies
        self.delay = delay
        self.remote = network.add_device(host, self.handle)

    def handle(self, request):
        for i in range(self.copies):
            response = Message(code=CONTENT, payload=self.payload)
            response.remote = self.remote
            asyncio.get_running_loop().call_later(
                self.delay * (i + 1), self.network.respond, request, response
            )


class BlockwiseDevice:
    """Emulates a device whose response does not fit into a single
    datagram: It answers the multicast request with the first Block2 block,
    and serves the follow-up unicast requests for the remaining blocks.

    With serve_followups=False, it goes silent after the first block (eg.
    because it crashed), leaving its blockwise transfer incomplete.
    """

    size_exp = 1  # 32 byte blocks

    def __init__(self, network, host, payload, *, serve_followups=True, delay=0.01):
        self.network = network
        self.payload = payload
        self.serve_followups = serve_followups
        self.delay = delay
        self.remote = network.add_device(host, self.handle)

    def handle(self, request):
        blocksize = 2 ** (self.size_exp + 4)
        if request.opt.block2 is None:
            block_number = 0
        else:
            if not self.serve_followups:
                return
            block_number = request.opt.block2.block_number
        start = block_number * blocksize
        chunk = self.payload[start : start + blocksize]
        more = start + blocksize < len(self.payload)
        response = Message(code=CONTENT, payload=chunk)
        response.opt.block2 = BlockOption.BlockwiseTuple(
            block_number, more, self.size_exp
        )
        response.remote = self.remote
        asyncio.get_running_loop().call_later(
            self.delay, self.network.respond, request, response
        )


class TestMulticastRequest(WithLogMonitoring):
    def _mkcontext(self):
        context = Context()
        token_manager = TokenManager(context)
        network = MockMulticastNetwork(token_manager)
        token_manager.token_interface = network
        context.request_interfaces.append(token_manager)
        return context, token_manager, network

    def _mkrequest(self):
        return Message(
            code=GET,
            uri="coap://[ff02::fd]:5683/.well-known/core",
            transport_tuning=_FastTuning(),
        )

    @no_warnings
    async def test_multicast_request(self):
        """Three devices answer a multicast discovery request: One with a
        blockwise response, one whose response is duplicated on the way, and
        one that responds only after the discovery window has closed. The
        application is handed the first two (the blockwise one assembled
        from its blocks, the duplicated one only once), each with the
        remote of the device it came from."""
        context, token_manager, network = self._mkcontext()

        blockwise_payload = bytes(range(50))  # takes two 32 byte blocks
        blockwise = BlockwiseDevice(network, "2001:db8::1", blockwise_payload)
        duplicate = SimpleDevice(network, "2001:db8::2", b"duplicate", copies=2)
        # responds at 0.3s, after the 0.2s discovery window
        late = SimpleDevice(network, "2001:db8::3", b"too late", delay=0.3)

        request = self._mkrequest()

        responses = {}
        async for response in context.multicast_request(request):
            self.assertIs(response.request, request)
            responses[response.remote] = response.payload

        self.assertEqual(
            responses,
            {
                blockwise.remote: blockwise_payload,
                duplicate.remote: b"duplicate",
            },
        )

        # The discovery state was released when the window closed ...
        self.assertEqual(token_manager.outgoing_requests, {})

        # ... and the late response is not matched to the request any more.
        await asyncio.sleep(0.2)
        self.assertEqual(token_manager.outgoing_requests, {})
        self.assertNotIn(late.remote, responses)

        await context.shutdown()

    @no_warnings
    async def test_failing_device_does_not_affect_others(self):
        """A device that starts a blockwise response and then goes silent
        does not keep the discovery window open, and does not affect the
        responses of the other devices."""
        context, token_manager, network = self._mkcontext()

        ok = SimpleDevice(network, "2001:db8::1", b"fine")
        # starts a blockwise response, but never serves the follow-up blocks
        BlockwiseDevice(network, "2001:db8::2", bytes(range(50)), serve_followups=False)

        request = self._mkrequest()

        responses = {}
        async for response in context.multicast_request(request):
            responses[response.remote] = response.payload

        self.assertEqual(responses, {ok.remote: b"fine"})
        self.assertEqual(token_manager.outgoing_requests, {})

        await context.shutdown()

    @no_warnings
    async def test_early_termination(self):
        """When the application ends the iteration before the discovery
        window is over, the discovery state is released right away, and
        later responses are not matched to the request any more."""
        context, token_manager, network = self._mkcontext()

        first = SimpleDevice(network, "2001:db8::1", b"first", delay=0.01)
        SimpleDevice(network, "2001:db8::2", b"second", delay=0.05)

        request = self._mkrequest()

        iterator = context.multicast_request(request).__aiter__()
        response = await asyncio.wait_for(iterator.__anext__(), timeout=1)
        self.assertEqual(response.payload, b"first")
        self.assertEqual(response.remote, first.remote)

        await iterator.aclose()
        self.assertEqual(token_manager.outgoing_requests, {})

        # the second device's response arrives only now, and is ignored
        await asyncio.sleep(0.1)
        self.assertEqual(token_manager.outgoing_requests, {})

        await context.shutdown()
