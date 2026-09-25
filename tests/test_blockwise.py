# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This tests advanced cases of blockwise transfer; simple sequential transfers
are covered in test_server.TestServer.test_replacing_resource."""

import asyncio
import logging
import unittest
import aiocoap
import aiocoap.defaults
from aiocoap.blockwise import Block1Spool, ContinueException, IncompleteException
from aiocoap.protocol import BlockwiseRequest
from aiocoap.proxy.server import Proxy

from .test_server import (
    WithTestServer,
    WithClient,
    no_warnings,
    slow_empty_ack,
    BigResource,
    BasicTestingSite,
)
from .test_proxy import WithProxyServer
from . import common


class BigChunkyResource(BigResource):
    async def render_get(self, request):
        request.remote.maximum_block_size_exp = 3
        return await super().render_get(request)


class ChunkyTestingSite(BasicTestingSite):
    def __init__(self):
        super().__init__()

        self.add_resource(["big", "chunky"], BigChunkyResource())


class RecordingReplacingResource(aiocoap.resource.Resource):
    def __init__(self):
        super().__init__()
        self.received_payloads = []

    async def render_post(self, request):
        self.received_payloads.append(request.payload)
        return aiocoap.Message(
            code=aiocoap.CONTENT,
            payload=request.payload,
        )


class RequestTagTestingSite(BasicTestingSite):
    def __init__(self):
        super().__init__()
        self.recording_resource = RecordingReplacingResource()
        self.add_resource(["record"], self.recording_resource)


class WithChunkyTestServer(WithTestServer):
    TestingSite = ChunkyTestingSite


class WithRequestTagTestServer(WithTestServer):
    TestingSite = RequestTagTestingSite


class TestBlockwise(WithChunkyTestServer, WithClient):
    # tracked as https://github.com/chrysn/aiocoap/issues/58; behavior can be successful more or less by chance
    @unittest.skip
    @no_warnings
    async def test_sequential(self):
        """Test whether the client serializes simultaneous block requests"""

        pattern1 = b"01234 first pattern" + b"01" * 1024
        pattern2 = b"01234 second pattern" + b"02" * 1024

        request1 = aiocoap.Message(
            uri="coap://" + self.servernetloc + "/replacing/one",
            code=aiocoap.POST,
            payload=pattern1,
        )
        request2 = aiocoap.Message(
            uri="coap://" + self.servernetloc + "/replacing/one",
            code=aiocoap.POST,
            payload=pattern2,
        )

        responses = []
        for response in asyncio.as_completed(
            [self.client.request(r).response for r in [request1, request2]]
        ):
            response = await response
            self.assertTrue(
                response.code.is_successful(),
                "Simultaneous blockwise requests caused error.",
            )
            responses.append(response.payload)

        self.assertSetEqual(
            set(responses), set(x.replace(b"0", b"O") for x in (pattern1, pattern2))
        )

    @no_warnings
    # because we're counting responses, and on slow loaded systems a response
    # might all of a sudden take 0.2s -- it's unlikely, but we're counting 80
    # of them.
    @slow_empty_ack()
    async def test_client_hints(self):
        """Test whether a handle_blockwise=True request takes a block2 option
        set in it as a hint to start requesting with a low size right away

        That way of hinting at size requests is not documented, but understood
        and occasionally used; the test primarily serves to identify problems
        the server has with initially low block sizes."""

        resp = await self.client.request(
            aiocoap.Message(
                uri="coap://" + self.servernetloc + "/big",
                block2=(0, 0, 3),
                code=aiocoap.GET,
            )
        ).response

        self.assertEqual(resp.code, aiocoap.CONTENT, "Request was unsuccessful")
        self.assertEqual(
            self._count_received_messages(),
            (len(resp.payload) + 127) // 128,
            "Response not chunked into 128 bytes",
        )

    @no_warnings
    async def test_server_hints(self):
        """Test whether the needs_blockwise server mechanism considers size
        exponent limits of the remote.

        Mutating the remote as it is done in the BigChunkyResource is not
        documented, but helps verify that the information in
        maximum_block_size_exp is generally used."""

        resp = await self.client.request(
            aiocoap.Message(
                uri="coap://" + self.servernetloc + "/big/chunky",
                code=aiocoap.GET,
            )
        ).response

        self.assertEqual(resp.code, aiocoap.CONTENT, "Request was unsuccessful")
        self.assertEqual(
            self._count_received_messages(),
            (len(resp.payload) + 127) // 128,
            "Response not chunked into 128 bytes",
        )

    @no_warnings
    async def test_client_hints_block1(self):
        """Test whether a client can successfully indicate per-remote sizes
        even for the block1 phase."""

        # same as BigResource's content
        payload = b"0123456789----------" * 512
        reqmsg = aiocoap.Message(
            uri="coap://" + self.servernetloc + "/replacing/one",
            code=aiocoap.PUT,
            payload=payload,
        )
        reqmsg.remote.maximum_block_size_exp = 3
        resp = await self.client.request(reqmsg).response

        self.assertEqual(resp.code, aiocoap.CHANGED, "Request was unsuccessful")
        self.assertEqual(
            self._count_received_messages(),
            (len(payload) + 127) // 128,
            "Response not chunked into 128 bytes",
        )

    _received_logmsg = "Incoming message <aiocoap.Message"

    def _count_received_messages(self):
        # only client-side received empty-acks are counted
        return sum(
            self._received_logmsg in x.msg
            for x in self.handler
            if x.name != "coap-server"
        )


class TestRequestTagBlockwise(WithRequestTagTestServer, WithClient):
    async def test_concurrent_block1_operations(self):
        payload_a = b"A" * 2048
        payload_b = b"B" * 2048
        seen_blocks = []
        original_feed_and_take = aiocoap.blockwise.Block1Spool.feed_and_take
        original_default_size = (
            aiocoap.numbers.constants.TransportTuning.DEFAULT_BLOCK_SIZE_EXP
        )

        def feed_and_take(self, request):
            if request.opt.block1 is not None:
                seen_blocks.append(
                    (
                        request.opt.block1.block_number,
                        request.opt.block1.size_exponent,
                        request.opt.request_tag,
                        request.payload[:1],
                    )
                )
            return original_feed_and_take(self, request)

        aiocoap.blockwise.Block1Spool.feed_and_take = feed_and_take
        aiocoap.numbers.constants.TransportTuning.DEFAULT_BLOCK_SIZE_EXP = 3
        try:

            def make_request(payload):
                request = aiocoap.Message(
                    uri="coap://" + self.servernetloc + "/record",
                    code=aiocoap.POST,
                    payload=payload,
                )
                request.remote.maximum_block_size_exp = 6
                return request

            responses = await asyncio.gather(
                self.client.request(make_request(payload_a)).response,
                self.client.request(make_request(payload_b)).response,
            )
        finally:
            aiocoap.blockwise.Block1Spool.feed_and_take = original_feed_and_take
            aiocoap.numbers.constants.TransportTuning.DEFAULT_BLOCK_SIZE_EXP = (
                original_default_size
            )

        self.assertEqual(
            [response.code for response in responses],
            [aiocoap.CONTENT, aiocoap.CONTENT],
        )
        self.assertEqual(
            {response.payload for response in responses},
            {payload_a, payload_b},
        )
        self.assertEqual(
            set(self.server.serversite.recording_resource.received_payloads),
            {payload_a, payload_b},
        )

        tags = {block[2] for block in seen_blocks}
        self.assertEqual(len(tags), 2)
        self.assertTrue(all(len(tag) == 1 for tag in tags))
        self.assertEqual(
            sum(
                block[0] == 0 and block[1] == 6
                for block in seen_blocks
            ),
            2,
        )
        self.assertEqual(
            sum(
                block[0] == 0 and block[1] == 3
                for block in seen_blocks
            ),
            2,
        )
        for tag in tags:
            self.assertTrue(
                all(block[2] == tag for block in seen_blocks if block[2] == tag)
            )


class TestRequestTagAssembly(unittest.IsolatedAsyncioTestCase):
    class Remote:
        blockwise_key = "test-remote"

    def _block(self, block_number, more, payload, request_tag=()):
        request = aiocoap.Message(
            code=aiocoap.PUT,
            payload=payload,
            uri_path=("record",),
            block1=(block_number, more, 3),
            request_tag=request_tag,
        )
        request.remote = self.Remote()
        return request

    async def test_concurrent_spool_isolation(self):
        spool = Block1Spool()

        for request_tag, payload in ((b"one", b"A"), (b"two", b"B")):
            with self.assertRaises(ContinueException):
                spool.feed_and_take(
                    self._block(0, True, payload * 128, (request_tag,))
                )

        assembled_one = spool.feed_and_take(
            self._block(1, False, b"C", (b"one",))
        )
        assembled_two = spool.feed_and_take(
            self._block(1, False, b"D", (b"two",))
        )

        self.assertEqual(assembled_one.payload, b"A" * 128 + b"C")
        self.assertEqual(assembled_two.payload, b"B" * 128 + b"D")

    async def test_legacy_spool_without_request_tag(self):
        spool = Block1Spool()

        with self.assertRaises(ContinueException):
            spool.feed_and_take(self._block(0, True, b"A" * 128))
        assembled = spool.feed_and_take(self._block(1, False, b"B"))

        self.assertEqual(assembled.payload, b"A" * 128 + b"B")

    async def test_client_keeps_tag_through_size_negotiation(self):
        class Remote:
            blockwise_key = "test-remote"
            maximum_block_size_exp = 6
            maximum_payload_size = 1124

        class FakeBlockRequest:
            def __init__(self, loop, response):
                self.response = loop.create_future()
                self.response.set_result(response)

        class FakeProtocol:
            def __init__(self, loop):
                self.loop = loop
                self.sent = []

            async def find_remote_and_interface(self, request):
                return None

            def request(self, request, handle_blockwise=True):
                self.sent.append(request)
                block1 = request.opt.block1
                if len(self.sent) == 1:
                    response = aiocoap.Message(
                        code=aiocoap.CONTINUE,
                        block1=(0, True, 3),
                    )
                else:
                    response = aiocoap.Message(
                        code=aiocoap.CONTINUE
                        if block1.more
                        else aiocoap.CHANGED,
                        block1=(
                            block1.block_number,
                            block1.more,
                            block1.size_exponent,
                        ),
                    )
                response.remote = request.remote
                return FakeBlockRequest(self.loop, response)

        loop = asyncio.get_running_loop()
        protocol = FakeProtocol(loop)
        payload = bytes(range(256)) + b"Z" * 44
        request = aiocoap.Message(code=aiocoap.PUT, payload=payload)
        request.remote = Remote()
        request.remote.maximum_block_size_exp = 4
        response = loop.create_future()

        await BlockwiseRequest._run(
            request,
            response,
            lambda: None,
            protocol,
            logging.getLogger("test"),
        )

        sent_blocks = [
            (
                message.opt.block1.block_number,
                message.opt.block1.size_exponent,
                message.opt.request_tag,
                message.payload,
            )
            for message in protocol.sent
        ]

        self.assertEqual(
            [(block_number, size_exp) for block_number, size_exp, _, _ in sent_blocks],
            [(0, 4), (0, 3), (1, 3), (2, 3)],
        )
        self.assertEqual(
            {request_tag for _, _, request_tag, _ in sent_blocks},
            {sent_blocks[0][2]},
        )
        self.assertEqual(b"".join(block[3] for block in sent_blocks[1:]), payload)
        self.assertEqual(response.result().code, aiocoap.CHANGED)

    async def test_proxy_stable_tag_for_untagged_blocks(self):
        proxy = Proxy(None)

        first = self._block(0, True, b"A" * 128)
        retransmitted = self._block(0, True, b"A" * 128)
        second = self._block(1, False, b"B")

        proxy._add_block1_request_tag(first)
        proxy._add_block1_request_tag(retransmitted)
        proxy._add_block1_request_tag(second)

        self.assertEqual(len(first.opt.request_tag), 1)
        self.assertEqual(
            retransmitted.opt.request_tag,
            first.opt.request_tag,
        )
        self.assertEqual(
            second.opt.request_tag,
            first.opt.request_tag,
        )

    async def test_proxy_preserves_client_tag(self):
        proxy = Proxy(None)
        request = self._block(0, True, b"A" * 128, (b"client-tag",))

        proxy._add_block1_request_tag(request)

        self.assertEqual(request.opt.request_tag[0], b"client-tag")
        self.assertEqual(len(request.opt.request_tag), 2)

    async def test_proxy_rejects_unknown_continuation(self):
        proxy = Proxy(None)

        with self.assertRaises(IncompleteException):
            proxy._add_block1_request_tag(self._block(1, False, b"B"))


class TestRequestTagProxyBlockwise(
    WithProxyServer,
    WithClient,
    WithRequestTagTestServer,
):
    @unittest.skipIf(
        common.using_simple6,
        "Some proxy tests fail with simple6 (https://github.com/chrysn/aiocoap/issues/88)",
    )
    async def test_proxy_appends_request_tag(self):
        payload = b"C" * 256
        request = aiocoap.Message(
            code=aiocoap.POST,
            payload=payload,
        )
        request.unresolved_remote = self.proxyaddress
        request.opt.proxy_scheme = "coap"
        request.opt.uri_host = self.serveraddress
        request.opt.uri_path = ("record",)
        response = await self.client.request(request).response

        self.assertEqual(response.code, aiocoap.CONTENT)
        self.assertEqual(response.payload, payload)
        self.assertEqual(
            self.server.serversite.recording_resource.received_payloads,
            [payload],
        )

    @unittest.skipIf(
        common.using_simple6,
        "Some proxy tests fail with simple6 (https://github.com/chrysn/aiocoap/issues/88)",
    )
    async def test_legacy_sequential_requests_without_tag(self):
        payload = b"D" * 256

        for block_number in range(2):
            start = block_number * 128
            end = start + 128
            request = aiocoap.Message(
                code=aiocoap.POST,
                payload=payload[start:end],
            )
            request.unresolved_remote = self.proxyaddress
            request.opt.proxy_scheme = "coap"
            request.opt.uri_host = self.serveraddress
            request.opt.uri_path = ("record",)
            request.opt.block1 = (block_number, block_number == 0, 3)
            response = await self.client.request(
                request, handle_blockwise=False
            ).response

        self.assertEqual(response.code, aiocoap.CONTENT)
        self.assertEqual(
            self.server.serversite.recording_resource.received_payloads,
            [payload],
        )
