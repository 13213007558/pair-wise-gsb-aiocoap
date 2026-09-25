# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This tests advanced cases of blockwise transfer; simple sequential transfers
are covered in test_server.TestServer.test_replacing_resource."""

import asyncio

import aiocoap
import aiocoap.defaults

from .test_server import (
    WithTestServer,
    WithClient,
    no_warnings,
    slow_empty_ack,
    BigResource,
    BasicTestingSite,
)


class BigChunkyResource(BigResource):
    async def render_get(self, request):
        request.remote.maximum_block_size_exp = 3
        return await super().render_get(request)


class SpoolResource(aiocoap.resource.Resource):
    """POST target that records the bodies (and Request-Tags) of all requests
    that arrive completely assembled."""

    def __init__(self):
        super().__init__()
        self.arrived = []

    async def render_post(self, request):
        self.arrived.append((request.payload, request.opt.request_tag))
        return aiocoap.Message(code=aiocoap.CHANGED)


class ChunkyTestingSite(BasicTestingSite):
    def __init__(self):
        super().__init__()

        self.add_resource(["big", "chunky"], BigChunkyResource())
        self.spool = SpoolResource()
        self.add_resource(["spool"], self.spool)


class WithChunkyTestServer(WithTestServer):
    TestingSite = ChunkyTestingSite


class TestBlockwise(WithChunkyTestServer, WithClient):
    def create_testing_site(self):
        self.testingsite = super().create_testing_site()
        return self.testingsite

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
    async def test_interleaved(self):
        """Two equally long but different bodies are uploaded to the same
        resource in interleaved Block1 transfers, with a retransmitted first
        block and a block size reduction thrown in.

        The Request-Tag mechanism (RFC9175) has to ensure that the resource
        receives exactly the two original bodies and nothing mixed up, and
        that a later operation that does not use Request-Tags still works."""

        body1 = bytes(range(256)) * 8
        body2 = bytes(reversed(range(256))) * 8

        tag1 = b"op-one"
        tag2 = b"op-two"

        async def send_block(tag, number, more, size_exp, payload):
            request = aiocoap.Message(
                uri="coap://" + self.servernetloc + "/spool",
                code=aiocoap.POST,
                payload=payload,
            )
            request.opt.block1 = (number, more, size_exp)
            if tag is not None:
                request.opt.request_tag = (tag,)
            response = await self.client.request(
                request, handle_blockwise=False
            ).response
            if more:
                self.assertEqual(
                    response.code,
                    aiocoap.CONTINUE,
                    "Intermediate block not acknowledged with 2.31",
                )
            else:
                self.assertEqual(
                    response.code,
                    aiocoap.CHANGED,
                    "Final block not acknowledged with 2.04",
                )
            self.assertEqual(response.opt.block1.block_number, number)

        # first blocks of both operations, ...
        await send_block(tag1, 0, True, 6, body1[:1024])
        await send_block(tag2, 0, True, 6, body2[:1024])
        # ... a retransmission of the first block of the first operation, ...
        await send_block(tag1, 0, True, 6, body1[:1024])
        # ... completion of the second operation, ...
        await send_block(tag2, 1, False, 6, body2[1024:])
        # ... and completion of the first operation at a re-negotiated
        # (reduced) block size.
        await send_block(tag1, 4, True, 4, body1[1024:1280])
        await send_block(tag1, 5, True, 4, body1[1280:1536])
        await send_block(tag1, 6, True, 4, body1[1536:1792])
        await send_block(tag1, 7, False, 4, body1[1792:])

        # A sequential operation that does not use Request-Tags still works.
        await send_block(None, 0, True, 6, body1[:1024])
        await send_block(None, 1, False, 6, body1[1024:])

        arrived = self.testingsite.spool.arrived
        self.assertEqual(
            [payload for payload, _tags in arrived],
            [body2, body1, body1],
            "Resource did not receive exactly the sent bodies",
        )

    @no_warnings
    async def test_request_tag_forwarding(self):
        """A request that already carries a Request-Tag (eg. because a proxy
        added its own when forwarding) keeps that tag through the managed
        blockwise transfer, and the client adds its own tag to the set."""

        payload = b"0123456789----------" * 512
        request = aiocoap.Message(
            uri="coap://" + self.servernetloc + "/spool",
            code=aiocoap.POST,
            payload=payload,
        )
        request.opt.request_tag = (b"proxy-tag",)

        response = await self.client.request(request).response
        self.assertEqual(response.code, aiocoap.CHANGED)

        ((arrived_payload, arrived_tags),) = self.testingsite.spool.arrived
        self.assertEqual(arrived_payload, payload)
        self.assertIn(b"proxy-tag", arrived_tags)
        self.assertEqual(
            len(arrived_tags), 2, "Client did not add its own Request-Tag"
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
