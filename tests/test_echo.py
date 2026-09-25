# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests for RFC9175 Echo support (aiocoap.echo and the client side challenge
handling in aiocoap.protocol.BlockwiseRequest)"""

import asyncio
import logging
import types
import unittest

import aiocoap
import aiocoap.resource
from aiocoap.echo import AddressBoundEchoPolicy, EchoResourceWrapper
from aiocoap.protocol import BlockwiseRequest

from .fixtures import no_warnings, precise_warnings
from .test_server import WithTestServer, WithClient


class FakeClock:
    """Controllable clock used in place of time.monotonic"""

    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeRemote:
    """Stand-in for a transport's EndpointAddress"""

    def __init__(self, hostinfo):
        self.hostinfo = hostinfo


def build_request(echo=None, remote_hostinfo="[::1]:5683"):
    request = aiocoap.Message(code=aiocoap.GET)
    request.direction = aiocoap.message.Direction.INCOMING
    if remote_hostinfo is not None:
        request.remote = FakeRemote(remote_hostinfo)
    if echo is not None:
        request.opt.echo = echo
    return request


class TestAddressBoundEchoPolicy(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.policy = AddressBoundEchoPolicy(
            secret=b"test-secret", lifetime=30.0, clock=self.clock
        )

    def test_roundtrip(self):
        request = build_request()
        echo = self.policy.issue(request)
        request.opt.echo = echo
        self.assertTrue(self.policy.validate(request))

    def test_missing_echo(self):
        self.assertFalse(self.policy.validate(build_request()))

    def test_expiry(self):
        request = build_request()
        echo = self.policy.issue(request)
        request.opt.echo = echo

        # The same Echo value is accepted right up to its lifetime ...
        self.clock.advance(29.0)
        self.assertTrue(self.policy.validate(request))

        # ... and rejected once it has expired.
        self.clock.advance(2.0)
        self.assertFalse(self.policy.validate(request))

    def test_replay_from_other_source(self):
        echo = self.policy.issue(build_request(remote_hostinfo="[::1]:5683"))
        replayed = build_request(echo=echo, remote_hostinfo="[2001:db8::1]:5683")
        self.assertFalse(self.policy.validate(replayed))

        replayed = build_request(echo=echo, remote_hostinfo="[::1]:9999")
        self.assertFalse(self.policy.validate(replayed))

    def test_malformed(self):
        valid = self.policy.issue(build_request())

        for garbage in (
            b"",
            b"short",
            valid[:-1],
            valid + b"\x00",
            b"\x02" + valid[1:],  # unknown version
            bytes([valid[0]]) + bytes(b ^ 0xFF for b in valid[1:]),
        ):
            request = build_request(echo=garbage)
            self.assertFalse(
                self.policy.validate(request),
                "Malformed Echo value %r was accepted" % (garbage,),
            )

    def test_unaddressable_request(self):
        request = build_request(remote_hostinfo=None)
        with self.assertRaises(ValueError):
            self.policy.issue(request)
        self.assertFalse(self.policy.validate(request))


class CountingResource(aiocoap.resource.Resource):
    """Resource whose side effects (here: counting and payload recording)
    must not happen before the Echo challenge was answered"""

    def __init__(self):
        super().__init__()
        self.calls = 0
        self.payloads = []

    async def render_get(self, request):
        self.calls += 1
        return aiocoap.Message(code=aiocoap.CONTENT, payload=b"protected data")

    async def render_put(self, request):
        self.calls += 1
        self.payloads.append(request.payload)
        return aiocoap.Message(code=aiocoap.CHANGED)


class TestEchoResourceWrapper(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.policy = AddressBoundEchoPolicy(lifetime=30.0, clock=self.clock)
        self.inner = CountingResource()
        self.wrapped = EchoResourceWrapper(self.inner, self.policy)

    async def test_challenge_then_access(self):
        # Without an Echo option, the request is challenged and the handler
        # is not invoked
        response = await self.wrapped.render(build_request())
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertEqual(self.inner.calls, 0)

        # Answering the challenge lets the request through
        request = build_request(echo=response.opt.echo)
        response = await self.wrapped.render(request)
        self.assertEqual(response.code, aiocoap.CONTENT)
        self.assertEqual(self.inner.calls, 1)

    async def test_expired_echo_rechallenged(self):
        echo = self.policy.issue(build_request())
        self.clock.advance(31.0)

        response = await self.wrapped.render(build_request(echo=echo))
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertNotEqual(response.opt.echo, echo)
        self.assertEqual(self.inner.calls, 0)

    async def test_replayed_echo_rechallenged(self):
        echo = self.policy.issue(build_request(remote_hostinfo="[::1]:5683"))

        response = await self.wrapped.render(
            build_request(echo=echo, remote_hostinfo="[2001:db8::1]:5683")
        )
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertEqual(self.inner.calls, 0)

    async def test_malformed_echo_rechallenged(self):
        response = await self.wrapped.render(build_request(echo=b"garbage"))
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertEqual(self.inner.calls, 0)


# Client side challenge handling, tested against a scripted fake protocol


class FakeClientRemote:
    maximum_block_size_exp = 6
    maximum_payload_size = 1024


class FakeProtocol:
    """Answers requests from a script of responses, recording what was sent"""

    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []

    async def find_remote_and_interface(self, message):
        pass

    def request(self, message, handle_blockwise=True):
        assert not handle_blockwise
        self.sent.append(message)
        response = self.responses.pop(0)
        response.remote = message.remote
        future = asyncio.get_running_loop().create_future()
        future.set_result(response)
        return types.SimpleNamespace(response=future)


def build_challenge(echo):
    challenge = aiocoap.Message(code=aiocoap.UNAUTHORIZED)
    challenge.opt.echo = echo
    return challenge


class TestClientEchoRetry(unittest.IsolatedAsyncioTestCase):
    async def run_request(self, protocol, app_request):
        app_request.remote = FakeClientRemote()
        response = asyncio.get_running_loop().create_future()
        await BlockwiseRequest._run(
            app_request,
            response,
            lambda: None,
            protocol,
            logging.getLogger("coap.test.echo"),
        )
        return response.result()

    async def test_challenge_is_answered(self):
        protocol = FakeProtocol(
            [
                build_challenge(b"echo-value"),
                aiocoap.Message(code=aiocoap.CONTENT, payload=b"data"),
            ]
        )
        app_request = aiocoap.Message(code=aiocoap.PUT, payload=b"payload")

        response = await self.run_request(protocol, app_request)

        self.assertEqual(response.code, aiocoap.CONTENT)
        self.assertEqual(response.payload, b"data")

        # The request was sent once without and once with the Echo option;
        # method, payload and semantics of the original request are retained.
        self.assertEqual(len(protocol.sent), 2)
        self.assertIsNone(protocol.sent[0].opt.echo)
        self.assertEqual(protocol.sent[1].opt.echo, b"echo-value")
        self.assertEqual(protocol.sent[1].code, aiocoap.PUT)
        self.assertEqual(protocol.sent[1].payload, b"payload")
        # The caller's message object was not modified
        self.assertIsNone(app_request.opt.echo)

    async def test_retries_are_bounded(self):
        protocol = FakeProtocol(
            [
                build_challenge(b"challenge-%d" % i)
                for i in range(BlockwiseRequest.max_echo_retries + 1)
            ]
        )
        app_request = aiocoap.Message(code=aiocoap.GET)

        with self.assertLogs("coap.test.echo", level="WARNING"):
            response = await self.run_request(protocol, app_request)

        # A server that keeps challenging can not keep the client resending
        # forever; the last 4.01 response is passed through.
        self.assertEqual(len(protocol.sent), 1 + BlockwiseRequest.max_echo_retries)
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)


# Integration tests over a real (loopback) server


class CountingPolicy(AddressBoundEchoPolicy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.issued = 0

    def issue(self, request):
        self.issued += 1
        return super().issue(request)


class AlwaysChallengeResource(aiocoap.resource.Resource):
    """Resource that never accepts any Echo value, to verify that the client
    does not retry indefinitely"""

    def __init__(self, policy):
        super().__init__()
        self.policy = policy
        self.calls = 0

    async def render_get(self, request):
        self.calls += 1
        response = aiocoap.Message(
            code=aiocoap.UNAUTHORIZED, payload=b"Echo option required"
        )
        response.opt.echo = self.policy.issue(request)
        return response


class EchoTestingSite(aiocoap.resource.Site):
    def __init__(self, clock):
        super().__init__()
        self.policy = CountingPolicy(lifetime=30.0, clock=clock)
        self.protected = CountingResource()
        self.add_resource(
            ["protected"], EchoResourceWrapper(self.protected, self.policy)
        )
        self.always = AlwaysChallengeResource(self.policy)
        self.add_resource(["always"], self.always)


class TestEchoClientServer(WithTestServer, WithClient):
    def create_testing_site(self):
        self.echo_clock = FakeClock()
        self.testingsite = EchoTestingSite(self.echo_clock)
        return self.testingsite

    def build_request(self, code=aiocoap.GET, payload=b""):
        request = aiocoap.Message(code=code, payload=payload)
        request.opt.uri_path = ["protected"]
        request.unresolved_remote = self.servernetloc
        return request

    @no_warnings
    async def test_managed_request_answers_challenge(self):
        # The client transparently answers the challenge; the handler runs
        # exactly once, only after the challenge was answered.
        response = await self.client.request(self.build_request()).response
        self.assertEqual(response.code, aiocoap.CONTENT)
        self.assertEqual(response.payload, b"protected data")
        self.assertEqual(self.testingsite.protected.calls, 1)
        self.assertEqual(self.testingsite.policy.issued, 1)

    @no_warnings
    async def test_managed_request_preserves_method_and_payload(self):
        request = self.build_request(code=aiocoap.PUT, payload=b"some payload")
        response = await self.client.request(request).response
        self.assertEqual(response.code, aiocoap.CHANGED)
        # The side effect happened exactly once, with the original payload
        self.assertEqual(self.testingsite.protected.calls, 1)
        self.assertEqual(self.testingsite.protected.payloads, [b"some payload"])

    @no_warnings
    async def test_manual_challenge_response(self):
        # Unmanaged requests see the challenge as a regular 4.01 response
        response = await self.client.request(
            self.build_request(), handle_blockwise=False
        ).response
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertEqual(self.testingsite.protected.calls, 0)

        # Resending the request with the Echo option satisfies the policy
        request = self.build_request()
        request.opt.echo = response.opt.echo
        response = await self.client.request(request, handle_blockwise=False).response
        self.assertEqual(response.code, aiocoap.CONTENT)
        self.assertEqual(self.testingsite.protected.calls, 1)

    @no_warnings
    async def test_expired_echo_rechallenged(self):
        # Obtain an Echo value ...
        response = await self.client.request(
            self.build_request(), handle_blockwise=False
        ).response
        echo = response.opt.echo

        # ... which is accepted before it expires ...
        request = self.build_request()
        request.opt.echo = echo
        response = await self.client.request(request, handle_blockwise=False).response
        self.assertEqual(response.code, aiocoap.CONTENT)
        self.assertEqual(self.testingsite.protected.calls, 1)

        # ... and rejected (with a fresh challenge) after its lifetime.
        self.echo_clock.advance(31.0)
        request = self.build_request()
        request.opt.echo = echo
        response = await self.client.request(request, handle_blockwise=False).response
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertNotEqual(response.opt.echo, echo)
        self.assertEqual(self.testingsite.protected.calls, 1)

    @no_warnings
    async def test_replayed_echo_rechallenged(self):
        # An Echo value issued to this client ...
        response = await self.client.request(
            self.build_request(), handle_blockwise=False
        ).response
        echo = response.opt.echo

        # ... is not accepted when replayed from another source address.
        other_client = await aiocoap.Context.create_client_context()
        try:
            request = self.build_request()
            request.opt.echo = echo
            response = await other_client.request(
                request, handle_blockwise=False
            ).response
            self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
            self.assertIsNotNone(response.opt.echo)
            self.assertEqual(self.testingsite.protected.calls, 0)

            # The other client can still complete its own challenge.
            request = self.build_request()
            request.opt.echo = response.opt.echo
            response = await other_client.request(
                request, handle_blockwise=False
            ).response
            self.assertEqual(response.code, aiocoap.CONTENT)
            self.assertEqual(self.testingsite.protected.calls, 1)
        finally:
            await other_client.shutdown()

    @no_warnings
    async def test_malformed_echo_rechallenged(self):
        request = self.build_request()
        request.opt.echo = b"garbage"
        response = await self.client.request(request, handle_blockwise=False).response
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertEqual(self.testingsite.protected.calls, 0)

    @precise_warnings(["Server keeps sending Echo challenges, not retrying again."])
    async def test_retries_are_bounded(self):
        request = self.build_request()
        request.opt.uri_path = ["always"]
        response = await self.client.request(request).response

        # The client gives up after a bounded number of retries and passes
        # the 4.01 response through.
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertEqual(
            self.testingsite.always.calls,
            1 + BlockwiseRequest.max_echo_retries,
        )


if __name__ == "__main__":
    unittest.main()
