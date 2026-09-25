# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
import unittest
from types import SimpleNamespace

import aiocoap
import aiocoap.echo
import aiocoap.interfaces
import aiocoap.message
import aiocoap.resource

from . import common  # noqa: F401 (sets up environment)
from .fixtures import Destructing, no_warnings, CLEANUPTIME


class FakeClock:
    """Controllable clock used to test Echo validity periods"""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class RecordingResource(aiocoap.resource.Resource):
    """Resource whose (side-effectful) invocations can be observed"""

    def __init__(self):
        super().__init__()
        self.requests = []

    async def render_get(self, request):
        self.requests.append(request)
        return aiocoap.Message(payload=b"large answer " * 100)

    async def render_post(self, request):
        self.requests.append(request)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=b"stored")


class AlwaysChallengingResource(aiocoap.resource.Resource):
    """Resource that rejects every Echo value and challenges again"""

    def __init__(self):
        super().__init__()
        self.challenges = 0

    async def render_post(self, request):
        self.challenges += 1
        response = aiocoap.Message(code=aiocoap.UNAUTHORIZED)
        response.opt.echo = b"challenge-%d" % self.challenges
        return response


class _WithEchoContexts(Destructing):
    validity = 30

    def create_testing_site(self):
        self.clock = FakeClock()
        self.policy = aiocoap.echo.AddressBoundEchoPolicy(
            secret=b"test secret", validity=self.validity, clock=self.clock
        )
        self.inner = RecordingResource()
        site = aiocoap.resource.Site()
        site.add_resource(
            ["protected"], aiocoap.echo.EchoChallengeResource(self.inner, self.policy)
        )
        return site

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.server = await aiocoap.Context.create_server_context(
            self.create_testing_site(), bind=("::1", None)
        )
        self.client = await aiocoap.Context.create_client_context()

    async def asyncTearDown(self):
        await asyncio.sleep(CLEANUPTIME)
        await self.server.shutdown()
        await self.client.shutdown()
        await super().asyncTearDown()

    def build_request(self, code=aiocoap.GET, payload=b""):
        request = aiocoap.Message(code=code, payload=payload)
        request.unresolved_remote = "[::1]"
        request.opt.uri_path = ["protected"]
        return request


class TestEchoChallenge(_WithEchoContexts):
    @no_warnings
    async def test_handler_not_called_before_challenge(self):
        response = await self.client.request(self.build_request()).response

        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertEqual(
            self.inner.requests,
            [],
            "Side-effectful handler was invoked before the Echo challenge was passed",
        )

    @no_warnings
    async def test_retrying_client_completes_challenge(self):
        retrying = aiocoap.echo.EchoRetryingRequestProvider(self.client)

        response = await retrying.request(
            self.build_request(aiocoap.POST, b"payload")
        ).response

        self.assertEqual(response.code, aiocoap.CHANGED)
        self.assertEqual(len(self.inner.requests), 1)
        (handled,) = self.inner.requests
        self.assertEqual(handled.code, aiocoap.POST)
        self.assertEqual(handled.payload, b"payload")

    @no_warnings
    async def test_same_echo_before_and_after_expiry(self):
        first = await self.client.request(self.build_request()).response
        self.assertEqual(first.code, aiocoap.UNAUTHORIZED)
        echo = first.opt.echo

        # shortly before expiry, the very same Echo value is still accepted
        self.clock.advance(self.validity - 1)
        in_time = self.build_request(aiocoap.POST, b"in time")
        in_time.opt.echo = echo
        response = await self.client.request(in_time).response
        self.assertEqual(response.code, aiocoap.CHANGED)
        self.assertEqual(len(self.inner.requests), 1)

        # after expiry, the same Echo value is challenged again
        self.clock.advance(2)
        expired = self.build_request(aiocoap.POST, b"too late")
        expired.opt.echo = echo
        response = await self.client.request(expired).response
        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertNotEqual(response.opt.echo, echo)
        self.assertEqual(len(self.inner.requests), 1)

    @no_warnings
    async def test_malformed_echo_rechallenged(self):
        request = self.build_request(aiocoap.POST, b"payload")
        request.opt.echo = b"\x00garbage"
        response = await self.client.request(request).response

        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(response.opt.echo)
        self.assertEqual(self.inner.requests, [])


class TestEchoRetryLimit(Destructing):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.challenger = AlwaysChallengingResource()
        site = aiocoap.resource.Site()
        site.add_resource(["protected"], self.challenger)
        self.server = await aiocoap.Context.create_server_context(
            site, bind=("::1", None)
        )
        self.client = await aiocoap.Context.create_client_context()

    async def asyncTearDown(self):
        await asyncio.sleep(CLEANUPTIME)
        await self.server.shutdown()
        await self.client.shutdown()
        await super().asyncTearDown()

    @no_warnings
    async def test_retries_are_bounded(self):
        retrying = aiocoap.echo.EchoRetryingRequestProvider(self.client, max_retries=2)
        request = aiocoap.Message(code=aiocoap.POST, payload=b"payload")
        request.unresolved_remote = "[::1]"
        request.opt.uri_path = ["protected"]

        response = await retrying.request(request).response

        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertEqual(
            self.challenger.challenges,
            3,
            "Client did not stop after the initial request and 2 retries",
        )


class TestAddressBoundEchoPolicy(unittest.TestCase):
    """Policy-level tests with a controlled clock and mock remotes"""

    def setUp(self):
        self.clock = FakeClock()
        self.policy = aiocoap.echo.AddressBoundEchoPolicy(
            secret=b"test secret", validity=30, clock=self.clock
        )
        self.peer = SimpleNamespace(hostinfo="[2001:db8::1]:5683")

    def test_issue_validate_roundtrip(self):
        echo = self.policy.issue(self.peer)
        self.assertTrue(self.policy.validate(echo, self.peer))

    def test_expiry_with_controlled_clock(self):
        echo = self.policy.issue(self.peer)
        self.clock.advance(29)
        self.assertTrue(self.policy.validate(echo, self.peer))
        self.clock.advance(2)
        self.assertFalse(self.policy.validate(echo, self.peer))

    def test_replay_from_other_address_rejected(self):
        echo = self.policy.issue(self.peer)
        other = SimpleNamespace(hostinfo="[2001:db8::2]:5683")
        self.assertFalse(self.policy.validate(echo, other))

    def test_binding_covers_address_not_port(self):
        echo = self.policy.issue(self.peer)
        same_host_other_port = SimpleNamespace(hostinfo="[2001:db8::1]:9999")
        self.assertTrue(self.policy.validate(echo, same_host_other_port))

    def test_malformed_values_rejected(self):
        valid = self.policy.issue(self.peer)
        tampered = bytes([valid[0] ^ 0xFF]) + valid[1:]
        for garbage in (
            b"",
            b"\x00" * len(valid),
            valid + b"\x00",
            valid[:-1],
            tampered,
        ):
            self.assertFalse(
                self.policy.validate(garbage, self.peer),
                "Malformed Echo value %r was accepted" % (garbage,),
            )


class TestEchoChallengeResourceOffline(unittest.IsolatedAsyncioTestCase):
    """Render-path gating, exercised in-process without network access"""

    def setUp(self):
        self.clock = FakeClock()
        self.policy = aiocoap.echo.AddressBoundEchoPolicy(
            secret=b"test secret", validity=30, clock=self.clock
        )
        self.inner = RecordingResource()
        self.protected = aiocoap.echo.EchoChallengeResource(self.inner, self.policy)
        self.remote = SimpleNamespace(hostinfo="[2001:db8::1]:5683")

    def build_request(self, echo=None):
        request = aiocoap.Message(code=aiocoap.POST, payload=b"payload")
        request.direction = aiocoap.message.Direction.INCOMING
        request.remote = self.remote
        if echo is not None:
            request.opt.echo = echo
        return request

    async def test_challenge_then_render(self):
        challenged = await self.protected.render(self.build_request())
        self.assertEqual(challenged.code, aiocoap.UNAUTHORIZED)
        self.assertIsNotNone(challenged.opt.echo)
        self.assertEqual(self.inner.requests, [])

        response = await self.protected.render(
            self.build_request(echo=challenged.opt.echo)
        )
        self.assertEqual(response.code, aiocoap.CHANGED)
        self.assertEqual(len(self.inner.requests), 1)

    async def test_expired_and_foreign_echo_rechallenged(self):
        echo = self.policy.issue(self.remote)

        self.clock.advance(31)
        expired = await self.protected.render(self.build_request(echo=echo))
        self.assertEqual(expired.code, aiocoap.UNAUTHORIZED)

        self.clock.now = 1001.0
        foreign = self.policy.issue(SimpleNamespace(hostinfo="[2001:db8::2]:5683"))
        replayed = await self.protected.render(self.build_request(echo=foreign))
        self.assertEqual(replayed.code, aiocoap.UNAUTHORIZED)

        self.assertEqual(self.inner.requests, [])


class _FakeServerProvider(aiocoap.interfaces.RequestProvider):
    """In-process RequestProvider that behaves like an Echo-protected server

    Every request is answered with 4.01 and a fresh Echo value, unless it
    carries a currently valid one. If always_challenge is set, even valid
    Echo values are rejected again.
    """

    def __init__(self, policy, remote, always_challenge=False):
        self.policy = policy
        self.remote = remote
        self.always_challenge = always_challenge
        self.received = []

    def request(self, request_message, handle_blockwise=True):
        self.received.append(request_message)
        echo = request_message.opt.echo
        if (
            echo is None
            or self.always_challenge
            or not self.policy.validate(echo, self.remote)
        ):
            response = aiocoap.Message(code=aiocoap.UNAUTHORIZED)
            response.opt.echo = self.policy.issue(self.remote)
        else:
            response = aiocoap.Message(
                code=aiocoap.CHANGED, payload=request_message.payload
            )
        future = asyncio.get_running_loop().create_future()
        future.set_result(response)
        return SimpleNamespace(response=future)


class TestEchoRetryingClientOffline(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.policy = aiocoap.echo.AddressBoundEchoPolicy(
            secret=b"test secret", validity=30, clock=FakeClock()
        )
        self.remote = SimpleNamespace(hostinfo="[2001:db8::1]:5683")

    async def test_challenge_completed_preserving_request(self):
        provider = _FakeServerProvider(self.policy, self.remote)
        retrying = aiocoap.echo.EchoRetryingRequestProvider(provider)

        request = aiocoap.Message(code=aiocoap.POST, payload=b"payload")
        response = await retrying.request(request).response

        self.assertEqual(response.code, aiocoap.CHANGED)
        self.assertEqual(response.payload, b"payload")
        self.assertEqual(len(provider.received), 2)
        first, second = provider.received
        self.assertIsNone(first.opt.echo)
        self.assertIsNotNone(second.opt.echo)
        for attempt in (first, second):
            self.assertEqual(attempt.code, aiocoap.POST)
            self.assertEqual(attempt.payload, b"payload")
        # the caller's original message is left untouched
        self.assertIsNone(request.opt.echo)

    async def test_endless_challenges_do_not_loop_forever(self):
        provider = _FakeServerProvider(self.policy, self.remote, always_challenge=True)
        retrying = aiocoap.echo.EchoRetryingRequestProvider(provider, max_retries=3)

        request = aiocoap.Message(code=aiocoap.POST, payload=b"payload")
        response = await retrying.request(request).response

        self.assertEqual(response.code, aiocoap.UNAUTHORIZED)
        self.assertEqual(len(provider.received), 4)


if __name__ == "__main__":
    unittest.main()
