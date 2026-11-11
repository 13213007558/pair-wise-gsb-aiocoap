# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests for the proxy's unknown option handling policy (documented in
aiocoap.proxy.server's module docstring) and its interplay with cache key
generation.

These tests run fully in memory: requests are passed through the real proxy
entry point (``Proxy.render``), and the outgoing side is a fake context that
records exactly what would have been sent to the remote server."""

import asyncio
import unittest

import aiocoap
import aiocoap.optiontypes
import aiocoap.proxy.server
from aiocoap.numbers.codes import GET, CONTENT, BAD_OPTION, NOT_IMPLEMENTED
from aiocoap.numbers.optionnumbers import OptionNumber

from . import common  # noqa: F401 'imported but unused' (sets up environment)

# Custom (deliberately unregistered) option numbers covering all relevant
# combinations of the critical, unsafe-to-forward and nocachekey bits.

#: critical, safe-to-forward, part of the cache key
CUSTOM_CRITICAL_SAFE = OptionNumber(2049)
#: elective, safe-to-forward, part of the cache key
CUSTOM_ELECTIVE_SAFE = OptionNumber(2048)
#: critical, safe-to-forward, NoCacheKey
CUSTOM_CRITICAL_SAFE_NOCACHEKEY = OptionNumber(2077)
#: elective, safe-to-forward, NoCacheKey
CUSTOM_ELECTIVE_SAFE_NOCACHEKEY = OptionNumber(2076)
#: critical, unsafe-to-forward
CUSTOM_CRITICAL_UNSAFE = OptionNumber(2051)
#: elective, unsafe-to-forward
CUSTOM_ELECTIVE_UNSAFE = OptionNumber(2050)


class TestCustomOptionBitCombinations(unittest.TestCase):
    """Guard the test data itself: the custom option numbers must exhibit
    the bit combinations the policy tests rely on."""

    def test_bit_combinations(self):
        self.assertTrue(CUSTOM_CRITICAL_SAFE.is_critical())
        self.assertTrue(CUSTOM_CRITICAL_SAFE.is_safetoforward())
        self.assertTrue(CUSTOM_CRITICAL_SAFE.is_cachekey())

        self.assertTrue(CUSTOM_ELECTIVE_SAFE.is_elective())
        self.assertTrue(CUSTOM_ELECTIVE_SAFE.is_safetoforward())
        self.assertTrue(CUSTOM_ELECTIVE_SAFE.is_cachekey())

        self.assertTrue(CUSTOM_CRITICAL_SAFE_NOCACHEKEY.is_critical())
        self.assertTrue(CUSTOM_CRITICAL_SAFE_NOCACHEKEY.is_safetoforward())
        self.assertTrue(CUSTOM_CRITICAL_SAFE_NOCACHEKEY.is_nocachekey())

        self.assertTrue(CUSTOM_ELECTIVE_SAFE_NOCACHEKEY.is_elective())
        self.assertTrue(CUSTOM_ELECTIVE_SAFE_NOCACHEKEY.is_safetoforward())
        self.assertTrue(CUSTOM_ELECTIVE_SAFE_NOCACHEKEY.is_nocachekey())

        self.assertTrue(CUSTOM_CRITICAL_UNSAFE.is_critical())
        self.assertTrue(CUSTOM_CRITICAL_UNSAFE.is_unsafe())

        self.assertTrue(CUSTOM_ELECTIVE_UNSAFE.is_elective())
        self.assertTrue(CUSTOM_ELECTIVE_UNSAFE.is_unsafe())

    def test_nocachekey_is_meaningless_for_unsafe_options(self):
        """NoCacheKey is only defined for safe-to-forward options; asking an
        unsafe option about it is an error rather than a "no"."""
        with self.assertRaises(ValueError):
            CUSTOM_CRITICAL_UNSAFE.is_nocachekey()


class FakeObservation:
    def __init__(self):
        self.cancelled = False

    def register_callback(self, callback):
        pass

    def register_errback(self, errback):
        pass

    def cancel(self):
        self.cancelled = True


class FakeClientRequest:
    """Stand-in for the object returned by Context.request"""

    def __init__(self):
        self.response = asyncio.get_running_loop().create_future()
        self.observation = FakeObservation()


class FakeOutgoingContext:
    """Stand-in for the proxy's outgoing context.

    Records every request the proxy attempts to send, and immediately
    satisfies them with an empty 2.05 Content response."""

    def __init__(self):
        self.requests = []

    def request(self, request, **kwargs):
        self.requests.append(request)
        clientrequest = FakeClientRequest()
        clientrequest.response.set_result(
            aiocoap.Message(code=CONTENT, payload=b"remote")
        )
        return clientrequest


def forward_request():
    """A minimal request that a ForwardProxy can redirect"""
    request = aiocoap.Message(code=GET)
    request.opt.proxy_scheme = "coap"
    request.opt.uri_host = "example.com"
    request.opt.uri_path = ("target",)
    return request


class TestUnknownOptionForwarding(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.outgoing = FakeOutgoingContext()
        self.proxy = aiocoap.proxy.server.ForwardProxy(self.outgoing)

    async def test_safe_unknown_options_forwarded_verbatim(self):
        """Unknown safe-to-forward options of any criticality and cache-key
        class are forwarded, with their bytes (including non-normalizable
        leading zeros) and repetition order untouched."""
        request = forward_request()
        request.opt.add_option(
            CUSTOM_CRITICAL_SAFE.create_option(value=b"\x00\x00\x01")
        )
        # repeated options must survive in order
        request.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"second"))
        request.opt.add_option(CUSTOM_ELECTIVE_SAFE.create_option(value=b"elective"))
        request.opt.add_option(
            CUSTOM_CRITICAL_SAFE_NOCACHEKEY.create_option(value=b"nc-critical")
        )
        request.opt.add_option(
            CUSTOM_ELECTIVE_SAFE_NOCACHEKEY.create_option(value=b"nc-elective")
        )

        response = await self.proxy.render(request)

        self.assertEqual(response.code, CONTENT)
        [forwarded] = self.outgoing.requests

        # the proxy rewrote the addressing options into a remote ...
        self.assertIsNone(forwarded.opt.proxy_scheme)
        self.assertIsNone(forwarded.opt.uri_port)
        self.assertEqual(forwarded.remote.scheme, "coap")
        self.assertEqual(forwarded.remote.hostinfo, "example.com")

        # ... while the unknown options passed through byte for byte
        self.assertEqual(
            [o.value for o in forwarded.opt.get_option(CUSTOM_CRITICAL_SAFE)],
            [b"\x00\x00\x01", b"second"],
        )
        self.assertEqual(
            [o.value for o in forwarded.opt.get_option(CUSTOM_ELECTIVE_SAFE)],
            [b"elective"],
        )
        self.assertEqual(
            [
                o.value
                for o in forwarded.opt.get_option(CUSTOM_CRITICAL_SAFE_NOCACHEKEY)
            ],
            [b"nc-critical"],
        )
        self.assertEqual(
            [
                o.value
                for o in forwarded.opt.get_option(CUSTOM_ELECTIVE_SAFE_NOCACHEKEY)
            ],
            [b"nc-elective"],
        )

    async def test_wire_bytes_are_not_normalized(self):
        """A request decoded from the wire keeps its unknown options' exact
        bytes all the way into the forwarded request."""
        request = forward_request()
        request.mtype = aiocoap.CON
        request.mid = 0x1234
        # values chosen to be non-canonical under any typed interpretation
        request.opt.add_option(
            CUSTOM_CRITICAL_SAFE.create_option(value=b"\x00\x00\x01")
        )
        request.opt.add_option(
            CUSTOM_CRITICAL_SAFE.create_option(value=b"\xff\x00\xff")
        )

        decoded = aiocoap.Message.decode(request.encode())
        self.assertEqual(decoded.direction, aiocoap.message.Direction.INCOMING)

        response = await self.proxy.render(decoded)

        self.assertEqual(response.code, CONTENT)
        [forwarded] = self.outgoing.requests
        options = forwarded.opt.get_option(CUSTOM_CRITICAL_SAFE)
        self.assertEqual([o.value for o in options], [b"\x00\x00\x01", b"\xff\x00\xff"])
        # still opaque, ie. nothing attempted to interpret (and thus possibly
        # normalize) the value
        self.assertTrue(
            all(isinstance(o, aiocoap.optiontypes.OpaqueOption) for o in options)
        )

    async def test_known_options_are_accepted(self):
        """Options the proxy knows pass the policy check and are forwarded"""
        request = forward_request()
        request.opt.uri_query = ("a=1", "b=2")
        request.opt.accept = 40
        request.opt.etags = (b"tag1", b"tag2")

        response = await self.proxy.render(request)

        self.assertEqual(response.code, CONTENT)
        [forwarded] = self.outgoing.requests
        self.assertEqual(forwarded.opt.uri_query, ("a=1", "b=2"))
        self.assertEqual(forwarded.opt.accept, 40)
        self.assertEqual(forwarded.opt.etags, (b"tag1", b"tag2"))

    async def test_unknown_unsafe_options_are_rejected(self):
        """Unknown unsafe-to-forward options fail with 4.02 Bad Option
        naming the offending option, and nothing is forwarded -- no matter
        whether the option is critical or elective."""
        for number in (CUSTOM_CRITICAL_UNSAFE, CUSTOM_ELECTIVE_UNSAFE):
            with self.subTest(number=number):
                request = forward_request()
                request.opt.add_option(number.create_option(value=b"opaque"))

                response = await self.proxy.render(request)

                self.assertEqual(response.code, BAD_OPTION)
                self.assertIn(str(int(number)).encode("ascii"), response.payload)
                self.assertEqual(self.outgoing.requests, [])

    async def test_unsafe_unknown_option_rejects_despite_safe_company(self):
        """A single unknown unsafe option rejects the whole request, even if
        all other options are known or safe to forward."""
        request = forward_request()
        request.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"fine"))
        request.opt.add_option(CUSTOM_ELECTIVE_UNSAFE.create_option(value=b"no"))

        response = await self.proxy.render(request)

        self.assertEqual(response.code, BAD_OPTION)
        self.assertEqual(self.outgoing.requests, [])

    async def test_proxy_uri_is_not_rewritten(self):
        """Proxy-Uri is not split by this proxy; the request fails with an
        explainable 5.01 and is not forwarded."""
        request = aiocoap.Message(code=GET)
        request.opt.proxy_uri = "coap://example.com/target"

        response = await self.proxy.render(request)

        self.assertEqual(response.code, NOT_IMPLEMENTED)
        self.assertIn(b"Proxy-Scheme", response.payload)
        self.assertEqual(self.outgoing.requests, [])


class TestCacheKeyPolicy(unittest.TestCase):
    """Cache key generation honors the NoCacheKey bit -- and only that bit:
    requests that differ semantically must not share a cache entry."""

    def test_cachekey_options_separate_cache_entries(self):
        base = forward_request()
        variant1 = forward_request()
        variant1.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"1"))
        variant2 = forward_request()
        variant2.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"2"))

        self.assertNotEqual(variant1.get_cache_key(), variant2.get_cache_key())
        self.assertNotEqual(variant1.get_cache_key(), base.get_cache_key())

        # repetition is significant too: dropping or reordering repeated
        # options changes the key
        repeated = forward_request()
        repeated.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"1"))
        repeated.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"2"))
        self.assertNotEqual(repeated.get_cache_key(), variant1.get_cache_key())

    def test_nocachekey_options_do_not_separate_cache_entries(self):
        base = forward_request()
        for number in (
            CUSTOM_CRITICAL_SAFE_NOCACHEKEY,
            CUSTOM_ELECTIVE_SAFE_NOCACHEKEY,
        ):
            with self.subTest(number=number):
                variant = forward_request()
                variant.opt.add_option(number.create_option(value=b"ignored"))
                self.assertEqual(variant.get_cache_key(), base.get_cache_key())

    def test_unsafe_options_are_part_of_the_cache_key(self):
        """NoCacheKey is undefined for unsafe options, so they always
        contribute to the key (when they are cached at all -- a proxy would
        have rejected them already)."""
        variant1 = forward_request()
        variant1.opt.add_option(CUSTOM_CRITICAL_UNSAFE.create_option(value=b"1"))
        variant2 = forward_request()
        variant2.opt.add_option(CUSTOM_CRITICAL_UNSAFE.create_option(value=b"2"))

        self.assertNotEqual(variant1.get_cache_key(), variant2.get_cache_key())


class TestPooledObservationCacheKey(unittest.IsolatedAsyncioTestCase):
    """The proxy's own cache (pooled observations) keys on the same rules:
    semantically different requests never share a cached observation."""

    def setUp(self):
        self.outgoing = FakeOutgoingContext()
        self.proxy = aiocoap.proxy.server.ForwardProxyWithPooledObservations(
            self.outgoing
        )

    @staticmethod
    def observe_request():
        request = forward_request()
        request.opt.observe = 0
        return request

    async def test_semantically_different_requests_do_not_share_cache(self):
        request_a = self.observe_request()
        request_a.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"a"))
        request_b = self.observe_request()
        request_b.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"b"))

        observation_a = self.proxy._get_observation_for(request_a)
        observation_b = self.proxy._get_observation_for(request_b)

        self.assertIsNot(observation_a, observation_b)
        self.assertEqual(len(self.outgoing.requests), 2)

        # a request differing only in a NoCacheKey option (and in the Observe
        # option, which the proxy handles itself) is the same request as far
        # as the cache is concerned
        request_c = self.observe_request()
        request_c.opt.add_option(CUSTOM_CRITICAL_SAFE.create_option(value=b"a"))
        request_c.opt.add_option(
            CUSTOM_ELECTIVE_SAFE_NOCACHEKEY.create_option(value=b"ignored")
        )
        request_c.opt.observe = 1

        observation_c = self.proxy._get_observation_for(request_c)

        self.assertIs(observation_c, observation_a)
        self.assertEqual(len(self.outgoing.requests), 2)
