# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Security-ordering tests for the combined EDHOC+OSCORE flow

In the combined flow (EDHOC message 3 prepended to the first OSCORE request,
signalled with the EDHOC option), the server must not let the business
resource run before the peer is authenticated. These tests drive the server
side (OscoreSiteWrapper) in-process -- no sockets involved -- with a
call-counting resource behind it, and tamper with

* the EDHOC message 3 authentication content,
* the first OSCORE ciphertext, and
* critical EAD items,

each time verifying that the resource is not entered, and that no
half-established context or wrong-identity claims remain usable afterwards
(in particular when the connection identifier C_R is reused for a valid
handshake). A non-combined (explicit message 3) exchange is run for comparison.

All credentials are generated locally and ephemerally for each test.
"""

import asyncio
import io
import logging
import unittest

import cbor2
import lakers

import aiocoap
from aiocoap import edhoc, oscore, resource
from aiocoap.message import Direction
from aiocoap.numbers import GET, POST, CON, CONTENT, CHANGED, BAD_REQUEST
from aiocoap.numbers.eaditem import EADLabel
from aiocoap.pipe import IterablePipe, error_to_message, run_driving_pipe
from aiocoap.oscore_sitewrapper import OscoreSiteWrapper

from .fixtures import IsolatedAsyncioTestCase

log = logging.getLogger("test.edhoc-combined")

SERVER_URI_HOST = "server.example"
SERVER_ORIGIN = "coap://" + SERVER_URI_HOST


class FakeRemote:
    """Stand-in for a transport address of an incoming request."""

    scheme = "coap"
    hostinfo = SERVER_URI_HOST
    hostinfo_local = SERVER_URI_HOST
    uri_base = SERVER_ORIGIN
    uri_base_local = SERVER_ORIGIN
    is_multicast = False
    is_multicast_locally = False
    blockwise_key = "fake-remote"


class CountingResource(resource.Resource):
    """Business resource that records whether (and as whom) it was invoked."""

    def __init__(self):
        self.render_count = 0
        self.seen_claims = []

    async def render_get(self, request):
        self.render_count += 1
        claims = list(request.remote.authenticated_claims)
        self.seen_claims.append(claims)
        return aiocoap.Message(code=CONTENT, payload=repr(claims).encode("utf8"))


class NoGrease(edhoc.GreaseSettings):
    """GreaseSettings that never greases (deterministic message sizes)."""

    def __init__(self):
        self.bits = 63

    def should_grease(self):
        return False


class InjectEad(NoGrease):
    """GreaseSettings look-alike that adds fixed EAD items to message 3."""

    def __init__(self, eads):
        super().__init__()
        self._eads = eads

    def grease_ead(self, eads):
        return [*eads, *self._eads]


def generate_ccs(kid, subject):
    key = edhoc.CoseKeyForEdhoc.generate()
    return key, key.as_ccs(kid=kid, subject=subject)


class EdhocServerRig:
    """An OscoreSiteWrapper-protected site with EDHOC credentials, driven
    in-process at the render_to_pipe level (mirroring how protocol.py feeds
    incoming requests into the site)."""

    def __init__(self, server_key, server_ccs, clients):
        """
        clients: dict of label -> peer CCS; the label becomes the
        authenticated claim a client of that credential gets.
        """
        self.credentials = aiocoap.credentials.CredentialsMap()
        self.credentials.load_from_dict(
            {
                SERVER_ORIGIN + "/*": {
                    "edhoc-oscore": {
                        "suite": 2,
                        "method": 3,
                        "own_cred_style": "by-value",
                        "own_cred": server_ccs,
                        "private_key": server_key.secret_to_map(),
                    }
                },
                **{
                    label: {
                        "edhoc-oscore": {
                            "suite": 2,
                            "method": 3,
                            "peer_cred": ccs,
                        }
                    }
                    for label, ccs in clients.items()
                },
            }
        )

        self.counting = CountingResource()
        site = resource.Site()
        site.add_resource(["counting"], self.counting)
        self.wrapper = OscoreSiteWrapper(site, self.credentials)

    async def dispatch(self, request):
        """Feed a request into the site as if it arrived from the network;
        return the terminal response message."""
        request.mtype = CON
        request.direction = Direction.INCOMING
        request.remote = FakeRemote()

        pipe = IterablePipe(request)
        responder_side = error_to_message(pipe, log)
        run_driving_pipe(
            responder_side, self.wrapper.render_to_pipe(responder_side)
        )

        responses = []
        async for event in pipe:
            if event.message is not None:
                responses.append(event.message)
            if event.is_last:
                break
        # let cancellations of any helper tasks propagate
        await asyncio.sleep(0)
        assert responses, "Site produced no response at all"
        return responses[-1]

    def find_context(self, c_r):
        """Return the EdhocResponderContext registered for C_R, if any."""
        for item in self.credentials.values():
            if isinstance(item, edhoc.EdhocResponderContext):
                if item.recipient_id == c_r:
                    return item
        return None

    def context_count(self):
        return sum(
            1
            for item in self.credentials.values()
            if isinstance(item, edhoc.EdhocResponderContext)
        )


class ClientHandshake:
    """Drives the initiator side of EDHOC manually against an EdhocServerRig."""

    def __init__(self, rig, key, ccs, server_ccs, c_i=b"\x0a"):
        self.rig = rig
        self.key = key
        self.ccs = ccs
        self.server_ccs = server_ccs
        self.c_i = c_i

    async def run_message_12(self):
        self.initiator = lakers.EdhocInitiator()
        message_1 = self.initiator.prepare_message_1(
            self.c_i, [lakers.EADItem(EADLabel.CRED_BY_VALUE, is_critical=False)]
        )
        request = aiocoap.Message(
            code=POST,
            uri_host=SERVER_URI_HOST,
            uri_path=[".well-known", "edhoc"],
            payload=cbor2.dumps(True) + message_1,
        )
        response = await self.rig.dispatch(request)
        assert response.code == CHANGED, (
            "message 1 rejected: %r" % response
        )
        self.c_r, _id_cred_r, _ead_2 = self.initiator.parse_message_2(response.payload)
        return self.c_r

    def build_context(self, cred_i_override=None, ead3=(), complete=True):
        """Verify message 2 and build the initiator OSCORE context (which
        prepares message 3). By default the context is completed without
        message 4 as in the combined flow; pass complete=False for the
        explicit message 3 / message 4 flow."""
        cred_i = cbor2.dumps(
            (cred_i_override if cred_i_override is not None else self.ccs)[14],
            canonical=True,
        )
        cred_r = cbor2.dumps(self.server_ccs[14], canonical=True)
        self.initiator.verify_message_2(self.key.d, cred_i, cred_r)
        grease = InjectEad(ead3) if ead3 else NoGrease()
        self.context = edhoc.EdhocInitiatorContext(
            self.initiator,
            self.c_i,
            self.c_r,
            edhoc.OwnCredStyle.ByValue,
            log,
            grease,
        )
        self.context.complete_without_message_4() if complete else None
        return self.context

    def build_combined_request(self):
        """Build the combined EDHOC message 3 + OSCORE request."""
        message = aiocoap.Message(
            code=GET, uri_host=SERVER_URI_HOST, uri_path=["counting"]
        )
        protected, self.request_id = self.context.protect(message)
        assert protected.opt.edhoc
        return protected

    def build_plain_request(self):
        """Build a follow-up OSCORE request (no EDHOC option)."""
        message = aiocoap.Message(
            code=GET, uri_host=SERVER_URI_HOST, uri_path=["counting"]
        )
        protected, self.request_id = self.context.protect(message)
        assert not protected.opt.edhoc
        return protected

    async def unprotect_response(self, response):
        response.direction = Direction.INCOMING
        unprotected, _ = self.context.unprotect(response, self.request_id)
        return unprotected

    async def send_explicit_message_3(self, message_3=None):
        """Send message 3 the non-combined way and complete the context with
        the received message 4."""
        if message_3 is None:
            message_3 = self.context._message_3
            self.context._message_3 = None
        c_r = self.c_r
        if len(c_r) == 1 and (0 <= c_r[0] < 24 or 0x20 <= c_r[0] < 0x38):
            c_r_encoded = c_r
        else:
            c_r_encoded = cbor2.dumps(c_r)
        request = aiocoap.Message(
            code=POST,
            uri_host=SERVER_URI_HOST,
            uri_path=[".well-known", "edhoc"],
            payload=c_r_encoded + message_3,
        )
        return await self.rig.dispatch(request)


def message_3_length(protected_payload):
    """Length of the leading EDHOC message 3 in a combined payload (it is a
    single CBOR byte string; EAD items are inside ciphertext_3)."""
    stream = io.BytesIO(protected_payload)
    cbor2.load(stream)
    return stream.tell()


edhoc_modules = aiocoap.defaults.oscore_missing_modules()


@unittest.skipIf(edhoc_modules, "EDHOC/OSCORE missing modules (%s)" % (edhoc_modules,))
class TestCombinedEdhocFlow(IsolatedAsyncioTestCase):
    def setUp(self):
        self.server_key, self.server_ccs = generate_ccs(b"\x00", "server")
        self.client_key, self.client_ccs = generate_ccs(b"\x01", "client")
        self.rig = EdhocServerRig(
            self.server_key, self.server_ccs, {":edhocclient": self.client_ccs}
        )

    def new_client(self):
        return ClientHandshake(self.rig, self.client_key, self.client_ccs, self.server_ccs)

    async def test_valid_combined_flow(self):
        """Baseline: a valid combined request authenticates first, then runs
        the resource exactly once, with the client's claims."""
        client = self.new_client()
        c_r = await client.run_message_12()
        client.build_context()
        request = client.build_combined_request()

        response = await self.rig.dispatch(request)
        plain = await client.unprotect_response(response)

        self.assertEqual(plain.code, CONTENT)
        self.assertEqual(self.rig.counting.render_count, 1)
        self.assertEqual(self.rig.counting.seen_claims, [[":edhocclient"]])
        context = self.rig.find_context(c_r)
        self.assertIsNotNone(context)
        self.assertFalse(context._incomplete)
        self.assertEqual(context.authenticated_claims, [":edhocclient"])

    async def test_corrupted_handshake_authentication(self):
        """Tampered message 3 authentication: the resource must not run, no
        half-established context may remain, and a valid handshake reusing the
        connection identifier must succeed cleanly."""
        client = self.new_client()
        c_r = await client.run_message_12()
        client.build_context()
        request = client.build_combined_request()

        # Flip a bit in the authentication part of message 3 (the end of
        # ciphertext_3, which carries MAC_3)
        m3len = message_3_length(request.payload)
        tampered = bytearray(request.payload)
        tampered[m3len - 1] ^= 0x01
        request.payload = bytes(tampered)

        response = await self.rig.dispatch(request)

        self.assertEqual(response.code, BAD_REQUEST)
        self.assertEqual(self.rig.counting.render_count, 0)
        self.assertEqual(self.rig.counting.seen_claims, [])
        # No half-established context may linger: the connection identifier
        # is free again.
        self.assertIsNone(self.rig.find_context(c_r))
        self.assertEqual(self.rig.context_count(), 0)

        # A valid handshake reusing the same connection identifier works and
        # yields exactly the client's claims -- no residue.
        retry = self.new_client()
        c_r_retry = await retry.run_message_12()
        self.assertEqual(c_r_retry, c_r, "C_R was not freed after the failure")
        retry.build_context()
        response = await self.rig.dispatch(retry.build_combined_request())
        plain = await retry.unprotect_response(response)

        self.assertEqual(plain.code, CONTENT)
        self.assertEqual(self.rig.counting.render_count, 1)
        self.assertEqual(self.rig.counting.seen_claims, [[":edhocclient"]])
        context = self.rig.find_context(c_r)
        self.assertEqual(context.authenticated_claims, [":edhocclient"])

    async def test_corrupted_first_oscore_ciphertext(self):
        """Tampered OSCORE ciphertext around a valid message 3: the handshake
        completes (the context legitimately becomes authenticated at message 3
        verification), but the resource must not run on the corrupted request;
        a fresh request on the established context works."""
        client = self.new_client()
        c_r = await client.run_message_12()
        client.build_context()
        request = client.build_combined_request()

        # Flip a bit in the OSCORE ciphertext (after message 3)
        tampered = bytearray(request.payload)
        tampered[-1] ^= 0x01
        request.payload = bytes(tampered)

        response = await self.rig.dispatch(request)

        self.assertEqual(response.code, BAD_REQUEST)
        self.assertEqual(self.rig.counting.render_count, 0)

        # The context became authenticated when message 3 verified -- before
        # any business resource ran. It carries exactly the client's claims.
        context = self.rig.find_context(c_r)
        self.assertIsNotNone(context)
        self.assertFalse(context._incomplete)
        self.assertEqual(context.authenticated_claims, [":edhocclient"])

        # A retransmitted request (new sequence number, no EDHOC option) on
        # the established context succeeds.
        response = await self.rig.dispatch(client.build_plain_request())
        plain = await client.unprotect_response(response)
        self.assertEqual(plain.code, CONTENT)
        self.assertEqual(self.rig.counting.render_count, 1)
        self.assertEqual(self.rig.counting.seen_claims, [[":edhocclient"]])

    async def test_critical_ead3(self):
        """A critical EAD item in message 3 aborts the handshake before any
        credential lookup: resource not entered, no context left behind."""
        client = self.new_client()
        c_r = await client.run_message_12()
        client.build_context(
            ead3=[lakers.EADItem(160, value=b"critical", is_critical=True)]
        )
        request = client.build_combined_request()

        response = await self.rig.dispatch(request)

        self.assertEqual(response.code, BAD_REQUEST)
        self.assertEqual(self.rig.counting.render_count, 0)
        self.assertIsNone(self.rig.find_context(c_r))
        self.assertEqual(self.rig.context_count(), 0)

        # The freed connection identifier can be reused for a valid handshake.
        retry = self.new_client()
        c_r_retry = await retry.run_message_12()
        self.assertEqual(c_r_retry, c_r)
        retry.build_context()
        response = await self.rig.dispatch(retry.build_combined_request())
        plain = await retry.unprotect_response(response)
        self.assertEqual(plain.code, CONTENT)
        self.assertEqual(self.rig.counting.render_count, 1)
        self.assertEqual(self.rig.counting.seen_claims, [[":edhocclient"]])

    async def test_failed_authentication_leaves_no_identity_residue(self):
        """An attacker who claims a victim's identity in message 3 (valid
        message structure, but unable to prove possession of the victim's key)
        must not get the victim's claims attached to anything: the resource
        never runs, and the attacker's later honest handshake as itself shows
        only its own claims."""
        attacker_key, attacker_ccs = generate_ccs(b"\x02", "attacker")
        self.rig.credentials.load_from_dict(
            {
                ":attacker": {
                    "edhoc-oscore": {
                        "suite": 2,
                        "method": 3,
                        "peer_cred": attacker_ccs,
                    }
                }
            }
        )

        attacker = ClientHandshake(
            self.rig, attacker_key, attacker_ccs, self.server_ccs
        )
        c_r = await attacker.run_message_12()
        # Claim the victim's credential while using the attacker's key
        attacker.build_context(cred_i_override=self.client_ccs)
        request = attacker.build_combined_request()

        response = await self.rig.dispatch(request)

        self.assertEqual(response.code, BAD_REQUEST)
        self.assertEqual(self.rig.counting.render_count, 0)
        # No context with the victim's claims may survive the failed
        # verification.
        self.assertIsNone(self.rig.find_context(c_r))
        self.assertEqual(self.rig.context_count(), 0)

        # The attacker completes an honest handshake as itself; the victim's
        # claims do not stick anywhere.
        honest = ClientHandshake(self.rig, attacker_key, attacker_ccs, self.server_ccs)
        c_r_honest = await honest.run_message_12()
        self.assertEqual(c_r_honest, c_r)
        honest.build_context()
        response = await self.rig.dispatch(honest.build_combined_request())
        plain = await honest.unprotect_response(response)

        self.assertEqual(plain.code, CONTENT)
        self.assertEqual(self.rig.counting.render_count, 1)
        self.assertEqual(self.rig.counting.seen_claims, [[":attacker"]])
        context = self.rig.find_context(c_r)
        self.assertEqual(context.authenticated_claims, [":attacker"])

    async def test_explicit_message_3_comparison(self):
        """Non-combined flow for comparison: message 3 travels stand-alone,
        message 4 completes the handshake, and only then does the first OSCORE
        request reach the resource. A tampered stand-alone message 3 is
        rejected with the same no-residue properties."""
        client = self.new_client()
        c_r = await client.run_message_12()
        client.build_context(complete=False)

        response = await client.send_explicit_message_3()
        self.assertEqual(response.code, CHANGED)
        client.context.complete_with_message_4(response.payload)

        # The resource has not run yet (no OSCORE request was sent)
        self.assertEqual(self.rig.counting.render_count, 0)
        context = self.rig.find_context(c_r)
        self.assertFalse(context._incomplete)
        self.assertEqual(context.authenticated_claims, [":edhocclient"])

        response = await self.rig.dispatch(client.build_plain_request())
        plain = await client.unprotect_response(response)
        self.assertEqual(plain.code, CONTENT)
        self.assertEqual(self.rig.counting.render_count, 1)
        self.assertEqual(self.rig.counting.seen_claims, [[":edhocclient"]])

    async def test_explicit_message_3_tampered(self):
        """Tampered stand-alone message 3: rejected, resource never runs, no
        half-established context remains, identifier reusable."""
        client = self.new_client()
        c_r = await client.run_message_12()
        client.build_context(complete=False)

        message_3 = bytearray(client.context._message_3)
        message_3[-1] ^= 0x01
        response = await client.send_explicit_message_3(bytes(message_3))

        self.assertEqual(response.code, BAD_REQUEST)
        self.assertEqual(self.rig.counting.render_count, 0)
        self.assertIsNone(self.rig.find_context(c_r))
        self.assertEqual(self.rig.context_count(), 0)

        retry = self.new_client()
        c_r_retry = await retry.run_message_12()
        self.assertEqual(c_r_retry, c_r)
        retry.build_context(complete=False)
        response = await retry.send_explicit_message_3()
        self.assertEqual(response.code, CHANGED)
        retry.context.complete_with_message_4(response.payload)
        response = await self.rig.dispatch(retry.build_plain_request())
        plain = await retry.unprotect_response(response)
        self.assertEqual(plain.code, CONTENT)
        self.assertEqual(self.rig.counting.render_count, 1)
        self.assertEqual(self.rig.counting.seen_claims, [[":edhocclient"]])
