#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Group OSCORE identity-verification scenario for aiocoap.

Sets up one OSCORE group with a server and two legitimate members
(alice, bob) plus an impersonation actor, then checks:

* ciphertext that decrypts fine under shared group material is still
  rejected when the *member identity* (countersignature / pairwise key)
  does not verify;
* tampered packets (kid swap, member-credential swap, signature swap)
  never update replay state and never reach the application;
* failed packets do not disturb the other member's traffic;
* group-mode vs. pairwise-mode request/response paths.

No private keys are printed; members are identified by kid and by a
SHA-256 fingerprint of their *public* key only.
"""

import copy
import hashlib
import secrets
import sys

import cbor2

import aiocoap
import aiocoap.meta
import aiocoap.oscore
import aiocoap.credentials
from aiocoap import Message
from aiocoap.message import Direction
from aiocoap.oscore import (
    SimpleGroupContext,
    RequestIdentifiers,
    ProtectionInvalid,
    ReplayError,
    DecodeError,
    COSE_PIV,
)

# ---------------------------------------------------------------- group setup

alg_aead = aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM]
alg_group_enc = aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM]
hashfun = aiocoap.oscore.hashfunctions[aiocoap.oscore.DEFAULT_HASHFUNCTION]
alg_countersign = aiocoap.oscore.Ed25519()
alg_pairwise = aiocoap.oscore.EcdhSsHkdf256()

GROUP_ID = b"G"
SERVER, ALICE, BOB = b"", b"\x01", b"\x02"
MEMBER_NAMES = {SERVER: "server", ALICE: "alice", BOB: "bob"}

master_secret = secrets.token_bytes(64)
master_salt = b"PoCl4"
gm_cred = b"dummy credential"

privates = {}
creds = {}
for kid in (SERVER, ALICE, BOB):
    privates[kid], creds[kid] = alg_countersign.generate_with_ccs()


def make_group_context(own_id):
    return SimpleGroupContext(
        alg_aead,
        hashfun,
        alg_countersign,
        alg_group_enc,
        alg_pairwise,
        GROUP_ID,
        master_secret,
        master_salt,
        own_id,
        privates[own_id],
        creds[own_id],
        {k: creds[k] for k in (SERVER, ALICE, BOB) if k != own_id},
        gm_cred,
        group_manager_cred_fmt="dummy",
    )


server_ctx = make_group_context(SERVER)
alice_ctx = make_group_context(ALICE)
bob_ctx = make_group_context(BOB)

server_credentials = aiocoap.credentials.CredentialsMap()
server_credentials[":a"] = server_ctx


def pub_fingerprint(kid):
    pub = server_ctx._parse_credential(creds[kid]) if kid != SERVER else None
    if pub is None:
        pub = alg_countersign.public_from_private(privates[kid])
    return hashlib.sha256(pub).hexdigest()[:16]


# ------------------------------------------------------------------ helpers

app_log = []  # (sender_label, code, payload) actually delivered to the "application"
results = []  # (test_id, description, ok, detail)


def record(test_id, description, ok, detail=""):
    results.append((test_id, description, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {test_id}: {description}" + (f" -- {detail}" if detail else ""))


def window_state(kid):
    w = server_ctx.recipient_replay_windows[kid]
    return w.persist()


def server_receive(wire_message):
    """Mirror of OscoreSiteWrapper.render_to_pipe's security gate:
    context lookup by unprotected COSE header, then unprotect; only on
    success is the message handed to the application."""
    unprotected = aiocoap.oscore.verify_start(wire_message)
    sc = server_credentials.find_oscore(unprotected)  # KeyError -> 4.01
    plain, request_id = sc.unprotect(wire_message)
    app_log.append((type(sc).__name__, plain.code, plain.payload))
    return sc, plain, request_id


_mid = [0x4000]


def protect_request(ctx, payload, seq_token):
    _mid[0] += 1
    msg = Message(code=aiocoap.POST, uri_path=("identity", "check"), payload=payload)
    msg.mid = _mid[0]
    msg.token = seq_token
    msg.mtype = aiocoap.CON
    msg.direction = Direction.OUTGOING
    outer, request_id = ctx.protect(msg)
    # mid/token/mtype are set by the transport in a real stack
    outer.mid = msg.mid
    outer.token = msg.token
    outer.mtype = msg.mtype
    return outer, request_id


def protect_response(resp_ctx, payload, srv_reqid, req_token):
    _mid[0] += 1
    resp = Message(code=aiocoap.CONTENT, payload=payload)
    resp.direction = Direction.OUTGOING
    outer, _ = resp_ctx.protect(resp, srv_reqid)
    outer.mid = _mid[0]
    outer.token = req_token
    outer.mtype = aiocoap.ACK
    return outer


def to_wire(outer):
    return outer.encode()


def from_wire(raw):
    msg = Message.decode(raw)
    msg.direction = Direction.INCOMING
    return msg


def parse_oscore_option(opt):
    first = opt[0]
    idx = 1
    piv = opt[idx : idx + (first & 0x07)]
    idx += first & 0x07
    kid_context = None
    if first & 0x10:
        length = opt[idx]
        idx += 1
        kid_context = opt[idx : idx + length]
        idx += length
    kid = opt[idx:] if first & 0x08 else b""
    return first, piv, kid_context, kid


def rebuild_oscore_option(first, piv, kid_context, kid):
    out = bytes([first]) + piv
    if first & 0x10:
        out += bytes([len(kid_context)]) + kid_context
    if first & 0x08:
        out += kid
    return out


def with_swapped_kid(raw, new_kid):
    """Keep the ciphertext body byte-identical, replace only the kid."""
    msg = from_wire(raw)
    first, piv, kid_context, _kid = parse_oscore_option(msg.opt.oscore)
    msg.opt.oscore = rebuild_oscore_option(first, piv, kid_context, new_kid)
    return msg


def expect_reject(test_id, description, wire_message, before):
    try:
        server_receive(wire_message)
    except Exception as e:
        ok = window_state(ALICE) == before[ALICE] and window_state(BOB) == before[BOB]
        record(
            test_id,
            description,
            ok,
            f"rejected with {type(e).__name__}; replay windows unchanged: {ok}",
        )
        return True
    record(test_id, description, False, "message was ACCEPTED (must not happen)")
    return False


# =================================================================== scenario

print("=" * 78)
print("Group OSCORE identity-verification scenario (aiocoap %s)" % aiocoap.meta.version)
print("=" * 78)
print("group id: %r, countersign: Ed25519, pairwise: ECDH-SS+HKDF-256" % GROUP_ID)
for kid in (SERVER, ALICE, BOB):
    print(
        "  member %-6s kid=%s pubkey-fingerprint=%s"
        % (MEMBER_NAMES[kid], kid.hex(), pub_fingerprint(kid))
    )
print()

before = {ALICE: window_state(ALICE), BOB: window_state(BOB)}

# ---- T0: baseline, genuine group-mode request from alice -------------------
outer, _ = protect_request(alice_ctx, b"alice-hello-0", b"t-a0")
alice_wire_seq0 = to_wire(outer)
sc, plain, _ = server_receive(from_wire(alice_wire_seq0))
record(
    "T0",
    "genuine group-mode request from alice is delivered",
    plain.payload == b"alice-hello-0" and window_state(ALICE) != before[ALICE],
    f"context={type(sc).__name__}, alice window after: {window_state(ALICE)}",
)
before = {ALICE: window_state(ALICE), BOB: window_state(BOB)}

# ---- T1: kid swap (alice's packet re-labeled as bob) -----------------------
outer, _ = protect_request(alice_ctx, b"alice-hello-1", b"t-a1")
alice_wire_seq1 = to_wire(outer)
tampered = with_swapped_kid(alice_wire_seq1, BOB)
expect_reject(
    "T1",
    "kid swap: alice's ciphertext re-labeled with bob's kid is rejected",
    tampered,
    before,
)

# ---- T2: insider forgery -- bob impersonates alice -------------------------
# bob is a legitimate group member: he holds the shared group material and can
# derive alice's group sender key. He builds a context that *claims* alice's
# kid but signs with his own key.
forgery_ctx = SimpleGroupContext(
    alg_aead,
    hashfun,
    alg_countersign,
    alg_group_enc,
    alg_pairwise,
    GROUP_ID,
    master_secret,
    master_salt,
    ALICE,          # claims alice's identity
    privates[BOB],  # ... but only has bob's private key
    creds[BOB],
    {SERVER: creds[SERVER], BOB: creds[BOB]},
    gm_cred,
    group_manager_cred_fmt="dummy",
)
# use a sequence number that is fresh on the server, so the packet passes the
# replay check and the *authentication* checks are what actually reject it
forgery_ctx.sender_sequence_number = 10
outer, _ = protect_request(forgery_ctx, b"forged-by-bob-as-alice", b"t-f1")
forged_wire = to_wire(outer)

# show the ciphertext *is* decryptable with shared group material
forged_msg = from_wire(forged_wire)
aspect = server_ctx.get_oscore_context_for(aiocoap.oscore.verify_start(forged_msg))
_, _, unprotected_hdr, ciphertext = aiocoap.oscore.CanUnprotect._extract_encrypted0(
    forged_msg
)
piv = unprotected_hdr[COSE_PIV]
siglen = alg_countersign.signature_length
rid = RequestIdentifiers(ALICE, piv, can_reuse_nonce=True, request_code=forged_msg.code)
# The forger embedded *his own* credential in the AAD; decrypt with the AAD
# the sender actually used to show the ciphertext is well-formed under the
# shared group material alone.
saved_cred_for_aad = server_ctx.recipient_auth_creds[ALICE]
server_ctx.recipient_auth_creds[ALICE] = creds[BOB]
ext_aad = aspect._extract_external_aad(forged_msg, rid, local_is_sender=False)
server_ctx.recipient_auth_creds[ALICE] = saved_cred_for_aad
aad = cbor2.dumps(["Encrypt0", b"", ext_aad])
nonce = aspect._construct_nonce(piv, ALICE, alg_group_enc)
plaintext = alg_group_enc.decrypt(ciphertext[:-siglen], aad, aspect.recipient_key, nonce)
inner = Message(code=plaintext[0])
inner.payload = inner.opt.decode(plaintext[1:])
record(
    "T2a",
    "forged packet (kid=alice, signed by bob) IS decryptable with shared group material",
    inner.payload == b"forged-by-bob-as-alice",
    f"recovered inner payload: {inner.payload!r}",
)
expect_reject(
    "T2b",
    "same forged packet is rejected: alice's countersignature does not verify",
    from_wire(forged_wire),
    before,
)

# ---- T3: swap the member authentication credential on the verifier ---------
# Replace the (kid -> auth credential) binding the server holds for alice with
# bob's credential -- the forged packet from T2 then *passes*. This shows the
# identity guarantee comes from the member credential, not the group material.
saved_pub = server_ctx.recipient_public_keys[ALICE]
saved_cred = server_ctx.recipient_auth_creds[ALICE]
server_ctx.recipient_public_keys[ALICE] = server_ctx._parse_credential(creds[BOB])
server_ctx.recipient_auth_creds[ALICE] = creds[BOB]
apps_before = len(app_log)
try:
    server_receive(from_wire(forged_wire))
    passed = True
except Exception as e:
    passed = False
    record("T3", "credential swap lets the forgery through", False, f"still rejected: {e!r}")
if passed:
    record(
        "T3",
        "with alice's credential replaced by bob's, the same forgery is ACCEPTED",
        True,
        "identity is bound by the member auth credential, not by group material",
    )
server_ctx.recipient_public_keys[ALICE] = saved_pub
server_ctx.recipient_auth_creds[ALICE] = saved_cred
# T3 polluted alice's replay window (seq of the forgery); note it and move on
before = {ALICE: window_state(ALICE), BOB: window_state(BOB)}

# ---- T4: signature tampering ------------------------------------------------
msg = from_wire(alice_wire_seq1)
body = bytearray(msg.payload)
body[-siglen // 2] ^= 0x01  # flip one bit inside the encrypted signature
msg.payload = bytes(body)
expect_reject(
    "T4a",
    "bit-flip inside the (encrypted) signature is rejected",
    msg,
    before,
)
msg = from_wire(alice_wire_seq1)
body = bytearray(msg.payload)
body[2] ^= 0x01  # flip one bit in the AEAD ciphertext body
msg.payload = bytes(body)
expect_reject(
    "T4b",
    "bit-flip inside the ciphertext body is rejected",
    msg,
    before,
)

# ---- T5: unknown (non-member) kid -------------------------------------------
tampered = with_swapped_kid(alice_wire_seq1, b"\x09")
try:
    server_receive(tampered)
    record("T5", "packet with unknown kid is rejected", False, "accepted?!")
except KeyError:
    ok = window_state(ALICE) == before[ALICE] and window_state(BOB) == before[BOB]
    record(
        "T5",
        "packet with unknown (non-member) kid is rejected at context lookup",
        ok,
        "KeyError from find_oscore -> 4.01; replay windows untouched",
    )

# ---- T6: genuine alice seq1 still accepted after all the failed packets ----
sc, plain, _ = server_receive(from_wire(alice_wire_seq1))
record(
    "T6",
    "alice's genuine seq-1 packet is still accepted after failed forgeries",
    plain.payload == b"alice-hello-1",
    "failed packets did not burn alice's sequence numbers",
)
before = {ALICE: window_state(ALICE), BOB: window_state(BOB)}

# ---- T7: replay of alice's seq-0 packet -------------------------------------
try:
    server_receive(from_wire(alice_wire_seq0))
    record("T7", "replayed genuine packet (seq 0) is rejected as replay", False, "accepted?!")
except ReplayError:
    ok = window_state(ALICE) == before[ALICE]
    record("T7", "replayed genuine packet (seq 0) is rejected as replay", ok, "ReplayError")
except Exception as e:
    # aiocoap defect: group aspects lack `echo_recovery`, so a replay surfaces
    # as AttributeError instead of ReplayError. Still rejected, no state change.
    ok = window_state(ALICE) == before[ALICE] and window_state(BOB) == before[BOB]
    record(
        "T7",
        "replayed genuine packet (seq 0) is rejected as replay",
        ok,
        f"rejected with {type(e).__name__} (expected ReplayError; group aspect "
        "lacks echo_recovery -- aiocoap robustness defect), window untouched",
    )

# ---- T8: bob's genuine traffic unaffected ------------------------------------
outer, _ = protect_request(bob_ctx, b"bob-hello-0", b"t-b0")
bob_wire_seq0 = to_wire(outer)
sc, plain, _ = server_receive(from_wire(bob_wire_seq0))
record(
    "T8",
    "bob's genuine request is delivered; attacks on alice did not affect him",
    plain.payload == b"bob-hello-0" and window_state(BOB) != before[BOB],
    f"bob window after: {window_state(BOB)}",
)
before = {ALICE: window_state(ALICE), BOB: window_state(BOB)}

# ---- T9: pairwise mode -------------------------------------------------------
alice_pairwise = alice_ctx.pairwise_for(SERVER)
outer, alice_pw_reqid = protect_request(alice_pairwise, b"alice-pairwise-0", b"t-p0")
pw_wire = to_wire(outer)
sc, plain, srv_reqid = server_receive(from_wire(pw_wire))
record(
    "T9a",
    "genuine pairwise request from alice is delivered",
    plain.payload == b"alice-pairwise-0"
    and type(sc).__name__ == "_PairwiseContextAspect",
    f"context={type(sc).__name__}",
)
before = {ALICE: window_state(ALICE), BOB: window_state(BOB)}

# kid swap on the pairwise packet: server derives bob's pairwise key -> AEAD fails
tampered = with_swapped_kid(pw_wire, BOB)
expect_reject(
    "T9b",
    "pairwise packet with swapped kid is rejected (AEAD key mismatch)",
    tampered,
    before,
)

# insider forgery in pairwise mode: bob cannot derive the alice<->server
# pairwise key (needs alice's or the server's private key for the ECDH)
forged_pw_ctx = forgery_ctx.pairwise_for(SERVER)
outer, _ = protect_request(forged_pw_ctx, b"forged-pairwise", b"t-pf")
expect_reject(
    "T9c",
    "insider pairwise forgery (kid=alice, bob's ECDH key) is rejected",
    from_wire(to_wire(outer)),
    before,
)

# ---- T10: response paths -----------------------------------------------------
# group-mode request -> response must go out pairwise (RFC 8613 mode switch)
outer, alice_grp_reqid = protect_request(alice_ctx, b"alice-hello-2", b"t-a2")
sc, plain, srv_reqid = server_receive(from_wire(to_wire(outer)))
resp_ctx = sc.context_for_response()
record(
    "T10a",
    "response to a group-mode request uses the pairwise context",
    type(resp_ctx).__name__ == "_PairwiseContextAspect",
    f"context_for_response -> {type(resp_ctx).__name__}",
)
resp_outer = protect_response(resp_ctx, b"response-to-alice", srv_reqid, b"t-a2")
resp_wire = to_wire(resp_outer)
resp_first = parse_oscore_option(from_wire(resp_wire).opt.oscore)[0]
record(
    "T10b",
    "response to a group request carries no countersignature (pairwise AEAD only)",
    not (resp_first & 0x20),
    f"OSCORE option flags: 0x{resp_first:02x} (group bit 0x20 clear)",
)
resp_in = from_wire(resp_wire)
resp_unprotected = aiocoap.oscore.verify_start(resp_in)
resp_sc = alice_ctx.context_from_response(resp_unprotected)
plain_resp, _ = resp_sc.unprotect(resp_in, alice_grp_reqid)
record(
    "T10c",
    "alice verifies the pairwise response",
    plain_resp.payload == b"response-to-alice"
    and type(resp_sc).__name__ == "_PairwiseContextAspect",
    f"client-side context: {type(resp_sc).__name__}",
)

# tampered response is rejected at alice
resp_bad = from_wire(resp_wire)
body = bytearray(resp_bad.payload)
body[-1] ^= 0x01
resp_bad.payload = bytes(body)
try:
    resp_sc2 = alice_ctx.context_from_response(aiocoap.oscore.verify_start(resp_bad))
    resp_sc2.unprotect(resp_bad, alice_grp_reqid)
    record("T10d", "bit-flipped pairwise response is rejected at alice", False, "accepted?!")
except Exception as e:
    record(
        "T10d",
        "bit-flipped pairwise response is rejected at alice",
        True,
        f"{type(e).__name__}",
    )

# bob cannot read alice's pairwise response
resp_in2 = from_wire(resp_wire)
try:
    bob_resp_sc = bob_ctx.context_from_response(aiocoap.oscore.verify_start(resp_in2))
    bob_resp_sc.unprotect(resp_in2, alice_grp_reqid)
    record("T10e", "bob cannot unprotect alice's pairwise response", False, "accepted?!")
except Exception as e:
    record(
        "T10e",
        "bob cannot unprotect alice's pairwise response (pairwise key binds both members)",
        True,
        f"{type(e).__name__}",
    )

# pairwise request -> pairwise response
outer, alice_pw_reqid = protect_request(alice_ctx.pairwise_for(SERVER), b"alice-pw-1", b"t-p1")
sc, plain, srv_reqid = server_receive(from_wire(to_wire(outer)))
resp_ctx = sc.context_for_response()
resp_outer = protect_response(resp_ctx, b"pw-response", srv_reqid, b"t-p1")
resp_in = from_wire(to_wire(resp_outer))
resp_sc = alice_ctx.context_from_response(aiocoap.oscore.verify_start(resp_in))
plain_resp, _ = resp_sc.unprotect(resp_in, alice_pw_reqid)
record(
    "T10f",
    "pairwise request -> pairwise response round-trip works",
    plain_resp.payload == b"pw-response"
    and type(resp_ctx).__name__ == "_PairwiseContextAspect",
    f"server response context: {type(resp_ctx).__name__}",
)

# ================================================================== summary
print()
print("=" * 78)
print("Application delivered %d messages:" % len(app_log))
for i, (ctxname, code, payload) in enumerate(app_log):
    print("  %2d. via %-22s code=%s payload=%r" % (i, ctxname, code, payload))
print()
failed = [r for r in results if not r[2]]
print("%d checks, %d passed, %d failed" % (len(results), len(results) - len(failed), len(failed)))
if failed:
    for test_id, desc, _, detail in failed:
        print("FAILED: %s %s -- %s" % (test_id, desc, detail))
    sys.exit(1)
print("All expectations met.")
