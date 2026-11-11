# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests for the aiocoap.oscore module based on the test vectors."""

import unittest

import aiocoap
import aiocoap.defaults

oscore_modules = aiocoap.defaults.oscore_missing_modules()

if not oscore_modules:
    import aiocoap.oscore

    # shortcut definition, as this will be used all over the place with copy-pasted
    # values from the specification
    h = bytes.fromhex

    C1_KEY = h("0102030405060708090a0b0c0d0e0f10")
    C1_SALT = h("9e7ca92223786340")

    C2_KEY = h("0102030405060708090a0b0c0d0e0f10")
    C2_SALT = None

    C3_KEY = h("0102030405060708090a0b0c0d0e0f10")
    C3_SALT = h("9e7ca92223786340")
    C3_ID_CTX = h("37cbf3210017a2d3")

    default_algorithm = aiocoap.oscore.AES_CCM_16_64_128()
    default_hashfun = aiocoap.oscore.hashfunctions["sha256"]

    import aiocoap.oscore

    class NonsavingSecurityContext(
        aiocoap.oscore.CanProtect,
        aiocoap.oscore.CanUnprotect,
        aiocoap.oscore.SecurityContextUtils,
    ):
        def post_seqnoincrease(self):
            # obviously, don't use this anywhere else, especially not with secret
            # keys
            pass


_skip_unless_oscore = unittest.skipIf(
    oscore_modules, "Modules missing for running OSCORE tests: %s" % (oscore_modules,)
)


@_skip_unless_oscore
class TestOSCOAPStatic(unittest.TestCase):
    def test_c1_1(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(
            secctx.sender_key,
            h("f0910ed7295e6ad4b54fc793154302ff"),
            "Sender key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.recipient_key,
            h("ffb14e093c94c9cac9471648b4f98710"),
            "Recipient key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.common_iv,
            h("4622d4dd6d944168eefb54987c"),
            "Common IV key derivation disagrees with test vector",
        )

        sender_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.sender_id, default_algorithm
        )
        self.assertEqual(
            sender_nonce_0,
            h("4622d4dd6d944168eefb54987c"),
            "Sender nonce disagrees with test vector",
        )
        recipient_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.recipient_id, default_algorithm
        )
        self.assertEqual(
            recipient_nonce_0,
            h("4722d4dd6d944169eefb54987c"),
            "Recipient nonce disagrees with test vector",
        )

    def test_c1_2(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x01"
        secctx.recipient_id = b""
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(
            secctx.sender_key,
            h("ffb14e093c94c9cac9471648b4f98710"),
            "Sender key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.recipient_key,
            h("f0910ed7295e6ad4b54fc793154302ff"),
            "Recipient key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.common_iv,
            h("4622d4dd6d944168eefb54987c"),
            "Common IV key derivation disagrees with test vector",
        )

        sender_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.sender_id, default_algorithm
        )
        self.assertEqual(
            sender_nonce_0,
            h("4722d4dd6d944169eefb54987c"),
            "Sender nonce disagrees with test vector",
        )
        recipient_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.recipient_id, default_algorithm
        )
        self.assertEqual(
            recipient_nonce_0,
            h("4622d4dd6d944168eefb54987c"),
            "Recipient nonce disagrees with test vector",
        )

    def test_c2_1(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x00"
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C2_SALT, C2_KEY)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(
            secctx.sender_key,
            h("321b26943253c7ffb6003b0b64d74041"),
            "Sender key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.recipient_key,
            h("e57b5635815177cd679ab4bcec9d7dda"),
            "Recipient key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.common_iv,
            h("be35ae297d2dace910c52e99f9"),
            "Common IV key derivation disagrees with test vector",
        )

        sender_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.sender_id, default_algorithm
        )
        self.assertEqual(
            sender_nonce_0,
            h("bf35ae297d2dace910c52e99f9"),
            "Sender nonce disagrees with test vector",
        )
        recipient_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.recipient_id, default_algorithm
        )
        self.assertEqual(
            recipient_nonce_0,
            h("bf35ae297d2dace810c52e99f9"),
            "Recipient nonce disagrees with test vector",
        )

    # skipping the server side for c.2.2 as it is very redundant

    def test_c3_1(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = C3_ID_CTX
        secctx.derive_keys(C3_SALT, C3_KEY)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(
            secctx.sender_key,
            h("af2a1300a5e95788b356336eeecd2b92"),
            "Sender key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.recipient_key,
            h("e39a0c7c77b43f03b4b39ab9a268699f"),
            "Recipient key derivation disagrees with test vector",
        )
        self.assertEqual(
            secctx.common_iv,
            h("2ca58fb85ff1b81c0b7181b85e"),
            "Common IV key derivation disagrees with test vector",
        )

        sender_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.sender_id, default_algorithm
        )
        self.assertEqual(
            sender_nonce_0,
            h("2ca58fb85ff1b81c0b7181b85e"),
            "Sender nonce disagrees with test vector",
        )
        recipient_nonce_0 = secctx._construct_nonce(
            b"\0", secctx.recipient_id, default_algorithm
        )
        self.assertEqual(
            recipient_nonce_0,
            h("2da58fb85ff1b81d0b7181b85e"),
            "Recipient nonce disagrees with test vector",
        )

    def test_c4(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)
        secctx.sender_sequence_number = 20

        unprotected = aiocoap.Message.decode(
            h("44015d1f00003974396c6f63616c686f737483747631")
        )
        unprotected.direction = aiocoap.message.Direction.OUTGOING
        outer_message, _ = secctx.protect(unprotected)
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(
            encoded,
            h("44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"),
            "Encoded message differs",
        )

    def test_c5(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x00"
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C2_SALT, C2_KEY)
        secctx.sender_sequence_number = 20

        unprotected = aiocoap.Message.decode(
            h("440171c30000b932396c6f63616c686f737483747631")
        )
        unprotected.direction = aiocoap.message.Direction.OUTGOING
        outer_message, _ = secctx.protect(unprotected)
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(
            encoded,
            h(
                "440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0"
            ),
            "Encoded message differs",
        )

    def test_c6(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = C3_ID_CTX
        secctx.derive_keys(C3_SALT, C3_KEY)
        secctx.sender_sequence_number = 20

        unprotected = aiocoap.Message.decode(
            h("44012f8eef9bbf7a396c6f63616c686f737483747631")
        )
        unprotected.direction = aiocoap.message.Direction.OUTGOING
        outer_message, _ = secctx.protect(unprotected, kid_context=True)
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        # FIXME: This is composed from the expected ciphertext, not the protected coap request, see https://github.com/core-wg/oscoap/issues/241
        self.assertEqual(
            encoded,
            h(
                "44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff72cd7273fd331ac45cffbe55c3"
            ),
            "Encoded message differs",
        )

    def test_c7(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x01"
        secctx.recipient_id = b""
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)

        unprotected = aiocoap.Message.decode(
            h("64455d1f00003974ff48656c6c6f20576f726c6421")
        )
        unprotected.direction = aiocoap.message.Direction.OUTGOING
        request_sender_id = secctx.recipient_id
        request_piv_short = b"\x14"
        request_nonce = secctx._construct_nonce(
            request_piv_short, request_sender_id, default_algorithm
        )
        outer_message, _ = secctx.protect(
            unprotected,
            aiocoap.oscore.RequestIdentifiers(
                request_sender_id, request_piv_short, True, aiocoap.POST
            ),
        )
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(
            encoded,
            h("64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106"),
            "Encoded message differs",
        )

    def test_c8(self):
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x01"
        secctx.recipient_id = b""
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)
        secctx.sender_sequence_number = 0

        unprotected = aiocoap.Message.decode(
            h("64455d1f00003974ff48656c6c6f20576f726c6421")
        )
        unprotected.direction = aiocoap.message.Direction.OUTGOING
        request_sender_id = secctx.recipient_id
        request_piv_short = b"\x14"
        request_nonce = secctx._construct_nonce(
            request_piv_short, request_sender_id, default_algorithm
        )
        outer_message, _ = secctx.protect(
            unprotected,
            aiocoap.oscore.RequestIdentifiers(
                request_sender_id, request_piv_short, False, aiocoap.POST
            ),
        )
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(
            encoded,
            h("64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e"),
            "Encoded message differs",
        )


@_skip_unless_oscore
class TestOSCOAAsymmetric(unittest.TestCase):
    """Test asymmetric algorithms

    As the Group OSCORE document currently has no test vectors, this is using
    values from the IETF109 hackathon.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # From https://github.com/ace-wg/Hackathon-109/blob/master/GroupKeys.md,
        # "Rikard Test 1"

        self.r1_1_d = bytes.fromhex(
            "FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E6"
        )
        self.r1_1_y = bytes.fromhex(
            "64CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB0684"
        )
        self.r1_1_x = bytes.fromhex(
            "1ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC96"
        )

        self.r1_2_d = bytes.fromhex(
            "DA2593A6E0BCC81A5941069CB76303487816A2F4E6C0F21737B56A7C90381597"
        )
        self.r1_2_y = bytes.fromhex(
            "1897A28666FE1CC4FACEF79CC7BDECDC271F2A619A00844FCD553A12DD679A4F"
        )
        self.r1_2_x = bytes.fromhex(
            "0EB313B4D314A1001244776D321F2DD88A5A31DF06A6EEAE0A79832D39408BC1"
        )

        self.r1_3_d = bytes.fromhex(
            "BF31D3F9670A7D1342259E700F48DD9983A5F9DF80D58994C667B6EBFD23270E"
        )
        self.r1_3_y = bytes.fromhex(
            "5694315AD17A4DA5E3F69CA02F83E9C3D594712137ED8AFB748A70491598F9CD"
        )
        self.r1_3_x = bytes.fromhex(
            "FAD4312A45F45A3212810905B223800F6CED4BC8D5BACBC8D33BB60C45FC98DD"
        )

        # "Rikard Test 2"
        self.r2_csalg = -8
        self.r2_csalg_params = [[1], [1, 6]]

        self.r2_1_private = bytes.fromhex(
            "397CEB5A8D21D74A9258C20C33FC45AB152B02CF479B2E3081285F77454CF347"
        )
        self.r2_1_public = bytes.fromhex(
            "CE616F28426EF24EDB51DBCEF7A23305F886F657959D4DF889DDFC0255042159"
        )

        self.r2_2_private = bytes.fromhex(
            "70559B9EECDC578D5FC2CA37F9969630029F1592AFF3306392AB15546C6A184A"
        )
        self.r2_2_public = bytes.fromhex(
            "2668BA6CA302F14E952228DA1250A890C143FDBA4DAED27246188B9E42C94B6D"
        )

        self.r2_3_private = bytes.fromhex(
            "E550CD532B881D52AD75CE7B91171063E568F2531FBDFB32EE01D1910BCF810F"
        )
        self.r2_3_public = bytes.fromhex(
            "5394E43633CDAC96F05120EA9F21307C9355A1B66B60A834B53E9BF60B1FB7DF"
        )

        # from https://github.com/ace-wg/Hackathon-109/blob/master/GroupDerivation.md

        self.r1_shared_12 = bytes.fromhex(
            "56ede6c59e919031cfc8afa3e74a7b7615c2e7a08494cf3638c78757293adc80"
        )
        self.r1_shared_13 = bytes.fromhex(
            "f568ec5f7df45db137fc79a27595eba737b62e8ee385c7309e316dd409de6953"
        )

        # Not actually used; these are already verified in tests_util_cryptography's vectors
        self.r2_shared_12 = bytes.fromhex(
            "4546babdb9482396c167af11d21953bfa49eb9f630c45de93ee4d3b9ef059576"
        )
        self.r2_shared_13 = bytes.fromhex(
            "bb11648af3dfebb35e612914a7a21fc751b001aceb0267c5536528e2b9261450"
        )

    def alg(self):
        alg_sign = aiocoap.oscore.Ed25519()
        alg_pairwise = aiocoap.oscore.Ed25519()
        self.assertEqual(alg_sign.value, self.r2_csalg)
        return (alg_sign, alg_pairwise)

    def test_publickey_derivation(self):
        alg, _ = self.alg()
        self.assertEqual(self.r2_1_public, alg.public_from_private(self.r2_1_private))
        self.assertEqual(self.r2_2_public, alg.public_from_private(self.r2_2_private))
        self.assertEqual(self.r2_3_public, alg.public_from_private(self.r2_3_private))

    def _test_keypair(self, alg_sign, alg_pairwise, private, public):
        body = b""
        aad = b""
        signature = alg_sign.sign(body, aad, private)
        alg_sign.verify(signature, body, aad, public)

        self.assertRaises(
            aiocoap.oscore.ProtectionInvalid,
            lambda: alg_sign.verify(signature, body + b"x", aad, public),
        )

    @unittest.skip
    def test_publickey_signatures(self):
        alg = self.alg()

        self._test_keypair(*alg, self.r2_1_private, self.r2_1_public)

        self._test_keypair(*alg, self.r2_2_private, self.r2_2_public)
        self._test_keypair(*alg, self.r2_3_private, self.r2_3_public)

    @unittest.skip
    def test_generation(self):
        alg = self.alg()

        for alg in aiocoap.oscore.algorithms_staticstatic.values():
            random_key = alg.generate()
            public_key = alg.public_from_private(random_key)

            self._test_keypair(*alg, random_key, public_key)

            second_random = alg.generate()
            second_public = alg.public_from_private(second_random)
            self.assertEqual(
                alg.staticstatic(random_key, second_public),
                alg.staticstatic(second_random, public_key),
            )

    def test_ecdsa_vectors(self):
        alg = aiocoap.oscore.ECDSA_SHA256_P256()

        r1_1 = alg.from_private_parts(self.r1_1_x, self.r1_1_y, self.r1_1_d)
        r1_2 = alg.from_private_parts(self.r1_2_x, self.r1_2_y, self.r1_2_d)
        r1_3 = alg.from_private_parts(self.r1_3_x, self.r1_3_y, self.r1_3_d)

        self.assertEqual(
            alg.staticstatic(r1_1, alg.public_from_private(r1_2)), self.r1_shared_12
        )
        self.assertEqual(
            alg.staticstatic(r1_3, alg.public_from_private(r1_1)), self.r1_shared_13
        )


@_skip_unless_oscore
class TestOSCORECompression(unittest.TestCase):
    def compare_uncompress(
        self, ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext
    ):
        message = aiocoap.Message(payload=ref_payload, oscore=ref_option)
        protected_serialized, protected, unprotected, ciphertext = (
            aiocoap.oscore.CanUnprotect._extract_encrypted0(message)
        )

        self.assertEqual(protected, ref_protected, "Protected dictionary mismatch")
        self.assertEqual(
            unprotected, ref_unprotected, "Unprotected dictionary mismatch"
        )
        self.assertEqual(ciphertext, ref_ciphertext, "Ciphertext mismatch")

    def compare_compress(
        self, ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext
    ):
        option, payload = aiocoap.oscore.CanProtect._compress(
            ref_protected, ref_unprotected, ref_ciphertext
        )

        self.assertEqual(option, ref_option, "Compressed option mismatch")
        self.assertEqual(payload, ref_payload, "Compressed payload mismatch")

    def compare_all(
        self, ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext
    ):
        self.compare_uncompress(
            ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext
        )
        self.compare_compress(
            ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext
        )

    def test_empty(self):
        self.compare_all(b"", b"1234", {}, {}, b"1234")

    def test_short(self):
        self.compare_all(
            b"\x01\x00", b"1234", {}, {aiocoap.oscore.COSE_PIV: b"\x00"}, b"1234"
        )

    def test_long(self):
        self.compare_all(
            b"\x05ABCDE", b"1234", {}, {aiocoap.oscore.COSE_PIV: b"ABCDE"}, b"1234"
        )

    def test_kid(self):
        self.compare_all(
            b"\x0bABC--------",
            b"1234",
            {},
            {aiocoap.oscore.COSE_PIV: b"ABC", aiocoap.oscore.COSE_KID: b"--------"},
            b"1234",
        )

    def test_idcontext(self):
        self.compare_all(
            b"\x1bABC\x03abc--------",
            b"1234",
            {},
            {
                aiocoap.oscore.COSE_PIV: b"ABC",
                aiocoap.oscore.COSE_KID: b"--------",
                aiocoap.oscore.COSE_KID_CONTEXT: b"abc",
            },
            b"1234",
        )

    def test_idcontext_nopiv(self):
        self.compare_all(
            b"\x18\x03abc--------",
            b"1234",
            {},
            {
                aiocoap.oscore.COSE_KID: b"--------",
                aiocoap.oscore.COSE_KID_CONTEXT: b"abc",
            },
            b"1234",
        )

    def test_counterisgnature(self):
        # This is only as correct as it gets with the interactions between
        # determining the countersignature (or its length) and uncompression:
        # The flag is registered, but its value is deferred to a later step
        # (that'd actually know the algorithm) and relies on the later process
        # to move data over from the plaintext
        self.compare_all(
            b"\x2bABC--",
            b"1234sigsigsig",
            {},
            {
                aiocoap.oscore.COSE_PIV: b"ABC",
                aiocoap.oscore.COSE_KID: b"--",
                aiocoap.oscore.COSE_COUNTERSIGNATURE0: aiocoap.oscore.PRESENT_BUT_NO_VALUE_YET,
            },
            b"1234sigsigsig",
        )

    def test_reserved(self):
        self.assertRaises(
            aiocoap.oscore.DecodeError,
            lambda: self.compare_uncompress(b"\x4bABC--", b"1234", None, None, None),
        )
        self.assertRaises(
            aiocoap.oscore.DecodeError,
            lambda: self.compare_uncompress(b"\x8bABC--", b"1234", None, None, None),
        )

    def test_unknown(self):
        self.assertRaises(
            RuntimeError, lambda: self.compare_compress(None, None, {"x": "y"}, {}, b"")
        )
        self.assertRaises(
            RuntimeError, lambda: self.compare_compress(None, None, {}, {"x": "y"}, b"")
        )


@_skip_unless_oscore
class TestOSCORERequestResponseBinding(unittest.TestCase):
    """Negative tests for OSCORE request-response binding (RFC 8613 Sections
    7.4 and 8.1): when two requests are in flight simultaneously over the
    same security context, their response ciphertexts must not be
    interchangeable.

    The cryptographic binding is provided exclusively through the external
    AAD inputs request_kid and request_piv (see
    ``BaseSecurityContext._extract_external_aad``; the remaining AAD inputs
    are the OSCORE version, the algorithm list and the Class I options, all
    of which are constant here). The CoAP token and the other outer options
    are transport-layer concerns and are *not* authenticated by OSCORE.

    The tests therefore distinguish authentication failures (ProtectionInvalid
    raised from AEAD tag verification) from transport-layer deduplication
    (ReplayError raised from the replay window, or token/MID matching that
    happens outside this module), and map out the AAD coverage by varying the
    requests' Partial IV, token and Uri-Path independently.
    """

    def _context_pair(self):
        """Build a client and a server security context on the RFC 8613 C.1
        key material, with replay windows initialized so that server-side
        request processing behaves like in a real deployment."""

        client = NonsavingSecurityContext()
        client.alg_aead = default_algorithm
        client.hashfun = default_hashfun
        client.sender_id = b""
        client.recipient_id = b"\x01"
        client.id_context = None
        client.derive_keys(C1_SALT, C1_KEY)

        server = NonsavingSecurityContext()
        server.alg_aead = default_algorithm
        server.hashfun = default_hashfun
        server.sender_id = b"\x01"
        server.recipient_id = b""
        server.id_context = None
        server.derive_keys(C1_SALT, C1_KEY)

        for context in (client, server):
            context.sender_sequence_number = 0
            context.echo_recovery = None
            context.recipient_replay_window = aiocoap.oscore.ReplayWindow(
                aiocoap.oscore.DEFAULT_WINDOWSIZE, lambda: None
            )
            context.recipient_replay_window.initialize_empty()

        return client, server

    @staticmethod
    def _outgoing(code, token=b"", uri_path=None, payload=b""):
        message = aiocoap.Message(code=code, payload=payload)
        message.token = token
        if uri_path is not None:
            message.opt.uri_path = tuple(uri_path.split("/"))
        message.direction = aiocoap.message.Direction.OUTGOING
        return message

    @staticmethod
    def _incoming(message):
        message.direction = aiocoap.message.Direction.INCOMING
        return message

    def _protect_request(self, client, request):
        protected, request_id = client.protect(request)
        # The token travels in the outer message; carrying it over is the
        # transport's job, the OSCORE module does not touch it.
        protected.token = request.token
        return self._incoming(protected), request_id

    def _respond(self, server, protected_request, payload, response_has_own_piv):
        inner_request, server_request_id = server.unprotect(protected_request)
        if response_has_own_piv:
            # Legal alternative to reusing the request's Partial IV: the
            # server answers with a fresh sequence number of its own.
            server_request_id.can_reuse_nonce = False
        response = self._outgoing(aiocoap.CONTENT, payload=payload)
        protected_response, _ = server.protect(response, server_request_id)
        protected_response.token = protected_request.token
        return inner_request, self._incoming(protected_response)

    def assertResponseRejected(self, context, protected_response, request_id):
        """Assert that unprotecting a response fails with an AEAD
        authentication error -- and not with a replay-window (transport
        dedup) error, which would indicate the failure is not in the
        cryptographic binding."""
        with self.assertRaises(aiocoap.oscore.ProtectionInvalid) as caught:
            context.unprotect(protected_response, request_id)
        self.assertNotIsInstance(
            caught.exception,
            aiocoap.oscore.ReplayError,
            "Failure was replay detection, not authentication",
        )

    def test_interleaved_requests_response_swap(self):
        """Two requests are in flight at the same time on one security
        context (interleaved: both are protected before any response is
        processed). Their responses -- in both legal forms, with and without
        an own Partial IV -- must not verify under the other request's
        identifiers."""
        for own_piv in (False, True):
            with self.subTest(response_has_own_piv=own_piv):
                client, server = self._context_pair()

                request1 = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="a")
                request2 = self._outgoing(aiocoap.GET, token=b"\x02", uri_path="b")

                protected1, client_rid1 = self._protect_request(client, request1)
                protected2, client_rid2 = self._protect_request(client, request2)

                # The requests differ in Partial IV, token and Uri-Path.
                self.assertNotEqual(protected1.opt.oscore, protected2.opt.oscore)

                inner1, response1 = self._respond(server, protected1, b"answer-a", own_piv)
                inner2, response2 = self._respond(server, protected2, b"answer-b", own_piv)

                self.assertEqual(inner1.opt.uri_path, ("a",))
                self.assertEqual(inner2.opt.uri_path, ("b",))

                # The response has the requested legal form.
                if own_piv:
                    self.assertNotEqual(response1.opt.oscore, b"")
                    self.assertNotEqual(response2.opt.oscore, b"")
                else:
                    self.assertEqual(response1.opt.oscore, b"")
                    self.assertEqual(response2.opt.oscore, b"")

                # Swapped: a response ciphertext must not be accepted as the
                # other request's answer. (The differing tokens would let the
                # transport tell them apart, but the property tested here is
                # purely cryptographic.)
                self.assertResponseRejected(client, response1, client_rid2)
                self.assertResponseRejected(client, response2, client_rid1)

                # The correct assignment still verifies, proving the messages
                # themselves were well-formed.
                unprotected1, _ = client.unprotect(response1, client_rid1)
                unprotected2, _ = client.unprotect(response2, client_rid2)
                self.assertEqual(unprotected1.payload, b"answer-a")
                self.assertEqual(unprotected2.payload, b"answer-b")

    def test_partial_iv_is_the_binding_input(self):
        """Requests that differ only in their Partial IV (same token, same
        path) already produce non-interchangeable responses: request_kid and
        request_piv are the AAD inputs that bind a response to its request."""
        client, server = self._context_pair()

        request1 = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="same")
        request2 = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="same")

        protected1, client_rid1 = self._protect_request(client, request1)
        protected2, client_rid2 = self._protect_request(client, request2)

        _, response1 = self._respond(server, protected1, b"one", False)
        _, response2 = self._respond(server, protected2, b"two", False)

        self.assertResponseRejected(client, response1, client_rid2)
        self.assertResponseRejected(client, response2, client_rid1)

    def test_token_is_not_cryptographically_bound(self):
        """The token is not an input to the external AAD: two requests that
        differ only in their token (with forced identical Partial IVs, which
        a real sender must never produce as sequence numbers must not be
        reused) yield cryptographically interchangeable responses.

        This documents that matching tokens must not be mistaken for
        cryptographic request-response binding; telling such requests apart
        is entirely the transport layer's task."""
        client, server = self._context_pair()

        request1 = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="same")
        request2 = self._outgoing(aiocoap.GET, token=b"\x02", uri_path="same")

        protected1, client_rid1 = self._protect_request(client, request1)
        # Deliberate sequence number reuse to isolate the token dimension;
        # only the NonsavingSecurityContext tolerates this.
        client.sender_sequence_number = 0
        protected2, client_rid2 = self._protect_request(client, request2)

        self.assertEqual(protected1.opt.oscore, protected2.opt.oscore)

        # The server side is constructed manually: unprotecting the second
        # request would (correctly) be caught by the replay window, which is
        # a different layer than the one under test here.
        server_rid1 = aiocoap.oscore.RequestIdentifiers(b"", b"\x00", True, aiocoap.POST)
        server_rid2 = aiocoap.oscore.RequestIdentifiers(b"", b"\x00", True, aiocoap.POST)

        response1 = self._outgoing(aiocoap.CONTENT, payload=b"one")
        protected_response1, _ = server.protect(response1, server_rid1)
        response2 = self._outgoing(aiocoap.CONTENT, payload=b"two")
        protected_response2, _ = server.protect(response2, server_rid2)

        # A response to either request verifies under the other request's
        # identifiers: nothing in the AAD reflects the token.
        unprotected, _ = client.unprotect(
            self._incoming(protected_response1), client_rid2
        )
        self.assertEqual(unprotected.payload, b"one")
        unprotected, _ = client.unprotect(
            self._incoming(protected_response2), client_rid1
        )
        self.assertEqual(unprotected.payload, b"two")

    def test_uri_path_is_not_an_aad_input(self):
        """Like the token, the Uri-Path is not an input to the response's
        external AAD (it is only protected inside the request ciphertext):
        with forced identical Partial IVs, responses to requests for
        different paths are cryptographically interchangeable. The binding
        relies on sequence number uniqueness, not on the request's contents."""
        client, server = self._context_pair()

        request1 = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="a")
        request2 = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="b")

        protected1, client_rid1 = self._protect_request(client, request1)
        client.sender_sequence_number = 0  # deliberate reuse, see above
        protected2, client_rid2 = self._protect_request(client, request2)

        server_rid1 = aiocoap.oscore.RequestIdentifiers(b"", b"\x00", True, aiocoap.POST)
        server_rid2 = aiocoap.oscore.RequestIdentifiers(b"", b"\x00", True, aiocoap.POST)

        response1 = self._outgoing(aiocoap.CONTENT, payload=b"answer-a")
        protected_response1, _ = server.protect(response1, server_rid1)
        response2 = self._outgoing(aiocoap.CONTENT, payload=b"answer-b")
        protected_response2, _ = server.protect(response2, server_rid2)

        unprotected, _ = client.unprotect(
            self._incoming(protected_response1), client_rid2
        )
        self.assertEqual(unprotected.payload, b"answer-a")
        unprotected, _ = client.unprotect(
            self._incoming(protected_response2), client_rid1
        )
        self.assertEqual(unprotected.payload, b"answer-b")

    def test_outer_modifications(self):
        """Modifications of the Object-Security option and the ciphertext are
        authentication failures; modifications of the token or other outer
        options are not detected by OSCORE at all and are left to the
        transport layer."""
        client, server = self._context_pair()

        request = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="a")
        protected_request, client_rid = self._protect_request(client, request)
        _, response = self._respond(server, protected_request, b"answer", True)

        unprotected, _ = client.unprotect(response, client_rid)
        self.assertEqual(unprotected.payload, b"answer")

        def tampered():
            return response.copy()

        # Flipping a bit in the Partial IV of the Object-Security option
        # changes the nonce and fails AEAD verification.
        modified = tampered()
        modified.opt.oscore = b"\x01\x01"
        self.assertResponseRejected(client, modified, client_rid)

        # Flipping a bit in the ciphertext invalidates the tag.
        modified = tampered()
        modified.payload = modified.payload[:-1] + bytes(
            [modified.payload[-1] ^ 0x01]
        )
        self.assertResponseRejected(client, modified, client_rid)

        # Changing the token is not detected: the token is not authenticated
        # by OSCORE, matching it is the transport layer's task.
        modified = tampered()
        modified.token = b"\x02"
        unprotected, _ = client.unprotect(modified, client_rid)
        self.assertEqual(unprotected.payload, b"answer")

        # Adding an unrelated outer option is not detected either; only
        # Class I options (of which there are none here) enter the AAD.
        modified = tampered()
        modified.opt.etag = b"\xff"
        unprotected, _ = client.unprotect(modified, client_rid)
        self.assertEqual(unprotected.payload, b"answer")

    def test_replayed_request_is_replay_error(self):
        """Transport-layer deduplication is a different failure from
        authentication: unprotecting the same request twice raises
        ReplayError from the replay window, while all the swapped-response
        cases above raise ProtectionInvalid that is not a ReplayError."""
        client, server = self._context_pair()

        request = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="a")
        protected_request, _ = self._protect_request(client, request)

        server.unprotect(protected_request)
        with self.assertRaises(aiocoap.oscore.ReplayError):
            server.unprotect(protected_request)

    def test_consumed_response_context(self):
        """A request identifier's reusable nonce is consumed by the first
        response protected with it; a second response protected with the same
        (already consumed) identifiers automatically carries its own Partial
        IV. Unprotecting the same consumed no-PIV response twice still
        verifies -- response deduplication is a transport-layer task and not
        something the cryptographic binding provides."""
        client, server = self._context_pair()

        request = self._outgoing(aiocoap.GET, token=b"\x01", uri_path="a")
        protected_request, client_rid = self._protect_request(client, request)
        _, server_rid = server.unprotect(protected_request)

        response1 = self._outgoing(aiocoap.CONTENT, payload=b"first")
        protected_response1, _ = server.protect(response1, server_rid)
        # The first response reuses the request's Partial IV.
        self.assertEqual(protected_response1.opt.oscore, b"")

        response2 = self._outgoing(aiocoap.CONTENT, payload=b"second")
        protected_response2, _ = server.protect(response2, server_rid)
        # The consumed context can no longer reuse the nonce and sends its
        # own Partial IV.
        self.assertNotEqual(protected_response2.opt.oscore, b"")

        unprotected, _ = client.unprotect(
            self._incoming(protected_response1), client_rid
        )
        self.assertEqual(unprotected.payload, b"first")
        unprotected, _ = client.unprotect(
            self._incoming(protected_response2), client_rid
        )
        self.assertEqual(unprotected.payload, b"second")

        # Re-unprotecting the consumed response verifies again: nothing
        # cryptographic stops a replayed response, so the transport has to
        # deduplicate (by token/MID) -- token equality with an earlier
        # exchange is not proof of a fresh cryptographic binding.
        unprotected, _ = client.unprotect(
            self._incoming(protected_response1), client_rid
        )
        self.assertEqual(unprotected.payload, b"first")

    def test_rfc8613_response_vectors(self):
        """Independent protocol vectors anchoring the tests above: the
        RFC 8613 C.7 (response reusing the request's Partial IV) and C.8
        (response with its own Partial IV) protected responses verify under
        the request identifiers of the C.4 request (Partial IV 0x14, empty
        sender ID), and are rejected under mismatched ones -- covering the
        request_piv AAD input in both legal response forms."""
        secctx = NonsavingSecurityContext()
        secctx.alg_aead = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)
        secctx.sender_sequence_number = 0
        secctx.echo_recovery = None
        secctx.recipient_replay_window = aiocoap.oscore.ReplayWindow(
            aiocoap.oscore.DEFAULT_WINDOWSIZE, lambda: None
        )
        secctx.recipient_replay_window.initialize_empty()

        request_id = aiocoap.oscore.RequestIdentifiers(b"", b"\x14", None, aiocoap.POST)

        protected_c7 = self._incoming(
            aiocoap.Message.decode(
                h("64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106")
            )
        )
        unprotected, _ = secctx.unprotect(protected_c7, request_id)
        self.assertEqual(unprotected.code, aiocoap.CONTENT)
        self.assertEqual(unprotected.payload, b"Hello World!")

        protected_c8 = self._incoming(
            aiocoap.Message.decode(
                h("64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e")
            )
        )
        unprotected, _ = secctx.unprotect(protected_c8, request_id)
        self.assertEqual(unprotected.code, aiocoap.CONTENT)
        self.assertEqual(unprotected.payload, b"Hello World!")

        # The same responses under the request identifiers of a different
        # request (Partial IV 0x15) fail authentication -- the request's
        # Partial IV enters the AAD even when the response carries its own.
        mismatched_id = aiocoap.oscore.RequestIdentifiers(
            b"", b"\x15", None, aiocoap.POST
        )
        self.assertResponseRejected(secctx, protected_c7, mismatched_id)
        self.assertResponseRejected(secctx, protected_c8, mismatched_id)


@_skip_unless_oscore
class TestAlgorithms(unittest.TestCase):
    def test_aescbc(self):
        # Test vectors generated using PyCryptodome as described at
        # https://codeigo.com/python/aes-encryption-and-decryption-in-python-64-128-256/
        # ("Implementation of AES-CBC Encryption and Decryption in Python" with
        # they key length set to 16)

        from aiocoap.oscore import A128CBC

        key = b"3\x8b\xd0\xf2\x18&\x15\nS\x14%\xec!\x16\n$"
        iv = b"7\x07\xe3TA65~\x8d%'&\x8e\x1anE"
        plain = b"This is the message to be encrypted"
        expected_ciphertext = b"\x05\xbb\xd0\xea\xc2\x97pvF-P\x9a\x9e\xa4=\x94\xac\xad\x00\xc0/\x00&\x7f\x83\xca@c\xeew\xc3\x16\x14h\xca\x023\xb6Vq\xf4\x8d\xb7\xc2S3\xfa\xae"

        aad = b""

        encrypted = A128CBC.encrypt(plain, aad, key, iv)
        self.assertEqual(encrypted, expected_ciphertext)
        decrypted = A128CBC.decrypt(encrypted, aad, key, iv)
        self.assertEqual(decrypted, plain)
