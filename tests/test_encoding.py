# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import copy

import aiocoap
import aiocoap.optiontypes
from aiocoap.numbers.optionnumbers import OptionNumber

import unittest


class TestMessage(unittest.TestCase):
    def test_encode(self):
        msg1 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)
        binary1 = bytes((64, 0, 0, 0))
        self.assertEqual(
            msg1.encode(), binary1, "wrong encode operation for empty CON message"
        )

        msg2 = aiocoap.Message(
            _mtype=aiocoap.ACK,
            _mid=0xBC90,
            code=aiocoap.CONTENT,
            payload=b"temp = 22.5 C",
            _token=b"q",
        )
        msg2.opt.etag = b"abcd"
        binary2 = (
            bytes((97, 69, 188, 144, 113, 68))
            + b"abcd"
            + bytes((255,))
            + b"temp = 22.5 C"
        )
        self.assertEqual(
            msg2.encode(),
            binary2,
            "wrong encode operation for ACK message with payload, and Etag option",
        )
        msg2short = binary2[0:5] + binary2[10:]  # header, token, marker, data
        msg2a = copy.deepcopy(msg2)
        del msg2a.opt.etag
        self.assertEqual(
            msg2a.encode(), msg2short, "deleting single property did not succeed"
        )
        msg2b = copy.deepcopy(msg2)
        del msg2b.opt.etags
        self.assertEqual(
            msg2b.encode(), msg2short, "deleting list property did not succeed"
        )
        msg2c = copy.deepcopy(msg2)
        msg2c.opt.etags = []
        self.assertEqual(
            msg2c.encode(), msg2short, "emptying list property did not succeed"
        )
        msg2d = copy.deepcopy(msg2)
        msg2d.opt.etag = None
        self.assertEqual(
            msg2d.encode(), msg2short, "setting single property to None did not succeed"
        )

        msg3 = aiocoap.Message()
        self.assertRaises(TypeError, msg3.encode)

        msg4 = aiocoap.Message(_mtype=aiocoap.CON, _mid=2 << 16)
        self.assertRaises(Exception, msg4.encode)

        msg5 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)
        o = aiocoap.optiontypes.OpaqueOption(1234, value=b"abcd")
        msg5.opt.add_option(o)
        binary5 = binary1 + bytes((0xE4, 0x03, 0xC5)) + b"abcd"
        self.assertEqual(
            msg5.encode(), binary5, "wrong encoding for high option numbers"
        )

        msg6 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)
        o = aiocoap.optiontypes.OpaqueOption(12345678, value=b"abcd")
        msg6.opt.add_option(o)
        self.assertRaises(ValueError, msg6.encode)

        msg7 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)

        def set_unknown_opt():
            msg7.opt.foobar = 42

        self.assertRaises(AttributeError, set_unknown_opt)

    def test_decode(self):
        rawdata1 = bytes((64, 0, 0, 0))
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).mtype,
            aiocoap.CON,
            "wrong message type for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).mid,
            0,
            "wrong message ID for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).code,
            aiocoap.EMPTY,
            "wrong message code for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).token,
            b"",
            "wrong message token for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).payload,
            b"",
            "wrong message payload for decode operation",
        )
        rawdata2 = (
            bytes((97, 69, 188, 144, 113, 68))
            + b"abcd"
            + bytes((255,))
            + b"temp = 22.5 C"
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).mtype,
            aiocoap.ACK,
            "wrong message type for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).mid,
            0xBC90,
            "wrong message ID for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).code,
            aiocoap.CONTENT,
            "wrong message code for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).token,
            b"q",
            "wrong message token for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).payload,
            b"temp = 22.5 C",
            "wrong message payload for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).opt.etags,
            (b"abcd",),
            "problem with etag option decoding for decode operation",
        )
        self.assertEqual(
            len(aiocoap.Message.decode(rawdata2).opt._options),
            1,
            "wrong number of options after decode operation",
        )
        rawdata3 = rawdata1 + bytes((0xF0,))
        self.assertRaises(
            aiocoap.error.UnparsableMessage, aiocoap.Message.decode, rawdata3
        )  # message with option delta reserved for payload marker
        rawdata4 = rawdata1 + bytes((0xE0,))
        self.assertRaises(
            aiocoap.error.UnparsableMessage, aiocoap.Message.decode, rawdata4
        )  # message with extended option delta that is not actually there
        rawdata5 = rawdata1 + bytes((0x04,))
        self.assertRaises(
            aiocoap.error.UnparsableMessage, aiocoap.Message.decode, rawdata5
        )  # message with option that is not actually there


class TestReadExtendedFieldValue(unittest.TestCase):
    def test_read_extended_field_value(self):
        arguments = (
            (0, b"aaaa"),
            (0, b""),
            (1, b"aaaa"),
            (12, b"aaaa"),
            (13, b"aaaa"),
            (13, b"a"),
            (14, b"aaaa"),
            (14, b"aa"),
        )
        results = (
            (0, b"aaaa"),
            (0, b""),
            (1, b"aaaa"),
            (12, b"aaaa"),
            (110, b"aaa"),
            (110, b""),
            (25198, b"aa"),
            (25198, b""),
        )

        for argument, result in zip(arguments, results):
            self.assertEqual(
                aiocoap.options._read_extended_field_value(argument[0], argument[1]),
                result,
                "wrong result for value : "
                + repr(argument[0])
                + " , rawdata : "
                + repr(argument[1]),
            )


class TestExtendedToken(unittest.TestCase):
    critical_lengths = (8, 13, 268, 269, 65804, 65805)

    def test_udp_boundaries(self):
        for length in self.critical_lengths:
            with self.subTest(length=length):
                token = bytes(range(256)) * (length // 256 + 1)
                token = token[:length]
                msg = aiocoap.Message(
                    _mtype=aiocoap.CON,
                    _mid=0x1234,
                    code=aiocoap.GET,
                    _token=token,
                )
                msg.opt.add_option(
                    aiocoap.optiontypes.OpaqueOption(OptionNumber.ETAG, b"ab")
                )
                msg.payload = b"data"

                encoded = msg.encode()
                decoded = aiocoap.Message.decode(encoded, max_token_length=65805)

                self.assertEqual(decoded.token, token)
                self.assertEqual(decoded.opt.etag, b"ab")
                self.assertEqual(decoded.payload, b"data")

    def test_udp_truncated_and_limited(self):
        token = b"t" * 13
        encoded = aiocoap.Message(
            _mtype=aiocoap.CON,
            _mid=0,
            code=aiocoap.GET,
            _token=token,
            payload=b"x",
        ).encode()
        truncated_token = encoded[:-3]

        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            aiocoap.Message.decode,
            encoded[:4],
        )
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            aiocoap.Message.decode,
            encoded[:5],
        )
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            aiocoap.Message.decode,
            truncated_token,
        )
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            aiocoap.Message.decode,
            encoded,
            max_token_length=12,
        )

    def test_tcp_boundaries_and_incremental_decoding(self):
        from aiocoap.transports import tcp

        token_boundaries = (8, 13, 268, 269, 65804, 65805)
        suffix_lengths = (12, 13, 269, 270, 65804, 65805)

        for token_length in token_boundaries:
            for suffix_length in suffix_lengths:
                if token_length in (65804, 65805) and suffix_length > 13:
                    continue
                with self.subTest(
                    token_length=token_length, suffix_length=suffix_length
                ):
                    msg = aiocoap.Message(
                        code=aiocoap.GET,
                        _token=b"t" * token_length,
                    )
                    msg.payload = b"p" * (suffix_length - 1)

                    encoded = tcp._serialize(msg)
                    token_offset, announced_token_length, announced_suffix = (
                        tcp._extract_message_size(encoded, 65805)
                    )
                    self.assertEqual(announced_token_length, token_length)
                    self.assertEqual(
                        len(encoded),
                        token_offset + token_length + announced_suffix,
                    )
                    self.assertEqual(announced_suffix, suffix_length)

                    decoded = tcp._decode_message(encoded, 65805)
                    self.assertEqual(decoded.token, b"t" * token_length)
                    self.assertEqual(decoded.payload, b"p" * (suffix_length - 1))

                    length_extended = {
                        13: 1,
                        14: 2,
                        15: 4,
                    }.get(encoded[0] >> 4, 0)
                    tkl_extended = {
                        13: 1,
                        14: 2,
                        15: 4,
                    }.get(encoded[0] & 0x0F, 0)
                    self.assertIsNone(tcp._extract_message_size(encoded[:0]))
                    if length_extended:
                        self.assertIsNone(
                            tcp._extract_message_size(encoded[:length_extended])
                        )
                    header = tcp._extract_message_size(
                        encoded[: length_extended + 2 + tkl_extended], 65805
                    )
                    self.assertEqual(sum(header), len(encoded))
                    accumulated = b""
                    for byte in encoded:
                        accumulated += bytes((byte,))
                        incremental_header = tcp._extract_message_size(
                            accumulated, 65805
                        )
                        if incremental_header is not None:
                            self.assertIsNotNone(incremental_header)
                            self.assertEqual(sum(incremental_header), len(encoded))
                    received = encoded
                    incremental = tcp._decode_message(received, 65805)
                    self.assertEqual(incremental.token, decoded.token)
                    self.assertEqual(incremental.payload, decoded.payload)

    def test_tcp_truncated_and_limited(self):
        from aiocoap.transports import tcp

        self.assertIsNone(tcp._extract_message_size(b"\x0d"))
        self.assertEqual(tcp._extract_message_size(bytes((13, 0, 0))), (3, 13, 0))
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            tcp._extract_message_size,
            bytes((11, 0)),
        )
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            tcp._extract_message_size,
            b"\x09",
        )
        self.assertEqual(tcp._extract_message_size(bytes((13, 0, 13))), (3, 26, 0))
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            tcp._decode_message,
            bytes((13, 0, 13)),
        )
        oversized = b"\x0d\x00\x0d\x0d" + b"t" * 13
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            tcp._extract_message_size,
            oversized,
            12,
        )
        self.assertRaises(
            aiocoap.error.UnparsableMessage,
            tcp._extract_message_size,
            bytes((0x0F, 0, 0xFF, 0xFF, 0xFF, 0xFF)),
        )

    def test_tcp_options_and_ws_boundaries(self):
        from aiocoap.transports import ws

        for token_length in (8, 13):
            from aiocoap.transports import tcp

            with self.subTest(token_length=token_length):
                msg = aiocoap.Message(
                    code=aiocoap.GET,
                    _token=b"t" * token_length,
                )
                msg.opt.add_option(
                    aiocoap.optiontypes.OpaqueOption(OptionNumber.ETAG, b"ab")
                )
                msg.payload = b"payload"
                encoded = tcp._serialize(msg)
                suffix = msg.opt.encode() + bytes((0xFF,)) + msg.payload
                token_offset, decoded_token_length, announced_suffix = (
                    tcp._extract_message_size(encoded, 65805)
                )
                self.assertEqual(decoded_token_length, token_length)
                self.assertEqual(announced_suffix, len(suffix))
                self.assertEqual(encoded[token_offset + token_length :], suffix)

        for length in self.critical_lengths:
            with self.subTest(length=length):
                msg = aiocoap.Message(
                    code=aiocoap.GET,
                    _token=b"t" * length,
                    payload=b"x",
                )
                encoded = ws._serialize(msg)
                decoded = ws._decode_message(encoded, max_token_length=65805)
                self.assertEqual(decoded.token, msg.token)
                self.assertEqual(decoded.payload, b"x")

    def test_reliable_capability(self):
        from aiocoap.transports.rfc8323common import RFC8323Remote

        class DummyReliableRemote(RFC8323Remote):
            hostinfo = "example"
            hostinfo_local = "local"
            uri_base = "coap+tcp://example"
            uri_base_local = "coap+tcp://local"
            is_multicast = False
            is_multicast_locally = False
            scheme = "coap+tcp"

            def _send_message(self, msg):
                pass

        remote = DummyReliableRemote()
        request = aiocoap.Message(code=aiocoap.GET, _token=b"t" * 13)

        self.assertRaises(ValueError, remote._check_outgoing_token, request)
        csm = aiocoap.Message(code=aiocoap.CSM)
        csm.opt.add_option(aiocoap.optiontypes.OpaqueOption(6, bytes((12,))))
        remote._process_signaling(csm)

        self.assertEqual(remote.max_supported_token_length, 12)
        remote._check_outgoing_token(
            aiocoap.Message(code=aiocoap.GET, _token=b"t" * 12)
        )
        self.assertRaises(ValueError, remote._check_outgoing_token, request)

    def test_udp_capability(self):
        from aiocoap.transports.udp6 import UDP6EndpointAddress

        sockaddr = ("::1", 1234, 0, 0)

        class DummyInterface:
            pass

        interface = DummyInterface()
        request = aiocoap.Message(code=aiocoap.GET, _token=b"t" * 13)

        default_remote = UDP6EndpointAddress(sockaddr, interface)
        self.assertEqual(default_remote.max_supported_token_length, 8)
        self.assertRaises(ValueError, default_remote.check_outgoing_token, request)

        allowed_remote = UDP6EndpointAddress(
            sockaddr,
            interface,
            allow_extended_tokens=True,
            max_token_length=13,
        )
        allowed_remote.check_outgoing_token(request)

        learned_remote = UDP6EndpointAddress(sockaddr, interface)
        learned_remote.set_extended_token_supported(True, max_token_length=13)
        learned_remote.check_outgoing_token(request)


class TestUintOption(unittest.TestCase):
    def test_encode(self):
        arguments = (0, 1, 2, 40, 50, 255, 256, 1000)
        results = (
            b"",
            bytes((1,)),
            bytes((2,)),
            bytes((40,)),
            bytes((50,)),
            bytes((255,)),
            bytes((1, 0)),
            bytes((3, 232)),
        )
        for argument, result in zip(arguments, results):
            self.assertEqual(
                aiocoap.optiontypes.UintOption(0, argument).encode(),
                result,
                "wrong encode operation for option value : " + str(argument),
            )

    def test_decode(self):
        arguments = (
            b"",
            bytes((1,)),
            bytes((2,)),
            bytes((40,)),
            bytes((50,)),
            bytes((255,)),
            bytes((1, 0)),
            bytes((3, 232)),
        )
        results = (0, 1, 2, 40, 50, 255, 256, 1000)
        for argument, result in zip(arguments, results):
            o = aiocoap.optiontypes.UintOption(0)
            o.decode(argument)
            self.assertEqual(
                o.value, result, "wrong decode operation for rawdata : " + str(argument)
            )


class TestOptions(unittest.TestCase):
    def test_set_uri_path(self):
        opt1 = aiocoap.options.Options()
        opt1.uri_path = ["core"]
        self.assertEqual(
            len(opt1.get_option(aiocoap.OptionNumber.URI_PATH)),
            1,
            "wrong uri_path setter operation for single string argument",
        )
        self.assertEqual(
            opt1.get_option(aiocoap.OptionNumber.URI_PATH)[0].value,
            "core",
            "wrong uri_path setter operation for single string argument",
        )
        opt2 = aiocoap.options.Options()
        opt2.uri_path = ("core", ".well-known")
        self.assertEqual(
            len(opt2.get_option(aiocoap.OptionNumber.URI_PATH)),
            2,
            "wrong uri_path setter operation for 2-element tuple argument",
        )
        self.assertEqual(
            opt2.get_option(aiocoap.OptionNumber.URI_PATH)[0].value,
            "core",
            "wrong uri_path setter operation for 2-element tuple argument",
        )
        self.assertEqual(
            opt2.get_option(aiocoap.OptionNumber.URI_PATH)[1].value,
            ".well-known",
            "wrong uri_path setter operation for 2-element tuple argument",
        )
        opt3 = aiocoap.options.Options()
        self.assertRaises(TypeError, setattr, opt3, "uri_path", 42)


class TestOptiontypes(unittest.TestCase):
    def test_optiontypes(self):
        # from rfc725 table 4
        on = aiocoap.numbers.OptionNumber
        options = {
            on.IF_MATCH: "C",
            on.URI_HOST: "CU",
            on.ETAG: "",
            on.MAX_AGE: "U",
            on.SIZE1: "N",
        }

        for o, expected in options.items():
            self.assertEqual(
                "C" in expected, o.is_critical(), "Unexpected criticalness of %r" % o
            )
            self.assertEqual(
                "C" not in expected,
                o.is_elective(),
                "Unexpected electiveness of %r" % o,
            )
            self.assertEqual(
                "U" in expected, o.is_unsafe(), "Unexpected unsafeness of %r" % o
            )
            self.assertEqual(
                "U" not in expected,
                o.is_safetoforward(),
                "Unexpected safetoforwardness of %r" % o,
            )
            if o.is_safetoforward():
                self.assertEqual(
                    "N" in expected,
                    o.is_nocachekey(),
                    "Unexpected nocachekeyness of %r" % o,
                )
                self.assertEqual(
                    "N" not in expected,
                    o.is_cachekey(),
                    "Unexpected cachekeyness of %r" % o,
                )
            else:
                self.assertRaises(ValueError, o.is_nocachekey)
                self.assertRaises(ValueError, o.is_cachekey)


class TestMessageOptionConstruction(unittest.TestCase):
    def test_uri_construction(self):
        message = aiocoap.Message(uri="coap://some-host:1234/some/path/")
        self.assertEqual(message.opt.uri_host, "some-host")
        self.assertEqual(message.opt.uri_port, None)
        self.assertEqual(message.opt.uri_path, ("some", "path", ""))

    def test_opt_roundtripping(self):
        message = aiocoap.Message()
        message.opt.content_format = 40
        message.opt.etag = b"1234"
        message.opt.uri_path = ()
        self.assertEqual(message.opt.content_format, 40)
        self.assertEqual(message.opt.etag, b"1234")
        self.assertEqual(message.opt.uri_path, ())

    def test_opt_construction(self):
        message = aiocoap.Message(content_format=40, observe=b"1234", uri_path=())
        self.assertEqual(message.opt.content_format, 40)
        self.assertEqual(message.opt.observe, b"1234")
        self.assertEqual(message.opt.uri_path, ())

    def test_copy(self):
        message = aiocoap.Message()
        original_state = repr(message)
        new_one = message.copy(
            payload=b"x",
            mid=42,
            code=0,
            mtype=3,
            token=b"xyz",
            observe=0,
            content_format=1234,
        )
        self.assertEqual(original_state, repr(message), "Message.copy mutated original")
        self.assertEqual(new_one.payload, b"x")
        self.assertEqual(new_one.mid, 42)
        self.assertEqual(new_one.token, b"xyz")
        self.assertEqual(str(new_one.code), "EMPTY")
        # "Type.RST" is also ok if the enum decides to have a different str,
        # but it should be of mtype class and not just a number. Beware that
        # other tests also look for the string versions (eg. "ACK EMPTY")
        self.assertEqual(str(new_one.mtype), "RST")
        self.assertEqual(new_one.opt.observe, 0)
        self.assertEqual(new_one.opt.content_format, 1234)

        new_two = new_one.copy(uri="coap://some-host/some/path")
        self.assertEqual(new_two.opt.uri_path, ("some", "path"))
