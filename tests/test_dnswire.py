from __future__ import annotations

import random
import struct
import unittest

from dnstune import dnswire
from dnstune.errors import DNSFormatError

from .helpers import build_response

TXID = 0x1234


def query_for(name: str = "example.com") -> bytes:
    return dnswire.build_query(name, dnswire.QTYPE_A, TXID)


def parse(data: bytes, name: str = "example.com") -> dnswire.Response:
    return dnswire.parse_response(data, txid=TXID, name=name, qtype=dnswire.QTYPE_A)


class HostnameTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(dnswire.validate_hostname("Example.COM."), "example.com")
        self.assertEqual(dnswire.validate_hostname("a-b_c.d1.org"), "a-b_c.d1.org")

    def test_invalid(self) -> None:
        for bad in ["", ".", "a..b", "example.com\n", "exa\nmple.com", "-a.com", "a-.com", "a b.com", "a" * 64 + ".com", "é.com", "a/b.com"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                dnswire.validate_hostname(bad)

    def test_too_long_total(self) -> None:
        name = ".".join(["a" * 60] * 5)
        with self.assertRaises(ValueError):
            dnswire.validate_hostname(name)


class BuildQueryTests(unittest.TestCase):
    def test_layout(self) -> None:
        q = query_for("a.example.com")
        txid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", q, 0)
        self.assertEqual((txid, flags, qd, an, ns, ar), (TXID, 0x0100, 1, 0, 0, 1))
        self.assertEqual(q[12:27], b"\x01a\x07example\x03com\x00")
        self.assertEqual(struct.unpack_from("!HH", q, 27), (1, 1))
        self.assertEqual(q[31], 0)  # OPT owner is root
        self.assertEqual(struct.unpack_from("!H", q, 32)[0], dnswire.QTYPE_OPT)

    def test_bad_txid(self) -> None:
        with self.assertRaises(ValueError):
            dnswire.build_query("example.com", 1, 70000)


class ParseResponseTests(unittest.TestCase):
    def test_a_records(self) -> None:
        resp = parse(build_response(query_for(), addrs=["93.184.216.34", "1.2.3.4"], txid=TXID))
        self.assertEqual(resp.rcode, 0)
        self.assertFalse(resp.truncated)
        self.assertEqual(resp.addresses, ("93.184.216.34", "1.2.3.4"))

    def test_nxdomain_and_truncated_flags(self) -> None:
        resp = parse(build_response(query_for(), rcode=3, tc=True, txid=TXID))
        self.assertEqual((resp.rcode, resp.truncated, resp.addresses), (3, True, ()))

    def test_case_insensitive_question(self) -> None:
        pkt = build_response(query_for("example.com"), addrs=["1.2.3.4"], txid=TXID)
        pkt = pkt.replace(b"\x07example", b"\x07EXAMPLE")
        self.assertEqual(parse(pkt).addresses, ("1.2.3.4",))

    def test_cname_chain_followed(self) -> None:
        q = query_for("www.example.com")
        head = struct.pack("!HHHHHH", TXID, 0x8180, 1, 2, 0, 0)
        question = q[12 : 12 + 17 + 4]
        cname_target = b"\x03cdn\x07example\x03com\x00"
        cname_rr = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(cname_target)) + cname_target
        target_offset = 12 + len(question) + 12 + 0  # start of rdata of CNAME
        a_rr = struct.pack("!H", 0xC000 | target_offset) + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([9, 9, 9, 9])
        resp = parse(head + question + cname_rr + a_rr, name="www.example.com")
        self.assertEqual(resp.addresses, ("9.9.9.9",))

    def test_unrelated_owner_ignored(self) -> None:
        q = query_for()
        pkt = build_response(q, addrs=["1.2.3.4"], txid=TXID)
        # Append a second record whose owner name is unrelated to the question: it must be ignored.
        extra = b"\x05other\x03com\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([6, 6, 6, 6])
        pkt = pkt[:6] + struct.pack("!H", 2) + pkt[8:] + extra
        self.assertEqual(parse(pkt).addresses, ("1.2.3.4",))

    def test_rejects_wrong_txid(self) -> None:
        with self.assertRaises(DNSFormatError):
            parse(build_response(query_for(), addrs=["1.2.3.4"], txid=TXID + 1))

    def test_rejects_query_packet(self) -> None:
        with self.assertRaises(DNSFormatError):
            parse(query_for())

    def test_rejects_wrong_question(self) -> None:
        pkt = build_response(query_for("other.com"), addrs=["1.2.3.4"], txid=TXID)
        with self.assertRaises(DNSFormatError):
            parse(pkt)

    def test_rejects_zero_questions(self) -> None:
        pkt = bytearray(build_response(query_for(), txid=TXID))
        pkt[4:6] = b"\x00\x00"
        with self.assertRaises(DNSFormatError):
            parse(bytes(pkt))

    def test_rejects_bad_address_length(self) -> None:
        q = query_for()
        pkt = build_response(q, addrs=["1.2.3.4"], txid=TXID)
        bad = pkt[:-6] + struct.pack("!H", 5) + bytes([1, 2, 3, 4, 5])
        with self.assertRaises(DNSFormatError):
            parse(bad)

    def test_rejects_self_pointer(self) -> None:
        header = struct.pack("!HHHHHH", TXID, 0x8180, 1, 0, 0, 0)
        packet = header + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
        with self.assertRaises(DNSFormatError):
            parse(packet)

    def test_rejects_forward_pointer(self) -> None:
        header = struct.pack("!HHHHHH", TXID, 0x8180, 1, 0, 0, 0)
        packet = header + b"\xc0\x20" + b"\x00" * 40
        with self.assertRaises(DNSFormatError):
            parse(packet)

    def test_rejects_reserved_label_type(self) -> None:
        header = struct.pack("!HHHHHH", TXID, 0x8180, 1, 0, 0, 0)
        with self.assertRaises(DNSFormatError):
            parse(header + b"\x40abc\x00" + struct.pack("!HH", 1, 1))

    def test_pointer_chain_is_bounded(self) -> None:
        # A long chain of strictly-backward pointers must hit the jump limit, not recurse forever.
        header = struct.pack("!HHHHHH", TXID, 0x8180, 1, 0, 0, 0)
        body = b"\x00"
        offsets = [12]
        for _ in range(40):
            offsets.append(12 + len(body))
            body += struct.pack("!H", 0xC000 | offsets[-2])
        packet = header + body
        with self.assertRaises(DNSFormatError):
            dnswire._read_name(packet, offsets[-1])

    def test_every_truncation_is_clean(self) -> None:
        pkt = build_response(query_for(), addrs=["1.2.3.4", "5.6.7.8"], txid=TXID)
        for cut in range(len(pkt)):
            with self.subTest(cut=cut):
                try:
                    parse(pkt[:cut])
                except DNSFormatError:
                    pass

    def test_random_mutations_never_crash(self) -> None:
        rng = random.Random(20260921)
        base = build_response(query_for(), addrs=["1.2.3.4", "5.6.7.8"], txid=TXID)
        for _ in range(20000):
            data = bytearray(base)
            for _ in range(rng.randint(1, 6)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            if rng.random() < 0.2:
                data = data[: rng.randrange(len(data))]
            try:
                parse(bytes(data))
            except DNSFormatError:
                pass

    def test_random_garbage_never_crashes(self) -> None:
        rng = random.Random(7)
        for _ in range(5000):
            blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 80)))
            try:
                parse(blob)
            except DNSFormatError:
                pass


if __name__ == "__main__":
    unittest.main()
