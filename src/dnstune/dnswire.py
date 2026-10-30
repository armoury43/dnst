"""A tiny, strict DNS wire-format codec (RFC 1035 + EDNS0 from RFC 6891).

Only what dnstune needs: build an ``A`` query and parse the response. Every
byte read from the network is bounds-checked, compression pointers may only
point backwards (so loops are impossible), and any violation raises
``DNSFormatError``. Nothing in here ever raises ``IndexError``/``struct.error``.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass

from .errors import DNSFormatError

QTYPE_A = 1
QTYPE_CNAME = 5
QTYPE_AAAA = 28
QTYPE_OPT = 41
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

MAX_LABEL = 63
MAX_WIRE_NAME = 255
MAX_ADDRESSES = 64
MAX_POINTER_JUMPS = 16
EDNS_PAYLOAD = 1232  # the "DNS flag day 2020" safe UDP size

_HEADER = struct.Struct("!HHHHHH")
_RR_FIXED = struct.Struct("!HHIH")
_LABEL_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")


def normalize_name(name: str) -> str:
    """Lower-case and strip one trailing dot. Does not validate."""
    return name[:-1].lower() if name.endswith(".") else name.lower()


def validate_hostname(name: str) -> str:
    """Return the normalized hostname or raise ``ValueError``.

    Only plain ASCII LDH names (plus underscore) are accepted. That is all the
    canary lists need, and it keeps the encoder trivially safe.
    """
    norm = normalize_name(name)
    if not norm or len(norm) > 253:
        raise ValueError(f"invalid hostname length: {name!r}")
    for label in norm.split("."):
        if not _LABEL_RE.fullmatch(label):
            raise ValueError(f"invalid hostname label {label!r} in {name!r}")
    return norm


def encode_name(name: str) -> bytes:
    """Encode a hostname as uncompressed wire-format labels."""
    norm = validate_hostname(name)
    out = bytearray()
    for label in norm.split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > MAX_WIRE_NAME:
        raise ValueError(f"hostname too long: {name!r}")
    return bytes(out)


def build_query(name: str, qtype: int, txid: int) -> bytes:
    """Build a recursive query with an EDNS0 OPT record."""
    if not 0 <= txid <= 0xFFFF:
        raise ValueError("txid out of range")
    header = _HEADER.pack(txid, 0x0100, 1, 0, 0, 1)  # RD=1, QD=1, AR=1 (OPT)
    question = encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
    opt = b"\x00" + _RR_FIXED.pack(QTYPE_OPT, EDNS_PAYLOAD, 0, 0)
    return header + question + opt


@dataclass(frozen=True, slots=True)
class Response:
    """The parts of a DNS response that dnstune cares about."""

    rcode: int
    truncated: bool
    addresses: tuple[str, ...]


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly-compressed name. Returns (name, offset_after_name)."""
    labels: list[str] = []
    pos = offset
    end: int | None = None
    jumps = 0
    total = 0
    size = len(data)
    while True:
        if pos >= size:
            raise DNSFormatError("name runs past end of packet")
        length = data[pos]
        if length == 0:
            if end is None:
                end = pos + 1
            break
        top = length & 0xC0
        if top == 0xC0:
            if pos + 1 >= size:
                raise DNSFormatError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise DNSFormatError("too many compression jumps")
            if target >= pos:
                raise DNSFormatError("compression pointer does not point backwards")
            pos = target
            continue
        if top != 0:
            raise DNSFormatError("reserved label type")
        pos += 1
        if pos + length > size:
            raise DNSFormatError("label runs past end of packet")
        total += length + 1
        if total > MAX_WIRE_NAME:
            raise DNSFormatError("name too long")
        labels.append(data[pos : pos + length].decode("latin-1"))
        pos += length
    return ".".join(labels).lower(), end


def parse_response(data: bytes, *, txid: int, name: str, qtype: int) -> Response:
    """Validate a response to our query and extract A/AAAA answers.

    The transaction id, opcode, question section and CNAME chain are all
    checked. Authority and additional sections are ignored on purpose.
    """
    if len(data) < _HEADER.size:
        raise DNSFormatError("packet shorter than DNS header")
    rid, flags, qdcount, ancount, _nscount, _arcount = _HEADER.unpack_from(data, 0)
    if rid != txid:
        raise DNSFormatError("transaction id mismatch")
    if not flags & 0x8000:
        raise DNSFormatError("not a response")
    if (flags >> 11) & 0xF != 0:
        raise DNSFormatError("unexpected opcode")
    if qdcount != 1:
        raise DNSFormatError("unexpected question count")

    offset = _HEADER.size
    qname, offset = _read_name(data, offset)
    if offset + 4 > len(data):
        raise DNSFormatError("truncated question")
    got_type, got_class = struct.unpack_from("!HH", data, offset)
    offset += 4
    if qname != normalize_name(name) or got_type != qtype or got_class != CLASS_IN:
        raise DNSFormatError("question does not match query")

    wanted = {qname}
    addresses: list[str] = []
    for _ in range(ancount):
        owner, offset = _read_name(data, offset)
        if offset + _RR_FIXED.size > len(data):
            raise DNSFormatError("truncated resource record header")
        rtype, rclass, _ttl, rdlen = _RR_FIXED.unpack_from(data, offset)
        offset += _RR_FIXED.size
        if offset + rdlen > len(data):
            raise DNSFormatError("resource record data runs past end of packet")
        rdata_start = offset
        offset += rdlen
        if rclass != CLASS_IN or owner not in wanted:
            continue
        if rtype == QTYPE_CNAME:
            target, _ = _read_name(data, rdata_start)
            wanted.add(target)
        elif rtype == qtype:
            if qtype == QTYPE_A and rdlen == 4:
                addr = str(ipaddress.IPv4Address(data[rdata_start:offset]))
            elif qtype == QTYPE_AAAA and rdlen == 16:
                addr = str(ipaddress.IPv6Address(data[rdata_start:offset]))
            else:
                raise DNSFormatError("address record has wrong length")
            if len(addresses) < MAX_ADDRESSES:
                addresses.append(addr)
    return Response(
        rcode=flags & 0xF,
        truncated=bool(flags & 0x0200),
        addresses=tuple(addresses),
    )
