"""Shared test helpers: an independent DNS response builder and fake servers."""

from __future__ import annotations

import socket
import struct
import subprocess
import threading
from collections.abc import Callable, Sequence


def question_end(query: bytes) -> int:
    """Offset just after the question section of an uncompressed query."""
    pos = 12
    while query[pos] != 0:
        pos += 1 + query[pos]
    return pos + 1 + 4


def build_response(
    query: bytes,
    *,
    rcode: int = 0,
    addrs: Sequence[str] = (),
    tc: bool = False,
    txid: int | None = None,
) -> bytes:
    """Craft a response with struct only (deliberately independent of dnswire)."""
    qid = struct.unpack_from("!H", query, 0)[0] if txid is None else txid
    question = query[12 : question_end(query)]
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    header = struct.pack("!HHHHHH", qid, flags, 1, len(addrs), 0, 0)
    answers = b""
    for addr in addrs:
        rdata = socket.inet_aton(addr)
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + rdata
    return header + question + answers


class FakeDnsServer:
    """A UDP server on localhost whose behaviour is a plain function."""

    def __init__(self, handler: Callable[[bytes], Sequence[bytes]]) -> None:
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.05)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self._sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            for reply in self._handler(data):
                self._sock.sendto(reply, peer)

    def __enter__(self) -> FakeDnsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


def normal_handler(query: bytes) -> list[bytes]:
    """Answers .invalid with NXDOMAIN and everything else with a public IP."""
    if b"\x07invalid\x00" in query:
        return [build_response(query, rcode=3)]
    return [build_response(query, addrs=["93.184.216.34"])]


def closed_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.close()
    return port


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeResolvedRunner:
    """Simulates just enough of ``resolvectl`` to test apply/revert flows."""

    def __init__(self, dns: dict[str, list[str]] | None = None) -> None:
        self.dns: dict[str, list[str]] = dns if dns is not None else {"eth0": ["192.168.1.1"]}
        self.calls: list[list[str]] = []
        self.query_results: list[bool] = []  # consumed in order, default True
        self.fail_set_times = 0
        self.fail_all_sets = False
        self.ignore_set = False  # accept the command but do not change state

    def __call__(self, argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        args = list(argv[1:])
        self.calls.append(args)
        cmd = args[0]
        if cmd == "status":
            return completed(0, "Global\n")
        if cmd == "flush-caches":
            return completed(0)
        if cmd == "dns" and len(args) == 2:
            servers = self.dns.get(args[1], [])
            return completed(0, f"Link 2 ({args[1]}): {' '.join(servers)}\n")
        if cmd == "dns":
            if self.fail_all_sets or self.fail_set_times > 0:
                self.fail_set_times = max(0, self.fail_set_times - 1)
                return completed(1, "", "Access denied")
            if not self.ignore_set:
                self.dns[args[1]] = list(args[2:])
            return completed(0)
        if cmd == "revert":
            self.dns[args[1]] = []
            return completed(0)
        if cmd == "query":
            ok = self.query_results.pop(0) if self.query_results else True
            return completed(0, "example.com: 93.184.216.34\n") if ok else completed(1, "", "failed")
        return completed(1, "", f"unexpected command {cmd}")
