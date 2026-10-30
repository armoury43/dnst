"""The built-in probe engine: plain UDP DNS queries using only the stdlib.

Design notes
------------
* One fresh UDP socket per query, so every query gets a new random source port
  and a new random transaction id (Kaminsky-style spoofing resistance).
* Sockets are ``connect()``ed, so the kernel drops datagrams from any address
  other than the server we asked.
* Packets that fail validation are ignored until the deadline; a spoofer
  cannot make a probe finish early or crash it.
* One worker handles one server at a time and queries it sequentially, so a
  server never competes with itself for bandwidth or rate limits.
"""

from __future__ import annotations

import errno
import logging
import secrets
import socket
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor

from .dnswire import QTYPE_A, build_query, parse_response
from .errors import DNSFormatError
from .models import (
    KIND_NX,
    KIND_POPULAR,
    Observation,
    ProbePlan,
    Server,
    ServerResult,
)

log = logging.getLogger(__name__)

_RECV_BUFFER = 4096


def probe_once(server: Server, domain: str, kind: str, timeout: float) -> Observation:
    """Send one A query and return exactly what happened."""
    family = socket.AF_INET6 if ":" in server.address else socket.AF_INET
    txid = secrets.randbelow(0x10000)
    try:
        query = build_query(domain, QTYPE_A, txid)
    except ValueError:
        return Observation(kind, domain, None, None, error="invalid-name")

    sock: socket.socket | None = None
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.connect((server.address, server.port))
        start = time.perf_counter()
        deadline = start + timeout
        sock.send(query)
        last_error = "timeout"
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return Observation(kind, domain, None, None, error=last_error)
            sock.settimeout(remaining)
            try:
                data = sock.recv(_RECV_BUFFER)
            except TimeoutError:
                return Observation(kind, domain, None, None, error=last_error)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            try:
                response = parse_response(data, txid=txid, name=domain, qtype=QTYPE_A)
            except DNSFormatError as exc:
                log.debug("ignoring bad packet from %s: %s", server.address, exc)
                last_error = "malformed"
                continue
            error = "truncated" if response.truncated and not response.addresses else None
            return Observation(
                kind,
                domain,
                response.rcode,
                round(elapsed_ms, 2),
                response.addresses,
                error,
            )
    except ConnectionRefusedError:
        return Observation(kind, domain, None, None, error="refused")
    except OSError as exc:
        name = errno.errorcode.get(exc.errno or 0, "error")
        return Observation(kind, domain, None, None, error=f"network:{name}")
    except Exception as exc:  # last line of defence: one bad probe must not kill a run
        log.debug("unexpected probe failure", exc_info=True)
        return Observation(kind, domain, None, None, error=f"internal:{type(exc).__name__}")
    finally:
        if sock is not None:
            sock.close()


def probe_server(server: Server, plan: ProbePlan) -> ServerResult:
    """Run the full plan against one server, sequentially."""
    # A random label under the reserved ``.invalid`` TLD (RFC 6761) must be
    # NXDOMAIN. Anything else means the resolver rewrites failed lookups.
    nx_name = f"dnstune-{secrets.token_hex(6)}.invalid"
    observations = [probe_once(server, nx_name, KIND_NX, plan.timeout)]
    for i in range(plan.queries):
        domain = plan.domains[i % len(plan.domains)]
        observations.append(probe_once(server, domain, KIND_POPULAR, plan.timeout))
    return ServerResult(server=server, observations=tuple(observations))


class PythonEngine:
    """Probe engine implemented in pure Python (always available)."""

    name = "python"

    def run(self, servers: Sequence[Server], plan: ProbePlan) -> list[ServerResult]:
        if not servers:
            return []
        workers = max(1, min(plan.workers, len(servers)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dnstune") as pool:
            return list(pool.map(lambda s: probe_server(s, plan), servers))
