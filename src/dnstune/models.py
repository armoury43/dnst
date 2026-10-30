"""Plain data containers shared by every module. No behaviour lives here."""

from __future__ import annotations

from dataclasses import dataclass

KIND_POPULAR = "popular"
KIND_NX = "nxprobe"
VALID_KINDS = frozenset({KIND_POPULAR, KIND_NX})


@dataclass(frozen=True, slots=True)
class Server:
    """One DNS resolver address from the catalog."""

    label: str
    provider: str
    address: str
    filtering: bool = False
    # Always 53 in real use. Only tests point this at a local fake server.
    port: int = 53


@dataclass(frozen=True, slots=True)
class Observation:
    """The outcome of a single DNS query against a single server."""

    kind: str
    domain: str
    rcode: int | None
    latency_ms: float | None
    addresses: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ProbePlan:
    """What to measure. Both engines implement exactly the same plan."""

    domains: tuple[str, ...]
    queries: int = 6
    timeout: float = 1.5
    workers: int = 32


@dataclass(frozen=True, slots=True)
class ServerResult:
    """Raw observations for one server, before any analysis."""

    server: Server
    observations: tuple[Observation, ...]
