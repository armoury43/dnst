"""Turn raw observations into a ranked, explainable result.

This is the only place where scoring and integrity decisions are made, so both
probe engines are judged by the same rules.

Score (lower is better)::

    score = median_ms * (1 + 4 * failure_rate) + 0.5 * jitter_ms

Integrity flags make a server ineligible regardless of speed:

``nxdomain_hijack``
    A random name under ``.invalid`` (guaranteed NXDOMAIN, RFC 6761) got an
    answer. The resolver rewrites failed lookups, usually to show ads.
``bogon_answer``
    A well-known public domain resolved to a non-public address (private,
    loopback, CGNAT, reserved...). Typical of DNS-level censorship/injection.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections.abc import Sequence
from dataclasses import dataclass

from .dnswire import RCODE_NOERROR
from .models import KIND_NX, KIND_POPULAR, Observation, ServerResult

FLAG_NX_HIJACK = "nxdomain_hijack"
FLAG_BOGON = "bogon_answer"

DEFAULT_MAX_FAILURE_RATE = 0.25
# A fallback from another provider may be at most this much slower (x factor + ms).
DIVERSITY_SLOWDOWN = 2.5
DIVERSITY_SLACK_MS = 25.0


@dataclass(frozen=True, slots=True)
class ServerStats:
    """Everything known about one server after analysis."""

    result: ServerResult
    sent: int
    answered: int
    popular_sent: int
    resolved: int
    median_ms: float | None
    jitter_ms: float | None
    failure_rate: float
    flags: tuple[str, ...]
    score: float | None
    eligible: bool
    reasons: tuple[str, ...]

    @property
    def address(self) -> str:
        return self.result.server.address

    @property
    def provider(self) -> str:
        return self.result.server.provider


def _resolved(obs: Observation) -> bool:
    return obs.kind == KIND_POPULAR and obs.rcode == RCODE_NOERROR and bool(obs.addresses)


def _is_bogon(address: str) -> bool:
    try:
        return not ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def analyse(result: ServerResult, *, max_failure_rate: float = DEFAULT_MAX_FAILURE_RATE) -> ServerStats:
    """Compute statistics, integrity flags and eligibility for one server."""
    observations = result.observations
    popular = [o for o in observations if o.kind == KIND_POPULAR]
    good = [o for o in popular if _resolved(o)]
    latencies = [o.latency_ms for o in good if o.latency_ms is not None]

    flags: list[str] = []
    for obs in observations:
        if obs.kind == KIND_NX and obs.rcode == RCODE_NOERROR and obs.addresses:
            flags.append(FLAG_NX_HIJACK)
            break
    for obs in popular:
        if any(_is_bogon(a) for a in obs.addresses):
            flags.append(FLAG_BOGON)
            break

    failure_rate = 1.0 if not popular else 1.0 - len(good) / len(popular)
    median = statistics.median(latencies) if latencies else None
    jitter = statistics.pstdev(latencies) if len(latencies) > 1 else (0.0 if latencies else None)

    reasons: list[str] = [f"integrity:{f}" for f in flags]
    if not good:
        reasons.append("unreachable")
    elif failure_rate > max_failure_rate:
        reasons.append("unreliable")

    score = None
    if median is not None and jitter is not None:
        score = median * (1.0 + 4.0 * failure_rate) + 0.5 * jitter

    return ServerStats(
        result=result,
        sent=len(observations),
        answered=sum(1 for o in observations if o.rcode is not None),
        popular_sent=len(popular),
        resolved=len(good),
        median_ms=None if median is None else round(median, 2),
        jitter_ms=None if jitter is None else round(jitter, 2),
        failure_rate=round(failure_rate, 4),
        flags=tuple(flags),
        score=None if score is None else round(score, 2),
        eligible=not reasons,
        reasons=tuple(reasons),
    )


def rank(stats: Sequence[ServerStats]) -> list[ServerStats]:
    """Eligible servers by ascending score first, then the rest by address."""
    eligible = sorted((s for s in stats if s.eligible), key=lambda s: (s.score or 0.0, s.address))
    others = sorted((s for s in stats if not s.eligible), key=lambda s: s.address)
    return eligible + others


def select(ranked: Sequence[ServerStats], count: int = 2) -> list[ServerStats]:
    """Pick the best server, then prefer runners-up from *other* providers.

    Two addresses of one provider fail together when that provider has an
    outage, so a fallback from a different provider is worth more than a
    slightly faster sibling address, unless it is dramatically slower.
    """
    eligible = [s for s in ranked if s.eligible]
    if not eligible or count < 1:
        return []
    chosen = [eligible[0]]
    remaining = eligible[1:]
    while remaining and len(chosen) < count:
        used = {s.provider for s in chosen}
        pick = remaining[0]
        other = next((s for s in remaining if s.provider not in used), None)
        # Diversity wins unless the other provider is far slower.
        if other is not None:
            limit = (pick.score or 0.0) * DIVERSITY_SLOWDOWN + DIVERSITY_SLACK_MS
            if (other.score or 0.0) <= limit:
                pick = other
        chosen.append(pick)
        remaining.remove(pick)
    return chosen


def network_warnings(stats: Sequence[ServerStats]) -> list[str]:
    """Explain suspicious whole-network situations in plain language."""
    warnings: list[str] = []
    responders = [s for s in stats if s.answered > 0]
    if not responders:
        warnings.append(
            "No server answered. You may be offline, or outgoing UDP port 53 is blocked."
        )
        return warnings
    if len(responders) >= 2 and all(s.flags for s in responders):
        warnings.append(
            "Every responding server shows DNS tampering signs. Your network is probably "
            "intercepting or rewriting DNS, so these measurements are unreliable and "
            "dnstune will not change your settings."
        )
    return warnings
