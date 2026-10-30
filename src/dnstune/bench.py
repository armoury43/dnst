"""Orchestration: choose an engine, probe, analyse, rank, select."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field

from . import analysis
from .dnswire import validate_hostname
from .engine_ext import find_engine
from .errors import ConfigError, EngineError
from .models import ProbePlan, Server, ServerResult
from .probe import PythonEngine

log = logging.getLogger(__name__)

# Long-lived, boring domains: they resolve the same way for years.
DEFAULT_DOMAINS = (
    "example.com",
    "wikipedia.org",
    "kernel.org",
    "debian.org",
    "python.org",
    "gnu.org",
)
MAX_DOMAINS = 32
ENGINE_CHOICES = ("auto", "python", "go")


@dataclass(frozen=True, slots=True)
class BenchOutcome:
    engine: str
    ranked: list[analysis.ServerStats]
    selected: list[analysis.ServerStats]
    warnings: list[str] = field(default_factory=list)


def parse_domains(value: str | None) -> tuple[str, ...]:
    """Parse a comma separated list; ``None`` gives the built-in canaries."""
    if value is None:
        return DEFAULT_DOMAINS
    seen: dict[str, None] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            seen[validate_hostname(part)] = None
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    if not seen:
        raise ConfigError("--domains needs at least one hostname")
    if len(seen) > MAX_DOMAINS:
        raise ConfigError(f"--domains accepts at most {MAX_DOMAINS} hostnames")
    return tuple(seen)


def run_bench(
    servers: Sequence[Server],
    plan: ProbePlan,
    *,
    engine_choice: str = "auto",
    max_failure_rate: float = analysis.DEFAULT_MAX_FAILURE_RATE,
    select_count: int = 2,
) -> BenchOutcome:
    """Probe every server and return a fully analysed outcome."""
    if not servers:
        raise ConfigError("no servers to test (all were filtered out?)")

    warnings: list[str] = []
    engine_name = "python"
    results: list[ServerResult] | None = None

    if engine_choice in ("auto", "go"):
        external = find_engine()
        if external is None:
            if engine_choice == "go":
                raise ConfigError(
                    "--engine go requested but 'dnstune-probe' was not found or failed its "
                    "version check (see docs/ENGINE.md)"
                )
        else:
            try:
                results = external.run(servers, plan)
                engine_name = external.name
            except EngineError as exc:
                if engine_choice == "go":
                    raise
                warnings.append(f"Go engine failed ({exc}); used the Python engine instead.")

    if results is None:
        results = PythonEngine().run(servers, plan)

    stats = [analysis.analyse(r, max_failure_rate=max_failure_rate) for r in results]
    ranked = analysis.rank(stats)
    selected = analysis.select(ranked, select_count)
    warnings.extend(analysis.network_warnings(ranked))
    return BenchOutcome(engine=engine_name, ranked=ranked, selected=selected, warnings=warnings)
