"""Adapter for the optional ``dnstune-probe`` engine written in Go.

The Go binary only *measures*; every judgement (scoring, integrity flags,
selection) stays in Python. Its output is treated as untrusted input and is
validated field by field. If anything looks wrong the caller falls back to the
built-in Python engine, so a broken or outdated binary can never break dnstune.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import re
import shutil
from collections.abc import Sequence
from typing import Any

from . import ENGINE_PROTOCOL
from .errors import EngineError
from .models import VALID_KINDS, Observation, ProbePlan, Server, ServerResult
from .procio import BoundedRunError, run_bounded

log = logging.getLogger(__name__)

ENGINE_ENV = "DNSTUNE_ENGINE"
ENGINE_NAME = "dnstune-probe"
_VERSION_RE = re.compile(r"dnstune-probe \S+ protocol=(\d+)")
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_VERSION_BYTES = 4096
_MAX_ADDRESSES = 64


def _trusted_when_root(path: str) -> bool:
    """When running as root only execute binaries that only root can modify."""
    if os.geteuid() != 0:
        return True
    try:
        for target in (path, os.path.dirname(os.path.realpath(path))):
            info = os.stat(target)
            if info.st_uid != 0 or info.st_mode & 0o022:
                return False
    except OSError:
        return False
    return True


def find_engine() -> ExternalEngine | None:
    """Locate and handshake with the Go engine. ``None`` if unavailable."""
    candidate = os.environ.get(ENGINE_ENV) or shutil.which(ENGINE_NAME)
    if not candidate:
        return None
    if not os.access(candidate, os.X_OK):
        log.debug("engine candidate %s is not executable", candidate)
        return None
    if not _trusted_when_root(candidate):
        log.warning("ignoring %s: not owned by root or writable by others", candidate)
        return None
    engine = ExternalEngine(candidate)
    return engine if engine.handshake() else None


class ExternalEngine:
    """Runs the Go engine as a subprocess speaking the JSON protocol."""

    name = "go"

    def __init__(self, path: str) -> None:
        self.path = path

    def handshake(self) -> bool:
        try:
            result = run_bounded(
                [self.path, "--version"], timeout=5, max_stdout=_MAX_VERSION_BYTES, max_stderr=_MAX_VERSION_BYTES
            )
        except (OSError, BoundedRunError):
            return False
        stdout = result.stdout.decode("utf-8", errors="replace")
        match = _VERSION_RE.fullmatch(stdout.strip())
        ok = result.returncode == 0 and match is not None and int(match.group(1)) == ENGINE_PROTOCOL
        if not ok:
            log.debug("engine %s failed the version handshake", self.path)
        return ok

    def run(self, servers: Sequence[Server], plan: ProbePlan) -> list[ServerResult]:
        if not servers:
            return []
        job = {
            "protocol": ENGINE_PROTOCOL,
            "servers": [s.address for s in servers],
            "domains": list(plan.domains),
            "queries": plan.queries,
            "timeout_ms": int(plan.timeout * 1000),
            "workers": plan.workers,
        }
        batches = math.ceil(len(servers) / max(1, plan.workers))
        budget = batches * (plan.queries + 1) * plan.timeout + 15.0
        try:
            result = run_bounded(
                [self.path, "run"],
                timeout=budget,
                max_stdout=_MAX_OUTPUT_BYTES,
                input_bytes=json.dumps(job).encode("utf-8"),
            )
        except BoundedRunError as exc:
            raise EngineError(f"probe engine was stopped: {exc}") from exc
        except OSError as exc:
            raise EngineError(f"cannot run probe engine: {exc.strerror or exc}") from exc
        if result.returncode != 0:
            first = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
            raise EngineError(f"probe engine failed: {first[0] if first else result.returncode}")
        return parse_engine_output(result.stdout.decode("utf-8", errors="replace"), servers, plan)


def parse_engine_output(
    text: str, servers: Sequence[Server], plan: ProbePlan
) -> list[ServerResult]:
    """Validate the engine's JSON and convert it to ``ServerResult`` objects."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EngineError("probe engine returned invalid JSON") from exc
    if not isinstance(doc, dict) or doc.get("protocol") != ENGINE_PROTOCOL:
        raise EngineError("probe engine speaks a different protocol")
    results = doc.get("results")
    if not isinstance(results, list) or len(results) != len(servers):
        raise EngineError("probe engine returned the wrong number of results")

    max_obs = plan.queries + 1
    out: list[ServerResult] = []
    for server, item in zip(servers, results, strict=True):
        if not isinstance(item, dict) or item.get("server") != server.address:
            raise EngineError("probe engine results are out of order")
        raw_obs = item.get("observations")
        if not isinstance(raw_obs, list) or len(raw_obs) > max_obs:
            raise EngineError("probe engine returned malformed observations")
        out.append(ServerResult(server, tuple(_parse_observation(o) for o in raw_obs)))
    return out


def _parse_observation(raw: Any) -> Observation:
    if not isinstance(raw, dict):
        raise EngineError("observation is not an object")
    kind, domain = raw.get("kind"), raw.get("domain")
    rcode, latency = raw.get("rcode"), raw.get("latency_ms")
    addresses, error = raw.get("addresses", []), raw.get("error", "")

    if kind not in VALID_KINDS or not isinstance(domain, str) or len(domain) > 253:
        raise EngineError("observation has invalid kind or domain")
    if rcode is not None and (not _is_int(rcode) or not 0 <= rcode <= 15):
        raise EngineError("observation has invalid rcode")
    if latency is not None and (
        not isinstance(latency, (int, float))
        or isinstance(latency, bool)
        or not 0 <= latency <= 600_000
    ):
        raise EngineError("observation has invalid latency")
    if not isinstance(addresses, list) or len(addresses) > _MAX_ADDRESSES:
        raise EngineError("observation has invalid addresses")
    clean: list[str] = []
    for addr in addresses:
        try:
            clean.append(str(ipaddress.ip_address(addr)))
        except (ValueError, TypeError) as exc:
            raise EngineError("observation contains an invalid IP address") from exc
    if not isinstance(error, str) or len(error) > 64:
        raise EngineError("observation has invalid error text")
    return Observation(
        kind=kind,
        domain=domain,
        rcode=rcode,
        latency_ms=None if latency is None else float(latency),
        addresses=tuple(clean),
        error=error or None,
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


__all__ = ["ENGINE_ENV", "ENGINE_NAME", "ExternalEngine", "find_engine", "parse_engine_output"]
