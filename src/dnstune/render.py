"""Human and machine readable output."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from . import __version__
from .analysis import ServerStats
from .bench import BenchOutcome
from .models import Server

JSON_SCHEMA_VERSION = 1

_CODES = {"green": "32", "red": "31", "yellow": "33", "dim": "2", "bold": "1"}


def paint(text: str, style: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\x1b[{_CODES[style]}m{text}\x1b[0m"


def _ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f} ms"


def _status(stat: ServerStats, selected: bool) -> tuple[str, str]:
    if selected:
        return "selected", "green"
    if stat.eligible:
        return "ok", "dim"
    return ", ".join(r.replace("integrity:", "") for r in stat.reasons), "red"


def render_table(outcome: BenchOutcome, *, color: bool) -> str:
    chosen = {s.address for s in outcome.selected}
    header = ["#", "SERVER", "ADDRESS", "MEDIAN", "JITTER", "FAIL", "STATUS"]
    rows: list[list[str]] = []
    styles: list[str] = []
    for index, stat in enumerate(outcome.ranked, start=1):
        text, style = _status(stat, stat.address in chosen)
        rows.append(
            [
                str(index),
                stat.result.server.label,
                stat.address,
                _ms(stat.median_ms),
                _ms(stat.jitter_ms),
                f"{stat.failure_rate * 100:.0f}%",
                text,
            ]
        )
        styles.append(style)

    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(len(header))]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    out = [paint(line(header), "bold", color)]
    for row, style in zip(rows, styles, strict=True):
        out.append(paint(line(row), style, color) if style != "dim" else line(row))
    out.append("")
    out.append(f"engine: {outcome.engine}   servers tested: {len(outcome.ranked)}")
    for warning in outcome.warnings:
        out.append(paint(f"warning: {warning}", "yellow", color))
    return "\n".join(out)


def stat_to_dict(stat: ServerStats, selected: bool) -> dict[str, Any]:
    server = stat.result.server
    return {
        "address": stat.address,
        "label": server.label,
        "provider": server.provider,
        "filtering": server.filtering,
        "median_ms": stat.median_ms,
        "jitter_ms": stat.jitter_ms,
        "failure_rate": stat.failure_rate,
        "score": stat.score,
        "eligible": stat.eligible,
        "reasons": list(stat.reasons),
        "flags": list(stat.flags),
        "selected": selected,
    }


def render_bench_json(outcome: BenchOutcome) -> str:
    chosen = {s.address for s in outcome.selected}
    doc = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": "dnstune",
        "version": __version__,
        "engine": outcome.engine,
        "selected": [s.address for s in outcome.selected],
        "warnings": outcome.warnings,
        "results": [stat_to_dict(s, s.address in chosen) for s in outcome.ranked],
    }
    return json.dumps(doc, indent=2)


def render_catalog(servers: Sequence[Server], *, as_json: bool) -> str:
    if as_json:
        doc = {
            "schema_version": JSON_SCHEMA_VERSION,
            "servers": [
                {
                    "label": s.label,
                    "provider": s.provider,
                    "address": s.address,
                    "filtering": s.filtering,
                }
                for s in servers
            ],
        }
        return json.dumps(doc, indent=2)
    header = ["ADDRESS", "PROVIDER", "FILTERING", "LABEL"]
    rows = [[s.address, s.provider, "yes" if s.filtering else "no", s.label] for s in servers]
    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(len(header))]
    lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in [header, *rows]]
    return "\n".join(lines)
