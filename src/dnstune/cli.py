"""Command line interface: ``dnstune [-v] <command> [options]``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from . import __version__, servers as catalog
from .analysis import DEFAULT_MAX_FAILURE_RATE
from .apply import apply_dns, revert_dns
from .bench import ENGINE_CHOICES, BenchOutcome, parse_domains, run_bench
from .errors import BackendError, ConfigError, DnstuneError, NoEligibleServerError
from .models import ProbePlan, Server
from .netutil import detect_default_interface, validate_interface
from .render import render_bench_json, render_catalog, render_table
from .resolved import ResolvedBackend
from .state import default_state_dir, load_state

EXIT_INTERRUPTED = 130

EPILOG = """\
exit codes:
  0  success
  1  unexpected error
  2  invalid usage, catalog or state file
  3  DNS backend missing or refused the change
  4  no server passed the reliability and integrity checks
  5  applying failed verification and was rolled back
"""


# --------------------------------------------------------------------------
# argument helpers
# --------------------------------------------------------------------------
def _int_range(low: int, high: int) -> Callable[[str], int]:
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from exc
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value

    return parse


def _float_range(low: float, high: float) -> Callable[[str], float]:
    def parse(text: str) -> float:
        try:
            value = float(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{text!r} is not a number") from exc
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value

    return parse


def _probe_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("measurement options")
    group.add_argument("--servers", metavar="FILE", help="use this TOML catalog instead of the built-in one")
    group.add_argument(
        "--include-filtering",
        action="store_true",
        help="also consider resolvers that block ads/malware by default",
    )
    group.add_argument("--domains", metavar="A,B,C", help="comma separated hostnames to query")
    group.add_argument("--queries", type=_int_range(1, 50), default=6, help="queries per server (default: 6)")
    group.add_argument(
        "--timeout", type=_float_range(0.2, 10.0), default=1.5, help="seconds per query (default: 1.5)"
    )
    group.add_argument(
        "--workers", type=_int_range(1, 128), default=32, help="servers probed in parallel (default: 32)"
    )
    group.add_argument("--engine", choices=ENGINE_CHOICES, default="auto", help="probe engine (default: auto)")
    group.add_argument(
        "--max-failure-rate",
        type=_float_range(0.0, 1.0),
        default=DEFAULT_MAX_FAILURE_RATE,
        help="ignore servers failing more often than this (default: 0.25)",
    )
    group.add_argument("--count", type=_int_range(1, 4), default=2, help="how many servers to select (default: 2)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnstune",
        description="Find the fastest trustworthy DNS servers and apply them safely.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"dnstune {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging on stderr")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    p_list = sub.add_parser("list", help="show the resolver catalog")
    p_list.add_argument("--servers", metavar="FILE", help="show this TOML catalog instead")
    p_list.add_argument("--json", action="store_true", help="machine readable output")
    p_list.set_defaults(func=cmd_list)

    p_bench = sub.add_parser("bench", help="measure every server and show a ranking")
    _probe_options(p_bench)
    p_bench.add_argument("--json", action="store_true", help="machine readable output")
    p_bench.set_defaults(func=cmd_bench)

    p_best = sub.add_parser("best", help="print the best servers, one per line")
    _probe_options(p_best)
    p_best.add_argument("--json", action="store_true", help="machine readable output")
    p_best.set_defaults(func=cmd_best)

    p_apply = sub.add_parser("apply", help="benchmark, then switch an interface to the best servers")
    _probe_options(p_apply)
    p_apply.add_argument("--interface", metavar="IFACE", help="network interface (default: the default route)")
    p_apply.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    p_apply.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p_apply.set_defaults(func=cmd_apply)

    p_revert = sub.add_parser("revert", help="restore the DNS settings saved before 'apply'")
    p_revert.add_argument("--interface", metavar="IFACE", help="interface to reset if there is no saved state")
    p_revert.set_defaults(func=cmd_revert)

    p_status = sub.add_parser("status", help="show the current DNS servers of an interface")
    p_status.add_argument("--interface", metavar="IFACE", help="network interface (default: the default route)")
    p_status.set_defaults(func=cmd_status)
    return parser


# --------------------------------------------------------------------------
# shared plumbing
# --------------------------------------------------------------------------
def _color_enabled(args: argparse.Namespace) -> bool:
    return not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


def _load_servers(args: argparse.Namespace) -> list[Server]:
    servers = catalog.load_file(Path(args.servers)) if args.servers else catalog.load_builtin()
    return catalog.select_servers(servers, include_filtering=args.include_filtering)


def _plan(args: argparse.Namespace) -> ProbePlan:
    return ProbePlan(
        domains=parse_domains(args.domains),
        queries=args.queries,
        timeout=args.timeout,
        workers=args.workers,
    )


def _bench(args: argparse.Namespace) -> tuple[BenchOutcome, ProbePlan]:
    plan = _plan(args)
    outcome = run_bench(
        _load_servers(args),
        plan,
        engine_choice=args.engine,
        max_failure_rate=args.max_failure_rate,
        select_count=args.count,
    )
    return outcome, plan


def _interface(args: argparse.Namespace) -> str:
    name = args.interface if args.interface else detect_default_interface()
    return validate_interface(name)


def _require_backend() -> ResolvedBackend:
    backend = ResolvedBackend()
    if not backend.available():
        raise BackendError(
            "systemd-resolved is not available. dnstune 0.1 supports only systemd-resolved; "
            "see the README for other setups."
        )
    return backend


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> int:
    servers = catalog.load_file(Path(args.servers)) if args.servers else catalog.load_builtin()
    print(render_catalog(servers, as_json=args.json))
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    outcome, _ = _bench(args)
    if args.json:
        print(render_bench_json(outcome))
    else:
        print(render_table(outcome, color=_color_enabled(args)))
    return 0


def cmd_best(args: argparse.Namespace) -> int:
    outcome, _ = _bench(args)
    if not outcome.selected:
        for warning in outcome.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        raise NoEligibleServerError("no server passed the reliability and integrity checks")
    if args.json:
        print(render_bench_json(outcome))
    else:
        for stat in outcome.selected:
            print(stat.address)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    backend = _require_backend()
    interface = _interface(args)
    outcome, plan = _bench(args)
    for warning in outcome.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not outcome.selected:
        raise NoEligibleServerError("no server passed the reliability and integrity checks")

    chosen = [s.address for s in outcome.selected]
    current = backend.get_dns(interface)
    print(render_table(outcome, color=_color_enabled(args)))
    print()
    print(f"interface : {interface}")
    print(f"current   : {' '.join(current) if current else '(none set on this link)'}")
    print(f"new       : {' '.join(chosen)}")

    if args.dry_run:
        print("\ndry run: nothing was changed.")
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            raise ConfigError("refusing to change DNS settings non-interactively without --yes")
        answer = input("\nApply these DNS servers? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("aborted, nothing was changed.")
            return 0

    report = apply_dns(
        backend,
        interface=interface,
        servers=chosen,
        state_dir=default_state_dir(),
        verify_hostname=plan.domains[0],
    )
    print(f"\nDNS for {report.interface} is now: {' '.join(report.applied)}")
    print("This is a runtime change: a reboot or reconnect restores your normal settings.")
    print("Undo it any time with: dnstune revert")
    return 0


def cmd_revert(args: argparse.Namespace) -> int:
    backend = _require_backend()
    interface = validate_interface(args.interface) if args.interface else None
    name, restored = revert_dns(backend, state_dir=default_state_dir(), interface=interface)
    if restored:
        print(f"restored DNS for {name}: {' '.join(restored)}")
    else:
        print(f"{name} reset to the system defaults.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    backend = _require_backend()
    interface = _interface(args)
    current = backend.get_dns(interface)
    print(f"interface : {interface}")
    print(f"DNS       : {' '.join(current) if current else '(none set on this link)'}")
    state = load_state(default_state_dir())
    if state is not None:
        print(f"dnstune   : applied {' '.join(state.applied)} on {state.applied_at} (run 'dnstune revert' to undo)")
    elif _root_state_may_exist():
        # State written by 'sudo dnstune apply' lives in a root-only directory that
        # a normal user cannot read, so "no saved changes" would be misleading.
        print("dnstune   : no changes recorded for this user")
        print("            (changes made with sudo are stored separately: run 'sudo dnstune status')")
    else:
        print("dnstune   : no saved changes")
    return 0


def _root_state_may_exist() -> bool:
    if os.geteuid() == 0 or os.environ.get("DNSTUNE_STATE_DIR"):
        return False
    return Path("/var/lib/dnstune").exists()


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def _silence_stdout() -> None:
    """Avoid a traceback when the reader of a pipe (e.g. ``head``) goes away."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return int(args.func(args))
    except DnstuneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        _silence_stdout()
        return 0
    except OSError as exc:
        print(f"error: {exc.strerror or exc}", file=sys.stderr)
        return 1
