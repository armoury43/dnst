"""systemd-resolved backend, driven through the ``resolvectl`` command.

Safety properties
-----------------
* ``resolvectl`` is located in a fixed set of system directories, never via the
  caller's ``PATH`` (matters when running under ``sudo``).
* Commands are argv lists, never shell strings, with a minimal environment.
* Changes made with ``resolvectl dns`` are runtime-only. A reboot or a network
  reconnect always restores the system's own configuration, so the worst case
  of any bug is bounded.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from .errors import BackendError
from .netutil import valid_dns_token, validate_interface
from .procio import BoundedRunError, run_bounded

SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
COMMAND_TIMEOUT = 15.0
# resolvectl output is normally a few lines; this is a generous ceiling that
# still protects the caller if the binary is ever replaced or misbehaves.
MAX_OUTPUT_BYTES = 1 << 20

Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]

_LINK_LINE_RE = re.compile(r"Link\s+\d+\s+\((?P<name>[^)]+)\):\s*(?P<rest>.*)")


def system_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Run a command without a shell, a scrubbed environment, and a bounded read.

    Uses the same time- and size-capped reader as the external probe engine:
    a hung or misbehaving binary is killed instead of blocking or growing our
    memory without limit.
    """
    env = {"PATH": SYSTEM_PATH, "LANG": "C", "LC_ALL": "C"}
    try:
        result = run_bounded(
            list(argv), timeout=timeout, max_stdout=MAX_OUTPUT_BYTES, max_stderr=MAX_OUTPUT_BYTES, env=env
        )
    except BoundedRunError as exc:
        raise BackendError(f"'{argv[0]}' {exc}") from exc
    except OSError as exc:
        raise BackendError(f"cannot run '{argv[0]}': {exc.strerror or exc}") from exc
    return subprocess.CompletedProcess(
        args=list(argv),
        returncode=result.returncode,
        stdout=result.stdout.decode("utf-8", errors="replace"),
        stderr=result.stderr.decode("utf-8", errors="replace"),
    )


class ResolvedBackend:
    """Read and change per-interface DNS servers through systemd-resolved."""

    def __init__(self, runner: Runner = system_runner, executable: str | None = None) -> None:
        self._runner = runner
        if executable is None:
            executable = shutil.which("resolvectl", path=SYSTEM_PATH)
        self._exe = executable

    # -- helpers -----------------------------------------------------------
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        if self._exe is None:
            raise BackendError("resolvectl not found (systemd-resolved is required)")
        return self._runner([self._exe, *args], COMMAND_TIMEOUT)

    def _run_checked(self, *args: str) -> str:
        proc = self._run(*args)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            reason = detail[0] if detail else f"exit status {proc.returncode}"
            hint = ""
            if "access denied" in reason.lower() or "authentication" in reason.lower():
                hint = " (try again with sudo)"
            raise BackendError(f"resolvectl {args[0]} failed: {reason}{hint}")
        return proc.stdout

    # -- public API --------------------------------------------------------
    def available(self) -> bool:
        """True if resolvectl exists and can talk to a running systemd-resolved."""
        if self._exe is None:
            return False
        try:
            return self._run("status", "--no-pager").returncode == 0
        except BackendError:
            return False

    def get_dns(self, interface: str) -> list[str]:
        """DNS servers currently configured on ``interface`` (raw tokens)."""
        out = self._run_checked("dns", interface)
        for line in out.splitlines():
            match = _LINK_LINE_RE.fullmatch(line.strip())
            if match:
                tokens = match.group("rest").split()
                if not all(valid_dns_token(t) for t in tokens):
                    raise BackendError("resolvectl returned an unparseable DNS server list")
                return tokens
        if not out.strip():
            return []
        raise BackendError("unexpected output from 'resolvectl dns'")

    def set_dns(self, interface: str, servers: Sequence[str]) -> None:
        if not servers:
            raise BackendError("refusing to set an empty DNS server list")
        if not all(valid_dns_token(s) for s in servers):
            raise BackendError("refusing to pass an invalid DNS server to resolvectl")
        self._run_checked("dns", interface, *servers)
        self.flush_caches()

    def revert_link(self, interface: str) -> None:
        """Drop all per-link overrides and return to the system defaults."""
        self._run_checked("revert", interface)
        self.flush_caches()

    def flush_caches(self) -> None:
        """Best effort; a failed flush must never fail the operation."""
        try:
            self._run("flush-caches")
        except BackendError:
            pass

    def can_resolve(self, hostname: str) -> bool:
        """True if the *system* resolver can currently resolve ``hostname``."""
        try:
            proc = self._run("query", "--legend=no", "-4", hostname)
        except BackendError:
            return False
        return proc.returncode == 0 and bool(proc.stdout.strip())

    def restore(self, interface: str, previous: Sequence[str]) -> None:
        """Put back what was there before we changed anything."""
        if previous:
            self.set_dns(interface, previous)
        else:
            self.revert_link(interface)


def check_interface(name: str, sys_class_net: Path | None = None) -> str:
    """Validate an interface name (thin wrapper kept here for the CLI)."""
    if sys_class_net is None:
        return validate_interface(name)
    return validate_interface(name, sys_class_net=sys_class_net)
