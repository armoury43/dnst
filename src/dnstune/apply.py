"""Apply and revert DNS settings with verification and automatic rollback.

Order of operations for ``apply_dns``:

1. Snapshot the current servers and write the snapshot to disk *first*, so an
   interrupted run can always be undone with ``dnstune revert``.
2. Set the new servers.
3. Read them back and make sure the system accepted exactly what we sent.
4. Resolve a real hostname through the system resolver.
5. If steps 2-4 fail in any way, restore the snapshot immediately.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import BackendError, ConfigError, VerificationError
from .resolved import ResolvedBackend
from .state import SavedState, clear_state, load_state, now_iso, save_state

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ApplyReport:
    interface: str
    previous: tuple[str, ...]
    applied: tuple[str, ...]


def _normalize(token: str) -> str:
    """Compare resolver tokens by IP, ignoring ``#server-name`` suffixes."""
    bare = token.split("#", 1)[0]
    try:
        return str(ipaddress.ip_address(bare))
    except ValueError:
        return bare


def _wait_for_resolution(
    backend: ResolvedBackend,
    hostname: str,
    attempts: int,
    delay: float,
    sleep: Callable[[float], None],
) -> bool:
    for attempt in range(attempts):
        if backend.can_resolve(hostname):
            return True
        if attempt + 1 < attempts:
            sleep(delay)
    return False


def apply_dns(
    backend: ResolvedBackend,
    *,
    interface: str,
    servers: Sequence[str],
    state_dir: Path,
    verify_hostname: str,
    attempts: int = 3,
    delay: float = 1.0,
    sleep: Callable[[float], None] | None = None,
) -> ApplyReport:
    """Switch ``interface`` to ``servers`` or leave it exactly as it was."""
    pause = time.sleep if sleep is None else sleep
    if not servers:
        raise ConfigError("no DNS servers to apply")

    current = tuple(backend.get_dns(interface))
    existing = load_state(state_dir)
    if (
        existing is not None
        and existing.interface == interface
        and tuple(existing.applied) == current
    ):
        previous = existing.previous  # keep the *original* snapshot on re-apply
    else:
        previous = current

    save_state(SavedState(interface, previous, tuple(servers), now_iso()), state_dir)

    try:
        backend.set_dns(interface, servers)
        after = backend.get_dns(interface)
        if {_normalize(t) for t in after} != {_normalize(s) for s in servers}:
            raise VerificationError("systemd-resolved did not accept the new DNS servers")
        if not _wait_for_resolution(backend, verify_hostname, attempts, delay, pause):
            raise VerificationError(
                f"could not resolve {verify_hostname} through the new DNS servers"
            )
    except (BackendError, VerificationError) as exc:
        try:
            backend.restore(interface, previous)
        except BackendError as rollback_exc:
            raise BackendError(
                f"{exc}; AND the automatic rollback failed ({rollback_exc}). "
                f"Run 'dnstune revert' or 'resolvectl revert {interface}' (a reboot also resets it)."
            ) from exc
        clear_state(state_dir)
        if isinstance(exc, VerificationError):
            raise VerificationError(f"{exc}; previous settings were restored") from exc
        raise BackendError(f"{exc}; previous settings were restored") from exc

    return ApplyReport(interface=interface, previous=previous, applied=tuple(servers))


def revert_dns(
    backend: ResolvedBackend, *, state_dir: Path, interface: str | None
) -> tuple[str, tuple[str, ...]]:
    """Undo ``apply_dns``. Returns (interface, restored servers)."""
    state = load_state(state_dir)
    if state is None:
        if interface is None:
            raise ConfigError(
                "nothing to revert: no saved state found. "
                "Use --interface IFACE to reset an interface to the system defaults."
            )
        backend.revert_link(interface)
        return interface, ()
    if interface is not None and interface != state.interface:
        raise ConfigError(
            f"saved state is for interface {state.interface!r}, not {interface!r}"
        )
    backend.restore(state.interface, state.previous)
    clear_state(state_dir)
    return state.interface, state.previous
