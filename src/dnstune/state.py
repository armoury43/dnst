"""Persistent snapshot of the DNS settings we replaced, so they can be restored.

The file is written atomically (temp file + fsync + rename) with mode 0600
inside a 0700 directory, and is treated as untrusted input when read back.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .errors import BackendError, ConfigError
from .netutil import valid_dns_token

STATE_SCHEMA = 1
STATE_FILENAME = "state.json"
_MAX_STATE_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class SavedState:
    """What was configured before dnstune touched an interface."""

    interface: str
    previous: tuple[str, ...]
    applied: tuple[str, ...]
    applied_at: str


def default_state_dir() -> Path:
    """``$DNSTUNE_STATE_DIR``, else /var/lib/dnstune (root) or the XDG state dir."""
    override = os.environ.get("DNSTUNE_STATE_DIR")
    if override:
        return Path(override)
    if os.geteuid() == 0:
        return Path("/var/lib/dnstune")
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "dnstune"


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _ensure_private_dir(directory: Path) -> None:
    """Create ``directory`` (mode 0700) or verify an existing one is private.

    dnstune's default state directory for root is world-readable-by-path
    (``/var/lib/dnstune``). If another local user created it first -- or
    loosened its permissions -- writing our snapshot into it could let that
    user read, replace or delete the file we rely on to undo a DNS change.
    Refuse instead of trusting a directory we do not already own privately.
    """
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = directory.stat()
    except OSError as exc:
        raise BackendError(f"cannot create {directory}: {exc.strerror or exc}") from exc
    if info.st_uid != os.geteuid():
        raise BackendError(
            f"refusing to use {directory}: it is owned by a different user (uid {info.st_uid})"
        )
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise BackendError(
            f"refusing to use {directory}: it is readable or writable by other users "
            f"(mode {oct(stat.S_IMODE(info.st_mode))}); fix it with 'chmod 700 {directory}'"
        )


def _atomic_write(path: Path, data: bytes) -> None:
    _ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def save_state(state: SavedState, directory: Path) -> Path:
    _ensure_private_dir(directory)
    path = directory / STATE_FILENAME
    payload = {
        "schema": STATE_SCHEMA,
        "interface": state.interface,
        "previous": list(state.previous),
        "applied": list(state.applied),
        "applied_at": state.applied_at,
    }
    _atomic_write(path, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    return path


def load_state(directory: Path) -> SavedState | None:
    """Return the saved state, ``None`` if there is none, or raise ``ConfigError``."""
    path = directory / STATE_FILENAME
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"{path}: not a regular file")
        if info.st_size > _MAX_STATE_BYTES:
            raise ConfigError(f"{path}: state file is unreasonably large")
        raw = path.read_text("utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: not valid UTF-8") from exc

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: corrupt state file ({exc.msg})") from exc
    except RecursionError as exc:
        # A pathologically nested (but small) JSON document can blow the
        # interpreter's recursion limit before hitting any size check.
        raise ConfigError(f"{path}: state file is too deeply nested") from exc
    if not isinstance(doc, dict) or doc.get("schema") != STATE_SCHEMA:
        raise ConfigError(f"{path}: unsupported state file")

    iface = doc.get("interface")
    previous = doc.get("previous")
    applied = doc.get("applied")
    applied_at = doc.get("applied_at")
    if not isinstance(iface, str) or not isinstance(applied_at, str):
        raise ConfigError(f"{path}: malformed state file")
    for name, values in (("previous", previous), ("applied", applied)):
        if not isinstance(values, list) or not all(
            isinstance(v, str) and valid_dns_token(v) for v in values
        ):
            raise ConfigError(f"{path}: malformed '{name}' list in state file")
    assert isinstance(previous, list) and isinstance(applied, list)  # narrowed above
    return SavedState(iface, tuple(previous), tuple(applied), applied_at)


def clear_state(directory: Path) -> None:
    try:
        (directory / STATE_FILENAME).unlink()
    except FileNotFoundError:
        pass
