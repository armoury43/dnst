"""Small, side-effect-free helpers for interfaces and resolver tokens."""

from __future__ import annotations

import re
from pathlib import Path

from .errors import BackendError, ConfigError

_IFACE_RE = re.compile(r"[A-Za-z0-9_.:@-]{1,15}")
_DNS_TOKEN_RE = re.compile(r"[A-Za-z0-9\[][A-Za-z0-9:.\[\]%#_-]{0,299}")

PROC_NET_ROUTE = Path("/proc/net/route")
SYS_CLASS_NET = Path("/sys/class/net")


def validate_interface(name: str, *, sys_class_net: Path = SYS_CLASS_NET) -> str:
    """Return ``name`` if it is a syntactically valid, existing interface."""
    if not _IFACE_RE.fullmatch(name) or name in {".", ".."}:
        raise ConfigError(f"invalid interface name: {name!r}")
    if not (sys_class_net / name).exists():
        raise ConfigError(f"interface {name!r} does not exist on this machine")
    return name


def valid_dns_token(token: str) -> bool:
    """True if ``token`` is safe to pass to ``resolvectl dns`` as one argument.

    Deliberately permissive about *what* the address looks like (resolvectl
    prints things like ``1.1.1.1#cloudflare-dns.com`` or ``[::1]:53``) but it
    can never start with ``-`` and never contains whitespace or shell syntax.
    """
    return bool(_DNS_TOKEN_RE.fullmatch(token))


def detect_default_interface(route_file: Path = PROC_NET_ROUTE) -> str:
    """Interface of the lowest-metric IPv4 default route."""
    try:
        lines = route_file.read_text("ascii", errors="replace").splitlines()
    except OSError as exc:
        raise BackendError(f"cannot read {route_file}: {exc.strerror or exc}") from exc

    best: tuple[int, str] | None = None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, dest, _gw, flags, _ref, _use, metric, mask = fields[:8]
        try:
            is_default = int(dest, 16) == 0 and int(mask, 16) == 0
            is_up = bool(int(flags, 16) & 0x1)
            metric_value = int(metric)
        except ValueError:
            continue
        if is_default and is_up and (best is None or metric_value < best[0]):
            best = (metric_value, iface)
    if best is None:
        raise BackendError(
            "could not find a default route; pass the network interface with --interface"
        )
    return best[1]
