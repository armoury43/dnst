"""Load and strictly validate resolver catalogs (built-in or user supplied)."""

from __future__ import annotations

import ipaddress
import re
import stat
import tomllib
from importlib import resources
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .models import Server

MAX_CATALOG_BYTES = 1_000_000
MAX_SERVERS = 512
_ALLOWED_KEYS = frozenset({"label", "provider", "address", "filtering"})
_PROVIDER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")


def load_builtin() -> list[Server]:
    """Load the catalog shipped inside the package."""
    text = resources.files("dnstune").joinpath("data/servers.toml").read_text("utf-8")
    return parse_catalog(text, source="built-in catalog")


def load_file(path: Path) -> list[Server]:
    """Load a user catalog from disk with size and syntax checks."""
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            # Refuses FIFOs, devices, and symlinks-to-those: a size of 0 would
            # sail past the size check below and reading one can hang forever.
            raise ConfigError(f"{path}: not a regular file")
        if info.st_size > MAX_CATALOG_BYTES:
            raise ConfigError(f"{path}: file too large (limit {MAX_CATALOG_BYTES} bytes)")
        text = path.read_text("utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: not valid UTF-8") from exc
    return parse_catalog(text, source=str(path))


def parse_catalog(text: str, *, source: str) -> list[Server]:
    """Parse TOML text into validated ``Server`` objects."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source}: invalid TOML: {exc}") from exc
    except RecursionError as exc:
        # A pathologically nested (but small) document can blow the
        # interpreter's recursion limit before any size check catches it.
        raise ConfigError(f"{source}: too deeply nested") from exc

    version = doc.get("schema_version", 1)
    if version != 1:
        raise ConfigError(f"{source}: unsupported schema_version {version!r} (expected 1)")
    unknown_top = set(doc) - {"schema_version", "server"}
    if unknown_top:
        raise ConfigError(f"{source}: unknown top-level keys: {sorted(unknown_top)}")

    entries = doc.get("server")
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"{source}: expected at least one [[server]] table")
    if len(entries) > MAX_SERVERS:
        raise ConfigError(f"{source}: too many servers (limit {MAX_SERVERS})")

    servers: list[Server] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        server = _parse_entry(entry, where=f"{source}: server #{index}")
        if server.address in seen:
            raise ConfigError(f"{source}: duplicate address {server.address}")
        seen.add(server.address)
        servers.append(server)
    return servers


def _parse_entry(entry: Any, *, where: str) -> Server:
    if not isinstance(entry, dict):
        raise ConfigError(f"{where}: must be a table")
    unknown = set(entry) - _ALLOWED_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")

    label = entry.get("label")
    provider = entry.get("provider")
    address = entry.get("address")
    filtering = entry.get("filtering", False)

    if not isinstance(label, str) or not 1 <= len(label) <= 64 or not label.isprintable():
        raise ConfigError(f"{where}: 'label' must be 1-64 printable characters")
    if not isinstance(provider, str) or not _PROVIDER_RE.fullmatch(provider):
        raise ConfigError(f"{where}: 'provider' must match {_PROVIDER_RE.pattern}")
    if not isinstance(address, str):
        raise ConfigError(f"{where}: 'address' must be a string")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ConfigError(f"{where}: invalid IP address {address!r}") from exc
    if not isinstance(filtering, bool):
        raise ConfigError(f"{where}: 'filtering' must be true or false")
    return Server(label=label, provider=provider, address=str(ip), filtering=filtering)


def select_servers(servers: list[Server], *, include_filtering: bool) -> list[Server]:
    """Drop filtering resolvers unless the user opted in."""
    return [s for s in servers if include_filtering or not s.filtering]
