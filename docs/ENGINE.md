# The optional Go engine (`dnstune-probe`)

The Python package is complete on its own. The Go engine is an accelerator: one static binary that probes many
servers in parallel with very low overhead. Use it if you benchmark large custom catalogs or run dnstune on small
machines.

## Build

```bash
make go-build                # produces ./dist/dnstune-probe
sudo install -m 0755 dist/dnstune-probe /usr/local/bin/dnstune-probe
```

Release pages also ship prebuilt `linux-amd64` / `linux-arm64` binaries with `SHA256SUMS`.

## How dnstune finds it

1. `$DNSTUNE_ENGINE` if set, otherwise `dnstune-probe` on `PATH`.
2. It must answer `--version` with `dnstune-probe <version> protocol=1`.
3. When dnstune runs as **root**, the binary and its directory must be owned by root and not writable by group or
   others; otherwise it is ignored. This prevents a user-writable `PATH` entry from becoming privilege escalation.

`--engine auto` (default) uses it when found and falls back to Python on any failure. `--engine go` insists on it and
fails loudly. `--engine python` never uses it. `dnstune bench` prints which engine ran.

## Protocol (version 1)

`dnstune-probe run` reads one JSON job on stdin and writes one JSON document on stdout. Unknown fields in the job are
rejected.

```json
{"protocol": 1, "servers": ["1.1.1.1"], "domains": ["example.com"], "queries": 6, "timeout_ms": 1500, "workers": 32}
```

```json
{
  "protocol": 1,
  "results": [
    {
      "server": "1.1.1.1",
      "observations": [
        {"kind": "nxprobe", "domain": "dnstune-ab12cd34ef56.invalid", "rcode": 3, "latency_ms": 9.4, "addresses": [], "error": ""},
        {"kind": "popular", "domain": "example.com", "rcode": 0, "latency_ms": 11.8, "addresses": ["93.184.216.34"], "error": ""}
      ]
    }
  ]
}
```

- `results` has the same length and order as `servers`; `server` echoes the input string unchanged.
- Each server yields `1 + queries` observations: one `nxprobe`, then `popular` queries rotating through `domains`.
- `rcode` and `latency_ms` are `null` when no valid response arrived; `error` then holds a short reason
  (`timeout`, `refused`, `malformed`, `network:...`).
- `addresses` is always an array (never `null`).

Python validates every field of the output and discards the run on any deviation.

## Changing the protocol

Bump `protocol` in `engine/main.go` **and** `ENGINE_PROTOCOL` in `src/dnstune/__init__.py` together. Old binaries then
fail the handshake and are ignored instead of misbehaving.
