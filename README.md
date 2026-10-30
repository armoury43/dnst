<div align="center">

# dnstune

**Find the fastest *trustworthy* DNS servers on Linux and apply them safely, with automatic rollback.**

[![CI](https://github.com/YOUR-USERNAME/dnstune/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/dnstune/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)

English · [فارسی](README.fa.md)

</div>

---

Changing DNS on Linux usually means guessing which server is fast, editing files by hand, and hoping you did not
break name resolution. **dnstune** measures real resolvers from *your* network, throws out the ones that tamper with
answers, and only then switches your system over, verifying that DNS still works and undoing the change itself if it
does not.

> **Status: alpha (v0.1).** The core is thoroughly unit-tested, but the systemd-resolved integration has so far been
> tested against a simulated `resolvectl`. Please try it on real machines and open an issue with the output of
> `dnstune -v status` if anything looks off. See [Roadmap](#roadmap).

## Why dnstune

- **Trust, not just speed.** Every server is checked for NXDOMAIN hijacking and for private/reserved addresses in
  answers to well-known domains (a classic sign of DNS-level censorship or injection).
- **Safe by construction.** Snapshot first, apply, read back, resolve a real hostname, and roll back automatically on
  any failure. Changes are runtime-only, so a reboot always restores your normal setup.
- **Fallbacks that actually fail independently.** The second server is chosen from a *different provider* so one
  provider outage cannot take DNS down.
- **Nothing to break.** Zero runtime dependencies, a hand-written and fuzz-tested DNS parser, strict input
  validation, no shell execution anywhere.
- **Fast when you want it.** An optional static Go engine probes hundreds of servers in parallel. If it is missing or
  misbehaves, dnstune silently uses the built-in Python engine.
- **Scriptable.** `--json` output with a versioned schema and meaningful exit codes.

## Install

Requires Linux and Python 3.11+. `apply`, `revert` and `status` additionally require **systemd-resolved**
(the default on Ubuntu, Fedora, Arch with `systemd-resolved` enabled, and others). `list`, `bench` and `best` work on
any system.

```bash
pipx install git+https://github.com/YOUR-USERNAME/dnstune.git
# or, from a clone:
pip install .
```

The optional Go engine is a single static binary; see [docs/ENGINE.md](docs/ENGINE.md).

## Usage

```console
$ dnstune bench
#   SERVER                  ADDRESS          MEDIAN   JITTER   FAIL  STATUS
1   Cloudflare              1.1.1.1          11.8 ms  1.9 ms   0%    selected
2   Google                  8.8.8.8          13.2 ms  2.4 ms   0%    selected
3   Cloudflare (secondary)  1.0.0.1          12.0 ms  2.1 ms   0%    ok
4   Quad9 (unfiltered)      9.9.9.10         19.5 ms  3.8 ms   0%    ok
5   Mullvad                 194.242.2.2      41.0 ms  6.3 ms   17%   ok
6   Example ISP resolver    203.0.113.7      7.0 ms   1.1 ms   0%    nxdomain_hijack

engine: python   servers tested: 6
```

*(Illustrative output; your numbers will differ.)*

Server 6 is the fastest but rewrites failed lookups, so it is never selected.

| Command | What it does |
| --- | --- |
| `dnstune list` | Show the resolver catalog |
| `dnstune bench` | Measure every server and print a ranking |
| `dnstune best` | Print the best servers, one per line (pipe-friendly) |
| `dnstune apply` | Benchmark, then switch an interface to the best servers |
| `dnstune revert` | Restore exactly what was configured before `apply` |
| `dnstune status` | Show the current DNS servers of an interface |

Useful options: `--json`, `--dry-run`, `--yes`, `--interface IFACE`, `--include-filtering`, `--domains a.org,b.org`,
`--servers my-servers.toml`, `--engine auto|python|go`, `--count N`. Run `dnstune <command> --help` for all of them.

### Applying

```bash
dnstune apply --dry-run     # see what would change, touch nothing
sudo "$(command -v dnstune)" apply
dnstune status
sudo "$(command -v dnstune)" revert
```

`apply` needs permission to change resolver settings (root, or a polkit-authorised desktop session). When installed
with `pipx`, plain `sudo dnstune` may not find the command, which is why the examples use
`sudo "$(command -v dnstune)"`.

### Adding your own resolvers

Regional or private resolvers change often, so they are deliberately not hard-coded. Put them in a TOML file:

```toml
schema_version = 1

[[server]]
label = "My resolver"
provider = "myisp"
address = "203.0.113.53"
```

```bash
dnstune bench --servers my-servers.toml
```

See [examples/custom-servers.toml](examples/custom-servers.toml).

## How it works

1. **Measure.** For every server: one query for a random name under the reserved `.invalid` TLD (must be NXDOMAIN),
   then `--queries` lookups of long-lived public domains. Each query uses a fresh socket, source port and
   transaction id.
2. **Judge.** Servers that answer the `.invalid` probe, or resolve a public domain to a private/reserved address, are
   disqualified. Unreachable or flaky servers (over 25% failures by default) are dropped.
3. **Rank.** `score = median_ms × (1 + 4 × failure_rate) + 0.5 × jitter_ms`, lower is better.
4. **Select.** Best server first, then the best server from a *different provider*, unless that one is dramatically
   slower.
5. **Apply.** Snapshot → set → read back → resolve a real hostname → auto-rollback on any failure.

If **every** responding server looks tampered with, dnstune warns that your network is probably intercepting DNS and
refuses to change anything.

More detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/RELIABILITY.md](docs/RELIABILITY.md).

## Privacy

Benchmarking sends ordinary DNS queries for a handful of public domains (`example.com`, `wikipedia.org`, ...) to each
resolver in the catalog. Nothing else is sent and dnstune has no telemetry. Change the domains with `--domains`.

## Security

dnstune parses untrusted network data and runs as a privileged tool, so it is written defensively: bounds-checked,
fuzz-tested parsing; no shell; validated interface names and server addresses; atomic 0600 state files; minimal
subprocess environment. See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

One honest limitation: plain DNS over UDP/53 can be observed or altered by anyone on the path. dnstune picks the
best resolver it can, but it cannot make unencrypted DNS private. DNS-over-TLS support is on the roadmap.

## Roadmap

- [x] **0.1** Catalog, benchmarking, integrity checks, safe apply/revert on systemd-resolved, optional Go engine
- [ ] **0.2** Per-application proxy: run a program through a proxy without touching the rest of the system
- [ ] **0.2** NetworkManager backend for systems without systemd-resolved
- [ ] **0.3** DNS-over-TLS, scheduled re-benchmarking with automatic failover
- [ ] **0.4** Local caching resolver (Go) with per-domain rules, tray icon / GUI

## Development

```bash
python -m venv .venv && . .venv/bin/activate
make install-dev
make fmt        # format Python and Go
make check      # ruff, mypy, pytest, go vet + go test
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
