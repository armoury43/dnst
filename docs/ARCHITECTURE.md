# Architecture

dnstune is split so that **measuring** is replaceable and **judging** is not.

```
              ┌────────────────────────── Python package ─────────────────────────┐
 servers.toml │                                                                   │
      │       │  servers.py ──► bench.py ──► engine ──► analysis.py ──► render.py │
      ▼       │  (validate)     (orchestrate) │  raw        (score, flags,  (table / │
   catalog    │                               │  observations  select)       JSON)   │
              │                               ▼                                     │
              │                    ┌─ probe.py        (pure Python, always there)   │
              │                    └─ engine_ext.py ─► dnstune-probe (Go, optional) │
              │                                                                     │
              │  cli.py ──► apply.py ──► resolved.py ──► resolvectl (systemd-resolved)
              │               │  └────► state.py  (atomic 0600 snapshot)            │
              └───────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Responsibility |
| --- | --- |
| `dnswire.py` | Strict DNS query builder and response parser. No I/O. |
| `models.py` | Immutable dataclasses shared everywhere. No behaviour. |
| `servers.py` | Load and validate resolver catalogs (built-in or user TOML). |
| `probe.py` | Pure-Python engine: UDP sockets + thread pool. |
| `engine_ext.py` | Adapter for the optional Go engine; validates its output as untrusted. |
| `analysis.py` | The **only** place that scores servers, flags tampering and selects. |
| `bench.py` | Chooses an engine, falls back on failure, ties measuring to analysis. |
| `resolved.py` | `resolvectl` wrapper with an injectable runner (fully testable). |
| `apply.py` | Snapshot → set → verify → rollback, and `revert`. |
| `state.py` | Atomic, permission-restricted persistence of the pre-change snapshot. |
| `netutil.py` | Interface and resolver-token validation, default-route detection. |
| `render.py` / `cli.py` | Output and command line. |

## Key decisions

**Engines only measure.** Both engines return the same list of raw *observations* (query kind, domain, rcode,
latency, addresses, error). Scoring and integrity flags are computed once, in Python, so the two engines can never
disagree about which server is trustworthy, and a bug in the Go code cannot change trust decisions.

**Everything crossing a boundary is untrusted.** Network packets, engine output, catalog files, state files and
`resolvectl` output are all validated before use.

**Dependency injection at the edges.** `ResolvedBackend` takes a `runner`; tests swap in a fake that simulates
`resolvectl`. The probe engines are pluggable. This is why the apply/rollback logic has exhaustive tests without
needing root or a real system.

## Data flow of `dnstune apply`

1. Resolve the interface (`--interface` or the default route) and validate it.
2. `bench`: catalog → engine → observations → `analysis` → ranked, selected servers.
3. Refuse if nothing is eligible (including "the whole network looks tampered with").
4. Show the plan; ask for confirmation unless `--yes` (refuse when non-interactive and no `--yes`).
5. `apply_dns`: write snapshot, set servers, read back, resolve a hostname, roll back on any failure.
