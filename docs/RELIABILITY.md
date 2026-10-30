# Reliability design

The goal: a tool that keeps working, unchanged, a year from now, and can never leave a machine without DNS.

## Nothing upstream can break it

- **Zero runtime dependencies.** Python standard library only (`tomllib` needs Python 3.11+). No dependency releases,
  yanks or supply-chain surprises. Dev tools are only needed to work *on* dnstune.
- **Go engine uses the standard library only** and is optional.
- **The catalog holds only long-established public resolvers.** Regional or private ones live in user files, so the
  built-in list cannot rot.
- **Probe domains are boring on purpose** (`example.com`, `kernel.org`, `debian.org`, ...).
- **Versioned contracts.** JSON output has `schema_version`; the engine protocol has `protocol`; catalog and state
  files have schema numbers. Incompatible files are rejected with a clear error instead of being half-understood.

## It cannot leave you without DNS

- `apply` writes a **snapshot to disk before changing anything**, so even a crash or power cut mid-way is recoverable
  with `dnstune revert`.
- After setting servers it **reads them back** and **resolves a real hostname** through the system resolver. Any
  failure triggers an immediate rollback to the snapshot.
- Changes are **runtime-only** (`resolvectl dns`). A reboot or network reconnect restores the system's own settings.
- If the automatic rollback itself fails, the error message includes the exact manual command.
- Re-applying keeps the *original* snapshot, and a fresh snapshot is taken if the network already reset our change.
- The tool refuses to act when the whole network looks like it is tampering with DNS, and when run non-interactively
  without `--yes`.

## It behaves the same under stress

- One socket per query, one worker per server, bounded thread pool: no unbounded resources.
- Every wait has a timeout; every subprocess has a timeout; output sizes are capped.
- A crash inside one probe is recorded as an observation and never aborts the run.
- If the Go engine is missing, slow, outdated or returns anything unexpected, the Python engine takes over.
- Output is safe to pipe into `head`, `jq` and friends (broken pipes are handled, colours honour `NO_COLOR` and TTY).

## How the code stays that way

- Strict `mypy`, `ruff`, and a test suite covering the parser (including randomized mutation and truncation tests),
  scoring, apply/rollback flows, state files, engine adapter and CLI.
- A dedicated adversarial-review test file (`tests/test_security_hardening.py`) that reproduces every issue found
  during a security pass: recursion-bomb catalog/state files, pre-existing world-writable state directories, FIFOs
  used as regular files, and a hostile engine binary flooding output to exhaust memory. Every fix has a regression
  test that fails loudly if it is ever undone.
- `tests/test_hygiene.py` fails the build if code introduces `shell=True`, `eval`/`exec`, `pickle`, third-party
  runtime imports, or a regex `$` anchor that would accept a trailing newline.
- CI runs on Python 3.11, 3.12 and 3.13, runs the Go tests with the race detector, and exercises both engines together.
