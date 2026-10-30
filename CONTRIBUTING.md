# Contributing

Thanks for helping! dnstune has a strong bias toward **staying small, stable and safe**, so a few ground rules.

## Ground rules

1. **No new runtime dependencies.** The standard library is enough. Dev-only tools are fine.
2. **Everything from outside is untrusted**: packets, files, subprocess output, engine output. Validate it.
3. **No shell.** Never `shell=True`; pass argv lists. `tests/test_hygiene.py` enforces this.
4. **Every behaviour change needs a test**, and every bug fix needs a regression test.
5. **Keep judging in Python.** Engines measure; `analysis.py` decides.

## Setup

```bash
git clone https://github.com/YOUR-USERNAME/dnstune.git && cd dnstune
python -m venv .venv && . .venv/bin/activate
make install-dev
pre-commit install        # optional but recommended
```

## Before opening a pull request

```bash
make fmt      # ruff format + gofmt
make check    # ruff, mypy --strict, pytest, go vet, go test -race
```

The Go engine needs Go 1.21+ (`make go-test`). Python tests do not need it.

## Commit and PR style

- Small, focused pull requests; describe *why*, not just *what*.
- Update `CHANGELOG.md` under **Unreleased**.
- Changes to parsing, subprocess use or privileges: mention how they were reviewed against `SECURITY.md`.

## Adding a resolver to the built-in catalog

Only long-established, publicly documented resolvers with stable addresses. Include the operator's documentation
link in the pull request, set `filtering = true` if the resolver blocks anything by default, and use the operator's
name as `provider` so fallback selection can tell providers apart.

## Adding a backend (NetworkManager, resolv.conf, ...)

Implement the same small interface as `ResolvedBackend` (`available`, `get_dns`, `set_dns`, `restore`,
`revert_link`, `can_resolve`) with an injectable command runner, and test it with a fake runner like
`tests/helpers.py::FakeResolvedRunner`. Snapshot-first and rollback-on-failure are not optional.
