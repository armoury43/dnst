# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behaviour).

## [Unreleased]

### Fixed
- The bounded subprocess reader could overrun its time limit when a child wrote a little output and then hung (it used a blocking buffered read). It now reads with `os.read`, so the deadline always holds.
- Test-suite lint errors (E702) fixed.
- `dnstune status` run as a normal user no longer claims "no saved changes" when the change was applied with `sudo` (that state lives in a root-only directory); it now points to `sudo dnstune status`.

### Security
- Catalog and state-file parsing no longer crashes with an uncaught `RecursionError` on small, pathologically
  nested input (a "recursion bomb" that fits well under the existing size caps).
- The state directory's ownership and permissions are now checked before every read and write; a pre-existing
  directory that is not privately owned (mode 0700, owned by the running user) is refused instead of trusted.
- Catalog and state files that are not regular files (FIFOs, devices) are rejected instead of being read, which
  could previously hang indefinitely.
- All subprocess output (the optional Go probe engine and `resolvectl`) is now read through a size- and
  time-capped reader; a misbehaving or hostile binary that floods stdout/stderr is killed immediately instead of
  being buffered without bound (previously this could exhaust the host's memory).
- Fixed a bug, introduced while hardening `resolvectl` calls, where the restricted subprocess environment
  (`PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `LANG=C`, `LC_ALL=C`) was constructed but never actually passed to the
  child process. Added a regression test that runs the real subprocess path to catch this class of bug.

## [0.1.0]

### Added
- Resolver catalog with provider grouping and an explicit `filtering` flag; bring-your-own catalogs via TOML.
- `dnstune list | bench | best | apply | revert | status` with `--json` output and stable exit codes.
- Integrity checks: NXDOMAIN-hijack detection (`.invalid` probe) and private/reserved-address detection.
- Scoring by median latency, failure rate and jitter; provider-diverse fallback selection.
- Safe apply on systemd-resolved: snapshot first, read-back, live resolution check, automatic rollback, `revert`.
- Strict, zero-dependency DNS wire parser; pure-Python probe engine.
- Optional static Go probe engine with a versioned JSON protocol and automatic fallback.
- CI for Python 3.11-3.13 and Go, release workflow building static binaries with checksums.

[Unreleased]: https://github.com/YOUR-USERNAME/dnstune/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YOUR-USERNAME/dnstune/releases/tag/v0.1.0
