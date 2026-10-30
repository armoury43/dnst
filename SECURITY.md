# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub Security Advisories](https://github.com/YOUR-USERNAME/dnstune/security/advisories/new).
Include the version (`dnstune --version`), what you observed, and a minimal reproduction if you have one.
You can expect an acknowledgement within a few days and a fix or mitigation plan after triage.

Supported versions: the latest release only (pre-1.0).

## Threat model

dnstune handles untrusted data and, for `apply`/`revert`, runs with elevated privileges. These are the risks it is
designed against and how.

| Risk | Mitigation |
| --- | --- |
| Malicious or spoofed DNS responses crash or confuse the parser | Strict bounds-checked parser; compression pointers may only point backwards; jump limit; every field validated; randomized mutation tests; anything invalid raises a single exception type and is ignored |
| Off-path response spoofing | Random transaction id and a fresh random source port per query; connected UDP sockets so the kernel drops packets from other peers; question section and CNAME chain verified |
| Command injection through interface names or server addresses | No shell anywhere (enforced by a test); argv lists only; interface names validated against a strict pattern and `/sys/class/net`; addresses parsed with `ipaddress`; tokens can never start with `-` |
| `PATH` hijacking while running under `sudo` | `resolvectl` is located in fixed system directories only; subprocesses get a minimal environment |
| Malicious probe-engine binary | Only used if it passes a version handshake; when running as root it must be root-owned and not group/world-writable; its output is validated field by field and discarded on any anomaly |
| Tampered or corrupt state and catalog files, including deeply-nested "recursion bomb" documents that fit under the size cap | Size limits, strict schema validation, unknown keys rejected, non-regular files (FIFOs/devices) refused, `RecursionError` from pathological nesting caught and turned into a clean error |
| A local user pre-creating or loosening permissions on the (root-owned) state directory before dnstune first runs | The directory's owner and mode are checked on every read and write; anything not privately owned (mode 0700, owned by the running user) is refused outright, nothing is written into it |
| A misbehaving or hostile probe-engine binary flooding stdout/stderr to exhaust memory | All subprocess output (the probe engine and `resolvectl`) is read incrementally through a size- and time-capped reader that kills the child the instant either limit is hit, instead of buffering without bound |
| A resolver that lies (NXDOMAIN rewriting, injected private addresses) | Integrity probes disqualify such servers; if all responders look tampered with, dnstune refuses to change settings |
| Leaving the system without DNS | Snapshot before change, read-back, live resolution check, automatic rollback, runtime-only changes |

## Out of scope / known limitations

- Plain DNS over UDP/53 is unauthenticated and unencrypted. Anyone on the network path can observe or alter it.
  dnstune reduces exposure by choosing better resolvers and flagging obvious tampering, but it cannot fix the
  protocol. DNS-over-TLS is on the roadmap.
- Integrity checks detect common tampering (NXDOMAIN rewriting, private-address injection). A resolver that returns
  plausible but wrong *public* addresses cannot be detected by black-box probing.
- Benchmark queries reveal to each resolver that *you* are testing DNS (source IP) and which canary domains you
  chose. Use `--domains` and a custom `--servers` catalog if that matters to you.
- Anyone who already has root can do anything; dnstune does not try to defend against a compromised root account.
