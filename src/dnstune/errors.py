"""Exception hierarchy. Every expected failure maps to a stable exit code."""

from __future__ import annotations


class DnstuneError(Exception):
    """Base class for all expected, user-facing errors."""

    exit_code = 1


class ConfigError(DnstuneError):
    """Invalid user input: flags, catalog files, state files."""

    exit_code = 2


class BackendError(DnstuneError):
    """The system DNS backend is missing, refused a change, or misbehaved."""

    exit_code = 3


class NoEligibleServerError(DnstuneError):
    """No server passed the reliability and integrity checks."""

    exit_code = 4


class VerificationError(DnstuneError):
    """A change was applied but verification failed; it was rolled back."""

    exit_code = 5


class EngineError(DnstuneError):
    """The optional external probe engine failed or produced invalid output."""

    exit_code = 1


class DNSFormatError(DnstuneError):
    """A DNS packet is malformed or does not match the query."""

    exit_code = 1
