"""Run a subprocess while enforcing hard caps on wall time AND output size.

``subprocess.run(capture_output=True)`` buffers stdout/stderr without limit
until the process exits or the timeout fires -- a misbehaving or hostile
child can flood a pipe and exhaust the parent's memory long before any
timeout or "check the length afterwards" logic gets a chance to run. This
module reads incrementally and kills the child the moment either cap is hit,
so the most a bad child can cost us is ``max_bytes`` of memory.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from dataclasses import dataclass

_CHUNK = 65536
_KILL_GRACE = 2.0


class BoundedRunError(Exception):
    """Raised when a subprocess is killed for exceeding a time or size cap."""


@dataclass(frozen=True, slots=True)
class BoundedResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_bounded(
    argv: list[str],
    *,
    timeout: float,
    max_stdout: int,
    max_stderr: int = 65536,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
) -> BoundedResult:
    """Like ``subprocess.run``, but never buffers more than the given caps.

    Raises ``BoundedRunError`` if the deadline passes or either stream grows
    past its cap; the child is killed either way. Raises ``OSError`` if the
    program cannot even be started. ``env`` replaces the child's environment
    entirely, same as ``subprocess.run(..., env=...)``; pass ``None`` to
    inherit ours.
    """
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdout is not None and proc.stderr is not None
    deadline = time.monotonic() + timeout
    out = bytearray()
    err = bytearray()

    def fail(message: str) -> BoundedRunError:
        proc.kill()
        try:
            proc.wait(timeout=_KILL_GRACE)
        except subprocess.TimeoutExpired:
            pass
        return BoundedRunError(message)

    try:
        if input_bytes is not None:
            assert proc.stdin is not None
            try:
                proc.stdin.write(input_bytes)
            except BrokenPipeError:
                pass  # the child may exit early (e.g. bad arguments); its exit is diagnostic enough
            finally:
                proc.stdin.close()

        selector = selectors.DefaultSelector()
        selector.register(proc.stdout.fileno(), selectors.EVENT_READ, ("out", out, max_stdout))
        selector.register(proc.stderr.fileno(), selectors.EVENT_READ, ("err", err, max_stderr))
        open_streams = 2

        while open_streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise fail(f"subprocess timed out after {timeout:g}s")
            for key, _mask in selector.select(timeout=remaining):
                stream_name, buf, cap = key.data
                # os.read returns whatever is available right now. A buffered
                # file.read(n) would block until n bytes or EOF and could ignore
                # the deadline when a child writes a little and then hangs.
                chunk = os.read(key.fd, _CHUNK)
                if not chunk:
                    selector.unregister(key.fd)
                    open_streams -= 1
                    continue
                buf += chunk
                if len(buf) > cap:
                    raise fail(f"subprocess {stream_name} exceeded {cap} bytes")
        selector.close()

        remaining = max(0.0, deadline - time.monotonic())
        try:
            proc.wait(timeout=remaining or 0.001)
        except subprocess.TimeoutExpired as exc:
            raise fail(f"subprocess timed out after {timeout:g}s") from exc
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    return BoundedResult(returncode=proc.returncode, stdout=bytes(out), stderr=bytes(err))
