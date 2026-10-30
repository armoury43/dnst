"""Regression tests for issues found in adversarial/security review.

Each test class corresponds to one confirmed, reproduced problem:

* RecursionError bombs in state and catalog files (small input, deep nesting)
* unprivileged/pre-existing state directories being trusted silently
* FIFOs/devices being read as if they were catalog or state files
* unbounded subprocess output from the external probe engine (OOM risk)
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from dnstune import servers, state
from dnstune.errors import BackendError, ConfigError, EngineError
from dnstune.procio import BoundedRunError, run_bounded


def nested_json_bomb(depth: int) -> str:
    return "[" * depth + "]" * depth


def nested_toml_bomb(depth: int) -> str:
    return "schema_version = 1\n[[server]]\nlabel='x'\nprovider='x'\naddress='1.1.1.1'\nx = " + nested_json_bomb(
        depth
    )


class RecursionBombTests(unittest.TestCase):
    """A deeply nested but small document must not crash with RecursionError."""

    def test_state_file_recursion_bomb_within_size_cap(self) -> None:
        depth = 30000
        payload = nested_json_bomb(depth)
        self.assertLess(len(payload), state._MAX_STATE_BYTES)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / state.STATE_FILENAME).write_text(payload)
            with self.assertRaises(ConfigError):
                state.load_state(Path(tmp))

    def test_catalog_recursion_bomb_within_size_cap(self) -> None:
        payload = nested_toml_bomb(20000)
        self.assertLess(len(payload), servers.MAX_CATALOG_BYTES)
        with self.assertRaises(ConfigError):
            servers.parse_catalog(payload, source="bomb")

    def test_catalog_file_recursion_bomb(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bomb.toml"
            path.write_text(nested_toml_bomb(20000))
            with self.assertRaises(ConfigError):
                servers.load_file(path)


class PrivateDirectoryTests(unittest.TestCase):
    """dnstune must refuse to read/write state through an untrusted directory."""

    def sample(self) -> state.SavedState:
        return state.SavedState("eth0", ("1.1.1.1",), ("8.8.8.8",), "2026-01-01T00:00:00+00:00")

    def test_world_writable_directory_is_rejected_on_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "state"
            d.mkdir(mode=0o777)
            os.chmod(d, 0o777)
            with self.assertRaises(BackendError):
                state.save_state(self.sample(), d)
            # and nothing was written into the attacker-controlled directory
            self.assertEqual(list(d.iterdir()), [])

    def test_group_readable_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "state"
            d.mkdir(mode=0o750)
            os.chmod(d, 0o750)
            with self.assertRaises(BackendError):
                state.save_state(self.sample(), d)

    def test_directory_owned_by_someone_else_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "state"
            d.mkdir(mode=0o700)
            with mock.patch("os.geteuid", return_value=os.geteuid() + 12345):
                with self.assertRaises(BackendError):
                    state.save_state(self.sample(), d)

    def test_freshly_created_private_directory_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "nested" / "state"
            state.save_state(self.sample(), d)  # must not raise
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)

    def test_preexisting_correctly_permissioned_directory_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "state"
            d.mkdir(mode=0o700)
            state.save_state(self.sample(), d)
            self.assertEqual(state.load_state(d), self.sample())


class NonRegularFileTests(unittest.TestCase):
    def test_catalog_rejects_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "servers.toml"
            os.mkfifo(fifo)
            with self.assertRaises(ConfigError):
                servers.load_file(fifo)

    def test_state_rejects_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "state"
            d.mkdir(mode=0o700)
            os.mkfifo(d / state.STATE_FILENAME)
            with self.assertRaises(ConfigError):
                state.load_state(d)


class BoundedSubprocessTests(unittest.TestCase):
    """Direct tests of the run_bounded() primitive used by the Go engine adapter."""

    def test_normal_run(self) -> None:
        result = run_bounded([sys.executable, "-c", "print('hi')"], timeout=5, max_stdout=1024)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, b"hi"))

    def test_stdout_cap_kills_the_process(self) -> None:
        script = "import sys\nwhile True: sys.stdout.write('A' * 65536)"
        start = time.monotonic()
        with self.assertRaises(BoundedRunError):
            run_bounded([sys.executable, "-c", script], timeout=10, max_stdout=200_000)
        # must be stopped quickly by the size cap, not by the 10s timeout
        self.assertLess(time.monotonic() - start, 5.0)

    def test_stderr_cap_kills_the_process(self) -> None:
        script = "import sys\nwhile True: sys.stderr.write('A' * 65536)"
        with self.assertRaises(BoundedRunError):
            run_bounded([sys.executable, "-c", script], timeout=10, max_stdout=1024, max_stderr=50_000)

    def test_timeout_kills_a_silent_hang(self) -> None:
        start = time.monotonic()
        with self.assertRaises(BoundedRunError):
            run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.3, max_stdout=1024)
        self.assertLess(time.monotonic() - start, 5.0)

    def test_deadline_holds_when_child_writes_a_little_then_hangs(self) -> None:
        # Regression: reading with a buffered file.read(n) blocked until n bytes
        # or EOF, so a child that printed a few bytes and then hung ignored the
        # timeout entirely (20s instead of 0.5s in the original reproduction).
        script = "import sys, time\nprint('partial')\nsys.stdout.flush()\ntime.sleep(20)"
        start = time.monotonic()
        with self.assertRaises(BoundedRunError):
            run_bounded([sys.executable, "-c", script], timeout=0.5, max_stdout=1 << 20)
        self.assertLess(time.monotonic() - start, 5.0)

    def test_input_is_delivered(self) -> None:
        result = run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"],
            timeout=5,
            max_stdout=1024,
            input_bytes=b"hello",
        )
        self.assertEqual(result.stdout, b"HELLO")

    def test_child_that_ignores_stdin_does_not_hang(self) -> None:
        # A child that never reads stdin must not deadlock the parent on stdin.write().
        result = run_bounded(
            [sys.executable, "-c", "print('ok')"], timeout=5, max_stdout=1024, input_bytes=b"x" * (1 << 20)
        )
        self.assertEqual(result.stdout.strip(), b"ok")

    def test_nonexistent_program_raises_oserror(self) -> None:
        with self.assertRaises(OSError):
            run_bounded(["/nonexistent/definitely-not-a-binary"], timeout=1, max_stdout=1024)

    def test_env_replaces_child_environment(self) -> None:
        # Regression: an earlier revision built a restricted env dict for
        # resolvectl but never passed it to the subprocess, so the real PATH
        # leaked through silently. Confirm env= actually reaches the child.
        result = run_bounded(
            [sys.executable, "-c", "import os, sys; sys.stdout.write(os.environ.get('PATH', '<unset>'))"],
            timeout=5,
            max_stdout=1024,
            env={"PATH": "/only/this/path"},
        )
        self.assertEqual(result.stdout, b"/only/this/path")

    def test_env_none_inherits_parent_environment(self) -> None:
        with mock.patch.dict(os.environ, {"DNSTUNE_TEST_MARKER": "present"}):
            result = run_bounded(
                [sys.executable, "-c", "import os, sys; sys.stdout.write(os.environ.get('DNSTUNE_TEST_MARKER', ''))"],
                timeout=5,
                max_stdout=1024,
            )
        self.assertEqual(result.stdout, b"present")


class EngineFloodingIntegrationTest(unittest.TestCase):
    """End-to-end: a flooding engine binary must fail fast, not exhaust memory."""

    def test_flooding_engine_is_stopped_quickly(self) -> None:
        from dnstune.engine_ext import ExternalEngine
        from dnstune.models import ProbePlan, Server

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flood-engine"
            path.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                'if sys.argv[1:] == ["--version"]:\n'
                '    print("dnstune-probe 1 protocol=1")\n'
                "    sys.exit(0)\n"
                "while True:\n"
                "    sys.stdout.write('A' * 65536)\n"
            )
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

            engine = ExternalEngine(str(path))
            self.assertTrue(engine.handshake())
            start = time.monotonic()
            with self.assertRaises(EngineError):
                engine.run([Server("a", "a", "1.1.1.1")], ProbePlan(domains=("example.com",), queries=1, timeout=1.0))
            self.assertLess(time.monotonic() - start, 5.0)


if __name__ == "__main__":
    unittest.main()
