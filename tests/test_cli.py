from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

from dnstune import __version__, cli
from dnstune.models import KIND_NX, KIND_POPULAR, Observation, ProbePlan, Server, ServerResult
from dnstune.resolved import ResolvedBackend

from .helpers import FakeResolvedRunner


def fake_results(servers: Sequence[Server], plan: ProbePlan, *, tampered: bool = False) -> list[ServerResult]:
    out = []
    for index, server in enumerate(servers):
        ip = "10.10.34.34" if tampered else "93.184.216.34"
        obs = [Observation(KIND_NX, "x.invalid", 3, 5.0)]
        obs += [Observation(KIND_POPULAR, "example.com", 0, 10.0 + index, (ip,)) for _ in range(plan.queries)]
        out.append(ServerResult(server, tuple(obs)))
    return out


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:  # argparse errors
            code = int(exc.code) if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


class CliBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_dir = Path(self._tmp.name) / "state"
        patcher = mock.patch.dict(os.environ, {"DNSTUNE_STATE_DIR": str(self.state_dir), "NO_COLOR": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def patch_engine(self, *, tampered: bool = False) -> None:
        def run(_self: object, servers: Sequence[Server], plan: ProbePlan) -> list[ServerResult]:
            return fake_results(servers, plan, tampered=tampered)

        for target in (
            mock.patch("dnstune.probe.PythonEngine.run", run),
            mock.patch("dnstune.bench.find_engine", return_value=None),
        ):
            target.start()
            self.addCleanup(target.stop)


class BasicCommandTests(CliBase):
    def test_version(self) -> None:
        code, out, _ = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

    def test_no_command_is_a_usage_error(self) -> None:
        self.assertEqual(run_cli()[0], 2)

    def test_list_table_and_json(self) -> None:
        code, out, _ = run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("1.1.1.1", out)
        code, out, _ = run_cli("list", "--json")
        doc = json.loads(out)
        self.assertEqual(doc["schema_version"], 1)
        self.assertTrue(any(s["address"] == "8.8.8.8" for s in doc["servers"]))

    def test_bad_arguments(self) -> None:
        for argv in (["bench", "--queries", "0"], ["bench", "--timeout", "abc"], ["bench", "--engine", "rust"]):
            with self.subTest(argv=argv):
                self.assertEqual(run_cli(*argv)[0], 2)

    def test_bad_catalog_and_domains_exit_2(self) -> None:
        code, _, err = run_cli("bench", "--servers", "/nonexistent.toml")
        self.assertEqual(code, 2)
        self.assertIn("error:", err)
        self.patch_engine()
        self.assertEqual(run_cli("bench", "--domains", "bad name")[0], 2)


class BenchTests(CliBase):
    def test_bench_table(self) -> None:
        self.patch_engine()
        code, out, _ = run_cli("bench", "--queries", "3")
        self.assertEqual(code, 0)
        self.assertIn("selected", out)
        self.assertIn("engine: python", out)
        self.assertNotIn("\x1b[", out)  # NO_COLOR respected

    def test_bench_json(self) -> None:
        self.patch_engine()
        code, out, _ = run_cli("bench", "--json", "--count", "3")
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(len(doc["selected"]), 3)
        self.assertEqual(doc["engine"], "python")
        self.assertTrue(all(not r["filtering"] for r in doc["results"]))

    def test_include_filtering_adds_servers(self) -> None:
        self.patch_engine()
        _, plain, _ = run_cli("bench", "--json")
        _, more, _ = run_cli("bench", "--json", "--include-filtering")
        self.assertGreater(len(json.loads(more)["results"]), len(json.loads(plain)["results"]))

    def test_best_prints_addresses(self) -> None:
        self.patch_engine()
        code, out, _ = run_cli("best")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.split()), 2)

    def test_best_exits_4_on_tampered_network(self) -> None:
        self.patch_engine(tampered=True)
        code, _, err = run_cli("best")
        self.assertEqual(code, 4)
        self.assertIn("intercepting", err)


class ApplyRevertTests(CliBase):
    def setUp(self) -> None:
        super().setUp()
        self.runner = FakeResolvedRunner({"lo": ["192.168.1.1"]})
        backend = ResolvedBackend(self.runner, executable="/usr/bin/resolvectl")
        patcher = mock.patch("dnstune.cli.ResolvedBackend", return_value=backend)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("dnstune.apply.time.sleep", lambda _s: None)  # retries must not slow tests
        patcher.start()
        self.addCleanup(patcher.stop)
        self.patch_engine()

    def test_dry_run_changes_nothing(self) -> None:
        code, out, _ = run_cli("apply", "--interface", "lo", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("dry run", out)
        self.assertEqual(self.runner.dns["lo"], ["192.168.1.1"])
        self.assertFalse(self.state_dir.exists())

    def test_apply_then_status_then_revert(self) -> None:
        code, out, _ = run_cli("apply", "--interface", "lo", "--yes")
        self.assertEqual(code, 0, out)
        self.assertNotEqual(self.runner.dns["lo"], ["192.168.1.1"])
        self.assertEqual(len(self.runner.dns["lo"]), 2)
        code, out, _ = run_cli("status", "--interface", "lo")
        self.assertIn("applied", out)
        code, out, _ = run_cli("revert")
        self.assertEqual(code, 0)
        self.assertEqual(self.runner.dns["lo"], ["192.168.1.1"])

    def test_status_hints_at_root_state_for_normal_users(self) -> None:
        with mock.patch("dnstune.cli._root_state_may_exist", return_value=True):
            code, out, _ = run_cli("status", "--interface", "lo")
        self.assertEqual(code, 0)
        self.assertIn("sudo dnstune status", out)
        self.assertNotIn("no saved changes", out)

    def test_status_plain_when_no_state_anywhere(self) -> None:
        with mock.patch("dnstune.cli._root_state_may_exist", return_value=False):
            _, out, _ = run_cli("status", "--interface", "lo")
        self.assertIn("no saved changes", out)

    def test_non_interactive_apply_requires_yes(self) -> None:
        with mock.patch("sys.stdin", io.StringIO("")):
            code, _, err = run_cli("apply", "--interface", "lo")
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        self.assertEqual(self.runner.dns["lo"], ["192.168.1.1"])

    def test_interactive_decline(self) -> None:
        with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", return_value="n"):
            code, out, _ = run_cli("apply", "--interface", "lo")
        self.assertEqual(code, 0)
        self.assertIn("nothing was changed", out)
        self.assertEqual(self.runner.dns["lo"], ["192.168.1.1"])

    def test_verification_failure_exit_5_and_rollback(self) -> None:
        self.runner.query_results = [False] * 10
        code, _, err = run_cli("apply", "--interface", "lo", "--yes")
        self.assertEqual(code, 5)
        self.assertIn("restored", err)
        self.assertEqual(self.runner.dns["lo"], ["192.168.1.1"])

    def test_apply_refuses_on_tampered_network(self) -> None:
        self.patch_engine(tampered=True)
        code, _, _ = run_cli("apply", "--interface", "lo", "--yes")
        self.assertEqual(code, 4)
        self.assertEqual(self.runner.dns["lo"], ["192.168.1.1"])

    def test_bad_interface_is_rejected_before_anything_runs(self) -> None:
        code, _, err = run_cli("apply", "--interface", "eth0; reboot", "--yes")
        self.assertEqual(code, 2)
        self.assertNotIn(["dns", "eth0; reboot"], self.runner.calls)
        self.assertIn("invalid interface", err)

    def test_no_resolved_gives_exit_3(self) -> None:
        dead = ResolvedBackend(lambda a, t: __import__("subprocess").CompletedProcess(a, 1, "", ""), executable="/x")
        with mock.patch("dnstune.cli.ResolvedBackend", return_value=dead):
            code, _, err = run_cli("apply", "--interface", "lo", "--yes")
        self.assertEqual(code, 3)
        self.assertIn("systemd-resolved", err)


if __name__ == "__main__":
    unittest.main()
