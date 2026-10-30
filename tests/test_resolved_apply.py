from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dnstune import state
from dnstune.apply import apply_dns, revert_dns
from dnstune.errors import BackendError, ConfigError, VerificationError
from dnstune.resolved import ResolvedBackend

from .helpers import FakeResolvedRunner, completed

EXE = "/usr/bin/resolvectl"
NEW = ["1.1.1.1", "8.8.8.8"]


def make(runner: FakeResolvedRunner) -> ResolvedBackend:
    return ResolvedBackend(runner, executable=EXE)


def no_sleep(_: float) -> None:
    return None


class BackendTests(unittest.TestCase):
    def test_get_dns_parsing(self) -> None:
        runner = FakeResolvedRunner({"eth0": ["192.168.1.1", "fe80::1%2", "1.1.1.1#one.one.one.one"], "lo": []})
        backend = make(runner)
        self.assertEqual(backend.get_dns("eth0"), ["192.168.1.1", "fe80::1%2", "1.1.1.1#one.one.one.one"])
        self.assertEqual(backend.get_dns("lo"), [])

    def test_unparseable_output_is_an_error(self) -> None:
        backend = ResolvedBackend(lambda argv, t: completed(0, "Link 2 (eth0): --evil\n"), executable=EXE)
        with self.assertRaises(BackendError):
            backend.get_dns("eth0")
        backend = ResolvedBackend(lambda argv, t: completed(0, "something else entirely\n"), executable=EXE)
        with self.assertRaises(BackendError):
            backend.get_dns("eth0")

    def test_set_dns_issues_expected_commands(self) -> None:
        runner = FakeResolvedRunner()
        make(runner).set_dns("eth0", NEW)
        self.assertEqual(runner.calls[0], ["dns", "eth0", *NEW])
        self.assertEqual(runner.calls[1], ["flush-caches"])

    def test_set_dns_rejects_bad_input(self) -> None:
        backend = make(FakeResolvedRunner())
        with self.assertRaises(BackendError):
            backend.set_dns("eth0", [])
        with self.assertRaises(BackendError):
            backend.set_dns("eth0", ["--help"])

    def test_access_denied_suggests_sudo(self) -> None:
        runner = FakeResolvedRunner()
        runner.fail_all_sets = True
        with self.assertRaises(BackendError) as ctx:
            make(runner).set_dns("eth0", NEW)
        self.assertIn("sudo", str(ctx.exception))

    def test_available(self) -> None:
        self.assertTrue(make(FakeResolvedRunner()).available())
        self.assertFalse(ResolvedBackend(lambda a, t: completed(1), executable=EXE).available())

    def test_missing_binary(self) -> None:
        backend = ResolvedBackend(FakeResolvedRunner(), executable=None)
        backend._exe = None  # simulate "not installed" regardless of the test machine
        self.assertFalse(backend.available())
        with self.assertRaises(BackendError):
            backend.get_dns("eth0")

    def test_flush_failure_is_not_fatal(self) -> None:
        def runner(argv, timeout):  # type: ignore[no-untyped-def]
            return completed(1, "", "boom") if argv[1] == "flush-caches" else completed(0)

        ResolvedBackend(runner, executable=EXE).flush_caches()


class ApplyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def apply(self, runner: FakeResolvedRunner):  # type: ignore[no-untyped-def]
        return apply_dns(
            make(runner), interface="eth0", servers=NEW, state_dir=self.dir,
            verify_hostname="example.com", attempts=3, delay=0, sleep=no_sleep,
        )

    def test_success(self) -> None:
        runner = FakeResolvedRunner()
        report = self.apply(runner)
        self.assertEqual(runner.dns["eth0"], NEW)
        self.assertEqual(report.previous, ("192.168.1.1",))
        saved = state.load_state(self.dir)
        assert saved is not None
        self.assertEqual((saved.previous, saved.applied), (("192.168.1.1",), tuple(NEW)))

    def test_verification_failure_rolls_back(self) -> None:
        runner = FakeResolvedRunner()
        runner.query_results = [False, False, False]
        with self.assertRaises(VerificationError) as ctx:
            self.apply(runner)
        self.assertIn("restored", str(ctx.exception))
        self.assertEqual(runner.dns["eth0"], ["192.168.1.1"])
        self.assertIsNone(state.load_state(self.dir))

    def test_transient_resolution_failure_is_retried(self) -> None:
        runner = FakeResolvedRunner()
        runner.query_results = [False, True]
        self.apply(runner)
        self.assertEqual(runner.dns["eth0"], NEW)

    def test_resolved_ignoring_our_change_rolls_back(self) -> None:
        runner = FakeResolvedRunner()
        runner.ignore_set = True
        with self.assertRaises(VerificationError):
            self.apply(runner)
        self.assertEqual(runner.dns["eth0"], ["192.168.1.1"])

    def test_set_failure_restores_previous(self) -> None:
        runner = FakeResolvedRunner()
        runner.fail_set_times = 1  # the apply fails, the rollback succeeds
        with self.assertRaises(BackendError) as ctx:
            self.apply(runner)
        self.assertIn("restored", str(ctx.exception))
        self.assertEqual(runner.dns["eth0"], ["192.168.1.1"])

    def test_failed_rollback_gives_manual_instructions(self) -> None:
        runner = FakeResolvedRunner()
        runner.fail_all_sets = True
        with self.assertRaises(BackendError) as ctx:
            self.apply(runner)
        self.assertIn("resolvectl revert eth0", str(ctx.exception))
        self.assertIsNotNone(state.load_state(self.dir))  # snapshot kept for a later revert

    def test_reapply_keeps_original_snapshot(self) -> None:
        runner = FakeResolvedRunner()
        self.apply(runner)
        apply_dns(make(runner), interface="eth0", servers=["9.9.9.10"], state_dir=self.dir,
                  verify_hostname="example.com", attempts=1, delay=0, sleep=no_sleep)
        saved = state.load_state(self.dir)
        assert saved is not None
        self.assertEqual(saved.previous, ("192.168.1.1",))
        self.assertEqual(saved.applied, ("9.9.9.10",))

    def test_new_snapshot_when_network_reset_our_change(self) -> None:
        runner = FakeResolvedRunner()
        self.apply(runner)
        runner.dns["eth0"] = ["10.0.0.1"]  # e.g. NetworkManager reconnected with new DHCP DNS
        self.apply(runner)
        saved = state.load_state(self.dir)
        assert saved is not None
        self.assertEqual(saved.previous, ("10.0.0.1",))

    def test_empty_server_list(self) -> None:
        with self.assertRaises(ConfigError):
            apply_dns(make(FakeResolvedRunner()), interface="eth0", servers=[], state_dir=self.dir,
                      verify_hostname="example.com")


class RevertTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_revert_restores_previous_servers(self) -> None:
        runner = FakeResolvedRunner()
        apply_dns(make(runner), interface="eth0", servers=NEW, state_dir=self.dir,
                  verify_hostname="example.com", sleep=no_sleep)
        name, restored = revert_dns(make(runner), state_dir=self.dir, interface=None)
        self.assertEqual((name, restored), ("eth0", ("192.168.1.1",)))
        self.assertEqual(runner.dns["eth0"], ["192.168.1.1"])
        self.assertIsNone(state.load_state(self.dir))

    def test_revert_with_empty_previous_uses_resolvectl_revert(self) -> None:
        runner = FakeResolvedRunner({"eth0": []})
        apply_dns(make(runner), interface="eth0", servers=NEW, state_dir=self.dir,
                  verify_hostname="example.com", sleep=no_sleep)
        revert_dns(make(runner), state_dir=self.dir, interface=None)
        self.assertIn(["revert", "eth0"], runner.calls)
        self.assertEqual(runner.dns["eth0"], [])

    def test_revert_without_state(self) -> None:
        runner = FakeResolvedRunner()
        with self.assertRaises(ConfigError):
            revert_dns(make(runner), state_dir=self.dir, interface=None)
        self.assertEqual(revert_dns(make(runner), state_dir=self.dir, interface="eth0"), ("eth0", ()))
        self.assertIn(["revert", "eth0"], runner.calls)

    def test_revert_interface_mismatch(self) -> None:
        runner = FakeResolvedRunner()
        apply_dns(make(runner), interface="eth0", servers=NEW, state_dir=self.dir,
                  verify_hostname="example.com", sleep=no_sleep)
        with self.assertRaises(ConfigError):
            revert_dns(make(runner), state_dir=self.dir, interface="wlan0")


if __name__ == "__main__":
    unittest.main()
