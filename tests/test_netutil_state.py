from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from dnstune import netutil, state
from dnstune.errors import BackendError, ConfigError

ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
    "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    "eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
)


class NetutilTests(unittest.TestCase):
    def test_default_interface_picks_lowest_metric(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "route"
            path.write_text(ROUTE)
            self.assertEqual(netutil.detect_default_interface(path), "eth0")

    def test_no_default_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "route"
            path.write_text(ROUTE.splitlines()[0] + "\n" + ROUTE.splitlines()[3] + "\ngarbage line\n")
            with self.assertRaises(BackendError):
                netutil.detect_default_interface(path)

    def test_unreadable_route_file(self) -> None:
        with self.assertRaises(BackendError):
            netutil.detect_default_interface(Path("/nonexistent/route"))

    def test_validate_interface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "eth0").mkdir()
            self.assertEqual(netutil.validate_interface("eth0", sys_class_net=root), "eth0")
            for bad in ["", "eth0\n", "eth0; rm -rf /", "../etc", "a" * 16, "-h", "..", "e th"]:
                with self.subTest(bad=bad), self.assertRaises(ConfigError):
                    netutil.validate_interface(bad, sys_class_net=root)
            with self.assertRaises(ConfigError):
                netutil.validate_interface("wlan9", sys_class_net=root)

    def test_dns_tokens(self) -> None:
        for good in ["1.1.1.1", "fe80::1%2", "1.1.1.1#cloudflare-dns.com", "[::1]:53", "2606:4700:4700::1111"]:
            self.assertTrue(netutil.valid_dns_token(good), good)
        for bad in ["", "-h", "--help", "1.1.1.1 8.8.8.8", "a;b", "$(x)", "1.1.1.1\n", "x" * 400]:
            self.assertFalse(netutil.valid_dns_token(bad), repr(bad))


class StateTests(unittest.TestCase):
    def sample(self) -> state.SavedState:
        return state.SavedState("eth0", ("192.168.1.1",), ("1.1.1.1", "8.8.8.8"), "2026-09-21T10:00:00+00:00")

    def test_roundtrip_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "nested" / "dnstune"
            path = state.save_state(self.sample(), directory)
            self.assertEqual(state.load_state(directory), self.sample())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual([p.name for p in directory.iterdir()], ["state.json"])  # no temp litter

    def test_overwrite_is_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            state.save_state(self.sample(), directory)
            newer = state.SavedState("eth0", (), ("9.9.9.9",), "2026-09-22T10:00:00+00:00")
            state.save_state(newer, directory)
            self.assertEqual(state.load_state(directory), newer)

    def test_missing_is_none_and_clear_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(state.load_state(Path(tmp)))
            state.clear_state(Path(tmp))
            state.save_state(self.sample(), Path(tmp))
            state.clear_state(Path(tmp))
            self.assertIsNone(state.load_state(Path(tmp)))

    def test_corrupt_or_hostile_state_is_rejected(self) -> None:
        good = {"schema": 1, "interface": "eth0", "previous": [], "applied": ["1.1.1.1"], "applied_at": "x"}
        cases = [
            "{not json",
            "[]",
            json.dumps({**good, "schema": 2}),
            json.dumps({**good, "interface": 5}),
            json.dumps({**good, "previous": ["--help"]}),
            json.dumps({**good, "applied": "1.1.1.1"}),
            json.dumps({**good, "applied": [1]}),
        ]
        for text in cases:
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "state.json").write_text(text)
                with self.assertRaises(ConfigError):
                    state.load_state(Path(tmp))

    def test_default_dir_respects_override(self) -> None:
        old = os.environ.get("DNSTUNE_STATE_DIR")
        os.environ["DNSTUNE_STATE_DIR"] = "/tmp/custom-dnstune"
        try:
            self.assertEqual(state.default_state_dir(), Path("/tmp/custom-dnstune"))
        finally:
            if old is None:
                del os.environ["DNSTUNE_STATE_DIR"]
            else:
                os.environ["DNSTUNE_STATE_DIR"] = old


if __name__ == "__main__":
    unittest.main()
