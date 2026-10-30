from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from dnstune import engine_ext
from dnstune.bench import run_bench
from dnstune.errors import ConfigError, EngineError
from dnstune.models import ProbePlan, Server

SERVERS = [Server("A", "a", "192.0.2.1"), Server("B", "b", "192.0.2.2")]
PLAN = ProbePlan(domains=("example.com",), queries=2, timeout=0.5)


def valid_doc(servers: list[Server] = SERVERS) -> dict:  # type: ignore[type-arg]
    return {
        "protocol": 1,
        "results": [
            {
                "server": s.address,
                "observations": [
                    {"kind": "nxprobe", "domain": "x.invalid", "rcode": 3, "latency_ms": 5.5, "addresses": [], "error": ""},
                    {"kind": "popular", "domain": "example.com", "rcode": 0, "latency_ms": 12.0,
                     "addresses": ["93.184.216.34"], "error": ""},
                    {"kind": "popular", "domain": "example.com", "rcode": None, "latency_ms": None,
                     "addresses": [], "error": "timeout"},
                ],
            }
            for s in servers
        ],
    }


class ParseTests(unittest.TestCase):
    def parse(self, doc: object) -> list:  # type: ignore[type-arg]
        return engine_ext.parse_engine_output(json.dumps(doc), SERVERS, PLAN)

    def test_valid(self) -> None:
        results = self.parse(valid_doc())
        self.assertEqual([r.server.address for r in results], ["192.0.2.1", "192.0.2.2"])
        obs = results[0].observations
        self.assertEqual((obs[1].rcode, obs[1].latency_ms, obs[1].addresses), (0, 12.0, ("93.184.216.34",)))
        self.assertEqual((obs[2].rcode, obs[2].error), (None, "timeout"))
        self.assertIsNone(obs[0].error)

    def test_rejects_garbage(self) -> None:
        bad_docs: list[object] = [
            [], {"protocol": 2, "results": []}, {"protocol": 1}, {"protocol": 1, "results": []},
        ]
        doc = valid_doc()
        doc["results"][0]["server"] = "203.0.113.1"
        bad_docs.append(doc)
        observation_mutations: list[tuple[int, str, object]] = [
            (0, "kind", "evil"),
            (1, "rcode", 99),
            (1, "rcode", True),
            (1, "latency_ms", -1),
            (1, "latency_ms", "fast"),
            (1, "addresses", ["not-an-ip"]),
            (1, "addresses", ["1.1.1.1"] * 100),
            (1, "error", "x" * 200),
        ]
        for index, key, value in observation_mutations:
            doc = valid_doc()
            doc["results"][0]["observations"][index][key] = value
            bad_docs.append(doc)
        doc = valid_doc()
        doc["results"][0]["observations"] = doc["results"][0]["observations"] * 3
        bad_docs.append(doc)
        for doc in bad_docs:
            with self.subTest(doc=str(doc)[:80]), self.assertRaises(EngineError):
                self.parse(doc)
        with self.assertRaises(EngineError):
            engine_ext.parse_engine_output("{nope", SERVERS, PLAN)


def write_engine(directory: Path, body: str) -> str:
    path = directory / "dnstune-probe"
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


GOOD_ENGINE = """
import json, sys
if sys.argv[1:] == ["--version"]:
    print("dnstune-probe 9.9.9 protocol=1"); sys.exit(0)
job = json.load(sys.stdin)
out = {"protocol": 1, "results": [
    {"server": s, "observations": [
        {"kind": "nxprobe", "domain": "x.invalid", "rcode": 3, "latency_ms": 4.0, "addresses": [], "error": ""},
        {"kind": "popular", "domain": "example.com", "rcode": 0, "latency_ms": 9.0, "addresses": ["93.184.216.34"], "error": ""},
        {"kind": "popular", "domain": "example.com", "rcode": 0, "latency_ms": 11.0, "addresses": ["93.184.216.34"], "error": ""},
    ]} for s in job["servers"]]}
json.dump(out, sys.stdout)
"""


class ExternalEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def env(self, path: str) -> mock._patch_dict:  # type: ignore[type-arg]
        return mock.patch.dict(os.environ, {engine_ext.ENGINE_ENV: path})

    def test_handshake_and_run(self) -> None:
        path = write_engine(self.dir, GOOD_ENGINE)
        with self.env(path):
            engine = engine_ext.find_engine()
        assert engine is not None
        results = engine.run(SERVERS, PLAN)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].observations[1].latency_ms, 9.0)

    def test_wrong_protocol_is_ignored(self) -> None:
        path = write_engine(self.dir, 'print("dnstune-probe 1.0 protocol=99")')
        with self.env(path):
            self.assertIsNone(engine_ext.find_engine())

    def test_not_an_engine_is_ignored(self) -> None:
        path = write_engine(self.dir, 'print("hello")')
        with self.env(path):
            self.assertIsNone(engine_ext.find_engine())

    def test_missing_engine(self) -> None:
        with self.env(str(self.dir / "does-not-exist")):
            self.assertIsNone(engine_ext.find_engine())

    def test_engine_crash_raises_engine_error(self) -> None:
        path = write_engine(self.dir, 'import sys\nif sys.argv[1:] == ["--version"]:\n    print("dnstune-probe 1 protocol=1")\nelse:\n    sys.stderr.write("boom\\n"); sys.exit(3)')
        engine = engine_ext.ExternalEngine(path)
        with self.assertRaises(EngineError):
            engine.run(SERVERS, PLAN)

    def test_engine_hostile_output_raises_engine_error(self) -> None:
        path = write_engine(self.dir, 'import sys\nif sys.argv[1:] == ["--version"]:\n    print("dnstune-probe 1 protocol=1")\nelse:\n    print("{}")')
        with self.assertRaises(EngineError):
            engine_ext.ExternalEngine(path).run(SERVERS, PLAN)


class BenchEngineSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_auto_uses_go_engine_when_present(self) -> None:
        path = write_engine(self.dir, GOOD_ENGINE)
        with mock.patch.dict(os.environ, {engine_ext.ENGINE_ENV: path}):
            outcome = run_bench(SERVERS, PLAN, engine_choice="auto")
        self.assertEqual(outcome.engine, "go")
        self.assertEqual(len(outcome.selected), 2)

    def test_auto_falls_back_to_python_when_engine_breaks(self) -> None:
        body = 'import sys\nif sys.argv[1:] == ["--version"]:\n    print("dnstune-probe 1 protocol=1")\nelse:\n    print("nonsense")'
        path = write_engine(self.dir, body)
        plan = ProbePlan(domains=("example.com",), queries=1, timeout=0.2)
        with mock.patch.dict(os.environ, {engine_ext.ENGINE_ENV: path}):
            outcome = run_bench([Server("L", "l", "127.0.0.1", port=1)], plan, engine_choice="auto")
        self.assertEqual(outcome.engine, "python")
        self.assertTrue(any("Go engine failed" in w for w in outcome.warnings))

    def test_explicit_go_without_engine_is_an_error(self) -> None:
        with mock.patch.dict(os.environ, {engine_ext.ENGINE_ENV: "/nonexistent/x"}):
            with self.assertRaises(ConfigError):
                run_bench(SERVERS, PLAN, engine_choice="go")

    def test_explicit_go_with_broken_engine_is_an_error(self) -> None:
        body = 'import sys\nif sys.argv[1:] == ["--version"]:\n    print("dnstune-probe 1 protocol=1")\nelse:\n    print("nonsense")'
        path = write_engine(self.dir, body)
        with mock.patch.dict(os.environ, {engine_ext.ENGINE_ENV: path}):
            with self.assertRaises(EngineError):
                run_bench(SERVERS, PLAN, engine_choice="go")

    def test_no_servers(self) -> None:
        with self.assertRaises(ConfigError):
            run_bench([], PLAN)


if __name__ == "__main__":
    unittest.main()
