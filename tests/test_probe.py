from __future__ import annotations

import unittest

from dnstune.models import KIND_NX, KIND_POPULAR, ProbePlan, Server
from dnstune.probe import PythonEngine, probe_once, probe_server

from .helpers import FakeDnsServer, build_response, closed_udp_port, normal_handler


def local(port: int, label: str = "fake") -> Server:
    return Server(label=label, provider=label, address="127.0.0.1", port=port)


class ProbeOnceTests(unittest.TestCase):
    def test_success(self) -> None:
        with FakeDnsServer(normal_handler) as srv:
            obs = probe_once(local(srv.port), "example.com", KIND_POPULAR, 1.0)
        self.assertEqual(obs.rcode, 0)
        self.assertEqual(obs.addresses, ("93.184.216.34",))
        self.assertIsNotNone(obs.latency_ms)
        self.assertIsNone(obs.error)

    def test_timeout(self) -> None:
        with FakeDnsServer(lambda q: []) as srv:
            obs = probe_once(local(srv.port), "example.com", KIND_POPULAR, 0.2)
        self.assertEqual((obs.rcode, obs.error), (None, "timeout"))

    def test_refused_port(self) -> None:
        obs = probe_once(local(closed_udp_port()), "example.com", KIND_POPULAR, 0.5)
        self.assertEqual(obs.error, "refused")

    def test_spoofed_packets_are_ignored_until_real_answer(self) -> None:
        def handler(query: bytes) -> list[bytes]:
            wrong_id = build_response(query, addrs=["6.6.6.6"], txid=0)
            wrong_id = wrong_id[:0] + bytes([wrong_id[0] ^ 0xFF]) + wrong_id[1:]
            return [b"garbage", wrong_id, build_response(query, addrs=["1.2.3.4"])]

        with FakeDnsServer(handler) as srv:
            obs = probe_once(local(srv.port), "example.com", KIND_POPULAR, 1.0)
        self.assertEqual(obs.addresses, ("1.2.3.4",))

    def test_only_garbage_reports_malformed(self) -> None:
        with FakeDnsServer(lambda q: [b"\x00" * 5]) as srv:
            obs = probe_once(local(srv.port), "example.com", KIND_POPULAR, 0.3)
        self.assertEqual((obs.rcode, obs.error), (None, "malformed"))

    def test_invalid_name_is_reported_not_raised(self) -> None:
        obs = probe_once(local(1), "bad name.com", KIND_POPULAR, 0.2)
        self.assertEqual(obs.error, "invalid-name")


class ProbeServerTests(unittest.TestCase):
    def test_plan_shape(self) -> None:
        plan = ProbePlan(domains=("example.com", "python.org"), queries=5, timeout=0.5)
        with FakeDnsServer(normal_handler) as srv:
            result = probe_server(local(srv.port), plan)
        kinds = [o.kind for o in result.observations]
        self.assertEqual(kinds, [KIND_NX] + [KIND_POPULAR] * 5)
        self.assertEqual(result.observations[0].rcode, 3)
        self.assertTrue(result.observations[0].domain.endswith(".invalid"))
        self.assertEqual(
            [o.domain for o in result.observations[1:]],
            ["example.com", "python.org", "example.com", "python.org", "example.com"],
        )


class EngineTests(unittest.TestCase):
    def test_runs_servers_in_order_and_in_parallel(self) -> None:
        plan = ProbePlan(domains=("example.com",), queries=2, timeout=0.5, workers=4)
        with FakeDnsServer(normal_handler) as a, FakeDnsServer(lambda q: []) as b:
            results = PythonEngine().run([local(a.port, "a"), local(b.port, "b")], plan)
        self.assertEqual([r.server.label for r in results], ["a", "b"])
        self.assertEqual(results[0].observations[1].rcode, 0)
        self.assertEqual(results[1].observations[1].error, "timeout")

    def test_empty(self) -> None:
        self.assertEqual(PythonEngine().run([], ProbePlan(domains=("example.com",))), [])


if __name__ == "__main__":
    unittest.main()
