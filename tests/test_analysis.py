from __future__ import annotations

import unittest

from dnstune import analysis
from dnstune.models import KIND_NX, KIND_POPULAR, Observation, Server, ServerResult


def server(addr: str, provider: str = "p") -> Server:
    return Server(label=addr, provider=provider, address=addr)


def good(ms: float, addrs: tuple[str, ...] = ("93.184.216.34",)) -> Observation:
    return Observation(KIND_POPULAR, "example.com", 0, ms, addrs)


def bad() -> Observation:
    return Observation(KIND_POPULAR, "example.com", None, None, error="timeout")


NX_OK = Observation(KIND_NX, "x.invalid", 3, 10.0)


def stats(addr: str, obs: list[Observation], provider: str = "p") -> analysis.ServerStats:
    return analysis.analyse(ServerResult(server(addr, provider), tuple([NX_OK, *obs])))


class AnalyseTests(unittest.TestCase):
    def test_clean_server(self) -> None:
        s = stats("1.1.1.1", [good(10), good(20), good(30)])
        self.assertTrue(s.eligible)
        self.assertEqual(s.median_ms, 20.0)
        self.assertEqual(s.failure_rate, 0.0)
        self.assertIsNotNone(s.score)
        self.assertEqual(s.flags, ())

    def test_failures_raise_score_and_can_disqualify(self) -> None:
        clean = stats("1.1.1.1", [good(20)] * 4)
        flaky = stats("2.2.2.2", [good(20)] * 3 + [bad()])  # 25% failure: allowed, penalised
        self.assertTrue(flaky.eligible)
        self.assertGreater(flaky.score or 0, clean.score or 0)
        worse = stats("3.3.3.3", [good(20)] * 2 + [bad()] * 2)
        self.assertFalse(worse.eligible)
        self.assertIn("unreliable", worse.reasons)

    def test_unreachable(self) -> None:
        s = stats("4.4.4.4", [bad(), bad()])
        self.assertFalse(s.eligible)
        self.assertIn("unreachable", s.reasons)
        self.assertIsNone(s.score)
        self.assertEqual(s.answered, 1)  # only the NX probe got a reply

    def test_nxdomain_hijack_flag(self) -> None:
        hijack = Observation(KIND_NX, "x.invalid", 0, 10.0, ("203.0.113.9",))
        s = analysis.analyse(ServerResult(server("5.5.5.5"), (hijack, good(10), good(10))))
        self.assertIn(analysis.FLAG_NX_HIJACK, s.flags)
        self.assertFalse(s.eligible)

    def test_bogon_flag_for_private_and_special_ranges(self) -> None:
        for bad_ip in ["10.10.34.34", "127.0.0.1", "0.0.0.0", "100.64.1.1", "192.168.1.1", "169.254.1.1"]:
            with self.subTest(ip=bad_ip):
                s = stats("6.6.6.6", [good(10, (bad_ip,)), good(10)])
                self.assertIn(analysis.FLAG_BOGON, s.flags)
                self.assertFalse(s.eligible)

    def test_public_ipv6_is_not_a_bogon(self) -> None:
        s = stats("7.7.7.7", [good(10, ("2606:2800:220:1:248:1893:25c8:1946",))])
        self.assertEqual(s.flags, ())

    def test_single_sample_has_zero_jitter(self) -> None:
        self.assertEqual(stats("8.8.8.8", [good(15)]).jitter_ms, 0.0)

    def test_servfail_counts_as_failure(self) -> None:
        servfail = Observation(KIND_POPULAR, "example.com", 2, 12.0)
        s = stats("9.9.9.9", [servfail, servfail])
        self.assertFalse(s.eligible)


class RankSelectTests(unittest.TestCase):
    def build(self) -> list[analysis.ServerStats]:
        return [
            stats("1.1.1.1", [good(10)] * 3, "cf"),
            stats("1.0.0.1", [good(11)] * 3, "cf"),
            stats("8.8.8.8", [good(14)] * 3, "google"),
            stats("9.9.9.9", [good(400)] * 3, "slow"),
            stats("6.6.6.6", [bad()] * 3, "dead"),
        ]

    def test_rank_orders_eligible_first_by_score(self) -> None:
        ranked = analysis.rank(self.build())
        self.assertEqual([s.address for s in ranked[:4]], ["1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"])
        self.assertFalse(ranked[-1].eligible)

    def test_select_prefers_other_provider_for_fallback(self) -> None:
        ranked = analysis.rank(self.build())
        picks = analysis.select(ranked, 2)
        self.assertEqual([s.address for s in picks], ["1.1.1.1", "8.8.8.8"])

    def test_select_does_not_pick_dramatically_slower_provider(self) -> None:
        ranked = analysis.rank(
            [stats("1.1.1.1", [good(10)] * 3, "cf"), stats("1.0.0.1", [good(11)] * 3, "cf"),
             stats("9.9.9.9", [good(400)] * 3, "slow")]
        )
        picks = analysis.select(ranked, 2)
        self.assertEqual([s.address for s in picks], ["1.1.1.1", "1.0.0.1"])

    def test_select_falls_back_to_same_provider(self) -> None:
        ranked = analysis.rank([stats("1.1.1.1", [good(10)] * 3, "cf"), stats("1.0.0.1", [good(11)] * 3, "cf")])
        self.assertEqual(len(analysis.select(ranked, 2)), 2)

    def test_select_nothing_when_nothing_eligible(self) -> None:
        self.assertEqual(analysis.select(analysis.rank([stats("6.6.6.6", [bad()] * 3)]), 2), [])

    def test_warning_when_everything_is_tampered(self) -> None:
        tampered = [stats(f"10.0.0.{i}", [good(10, ("10.10.34.34",))]) for i in range(1, 4)]
        warnings = analysis.network_warnings(tampered)
        self.assertEqual(len(warnings), 1)
        self.assertIn("intercepting", warnings[0])

    def test_warning_when_nobody_answers(self) -> None:
        dead = analysis.analyse(ServerResult(server("6.6.6.6"), (bad(), bad())))
        self.assertIn("No server answered", analysis.network_warnings([dead])[0])

    def test_no_warning_on_healthy_network(self) -> None:
        self.assertEqual(analysis.network_warnings(self.build()), [])


if __name__ == "__main__":
    unittest.main()
