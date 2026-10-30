from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dnstune import servers
from dnstune.errors import ConfigError

GOOD = """
schema_version = 1
[[server]]
label = "Example"
provider = "example"
address = "192.0.2.53"
"""


class CatalogTests(unittest.TestCase):
    def test_builtin_is_valid_and_sane(self) -> None:
        catalog = servers.load_builtin()
        self.assertGreaterEqual(len(catalog), 8)
        self.assertEqual(len({s.address for s in catalog}), len(catalog))
        self.assertTrue(any(s.filtering for s in catalog))
        self.assertTrue(any(not s.filtering for s in catalog))

    def test_filtering_excluded_by_default(self) -> None:
        catalog = servers.load_builtin()
        default = servers.select_servers(catalog, include_filtering=False)
        self.assertTrue(default)
        self.assertFalse(any(s.filtering for s in default))
        self.assertEqual(len(servers.select_servers(catalog, include_filtering=True)), len(catalog))

    def test_parse_good(self) -> None:
        (server,) = servers.parse_catalog(GOOD, source="t")
        self.assertEqual((server.address, server.provider, server.filtering), ("192.0.2.53", "example", False))

    def test_ipv6_is_normalized(self) -> None:
        text = GOOD.replace("192.0.2.53", "2001:DB8:0:0:0:0:0:1")
        self.assertEqual(servers.parse_catalog(text, source="t")[0].address, "2001:db8::1")

    def assert_rejected(self, text: str) -> None:
        with self.assertRaises(ConfigError):
            servers.parse_catalog(text, source="t")

    def test_rejections(self) -> None:
        self.assert_rejected("not toml [[[")
        self.assert_rejected("schema_version = 2\n" + GOOD.split("\n", 2)[2])
        self.assert_rejected("schema_version = 1\n")
        self.assert_rejected(GOOD + 'extra = "x"\n')
        self.assert_rejected(GOOD.replace('address = "192.0.2.53"', 'address = "not-an-ip"'))
        self.assert_rejected(GOOD.replace('address = "192.0.2.53"', 'address = "example.com"'))
        self.assert_rejected(GOOD.replace('provider = "example"', 'provider = "Bad Provider!"'))
        self.assert_rejected(GOOD.replace('label = "Example"', 'label = ""'))
        self.assert_rejected(GOOD + 'port = 5353\n')
        self.assert_rejected(GOOD + 'filtering = "yes"\n')
        self.assert_rejected(GOOD + GOOD.split("\n", 2)[2])  # duplicate address

    def test_file_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope.toml"
            with self.assertRaises(ConfigError):
                servers.load_file(missing)
            big = Path(tmp) / "big.toml"
            big.write_text("#" * (servers.MAX_CATALOG_BYTES + 1))
            with self.assertRaises(ConfigError):
                servers.load_file(big)
            ok = Path(tmp) / "ok.toml"
            ok.write_text(GOOD)
            self.assertEqual(len(servers.load_file(ok)), 1)


if __name__ == "__main__":
    unittest.main()
