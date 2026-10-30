"""Static guard rails that keep dangerous patterns out of the code base forever."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "dnstune"
FILES = sorted(SRC.glob("*.py"))


class HygieneTests(unittest.TestCase):
    def test_sources_found(self) -> None:
        self.assertGreater(len(FILES), 10)

    def test_no_shell_execution(self) -> None:
        for path in FILES:
            text = path.read_text()
            self.assertNotIn("shell=True", text, path.name)
            self.assertNotRegex(text, r"\bos\.system\(|\bos\.popen\(", path.name)

    def test_no_dynamic_code_or_unsafe_deserialisation(self) -> None:
        for path in FILES:
            text = path.read_text()
            for pattern in (r"\beval\(", r"\bexec\(", r"\bpickle\b", r"\byaml\.load\(", r"__import__"):
                self.assertIsNone(re.search(pattern, text), f"{path.name}: {pattern}")

    def test_no_third_party_runtime_imports(self) -> None:
        stdlib_or_local = re.compile(r"^(?:from|import) (?:\.|__future__|[a-z_]+)")
        third_party = {"requests", "dns", "dnspython", "yaml", "click", "rich", "toml", "psutil", "netifaces"}
        for path in FILES:
            for line in path.read_text().splitlines():
                if stdlib_or_local.match(line):
                    root = re.split(r"[ .]", line.split()[1].lstrip("."))[0]
                    self.assertNotIn(root, third_party, f"{path.name}: {line}")

    def test_no_regex_dollar_anchors_that_allow_trailing_newline(self) -> None:
        for path in FILES:
            for line in path.read_text().splitlines():
                if "re.compile(" in line:
                    self.assertNotRegex(line, r'\$"\)', f"{path.name}: use fullmatch instead of $ -> {line.strip()}")


if __name__ == "__main__":
    unittest.main()
