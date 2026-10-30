"""Confirm ResolvedBackend's system_runner actually restricts the subprocess PATH.

A prior revision built the restricted environment dict but forgot to pass it
to the subprocess call, so the real ``PATH`` leaked through silently. This
test runs the *real* system_runner (not the fake) against a tiny stand-in
"resolvectl" to catch any regression of that class.
"""

from __future__ import annotations

import stat
import sys
import tempfile
import unittest
from pathlib import Path

from dnstune.resolved import system_runner


class SystemRunnerEnvironmentTests(unittest.TestCase):
    def test_path_is_restricted_to_system_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "printenv-path"
            fake.write_text(f"#!{sys.executable}\nimport os, sys\nsys.stdout.write(os.environ.get('PATH', ''))\n")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            proc = system_runner([str(fake)], timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "/usr/bin:/bin:/usr/sbin:/sbin")

    def test_locale_is_forced_to_c(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "printenv-lang"
            fake.write_text(
                f"#!{sys.executable}\nimport os, sys\nsys.stdout.write(os.environ.get('LANG', '') + ':' "
                "+ os.environ.get('LC_ALL', ''))\n"
            )
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            proc = system_runner([str(fake)], timeout=5)
        self.assertEqual(proc.stdout, "C:C")


if __name__ == "__main__":
    unittest.main()
