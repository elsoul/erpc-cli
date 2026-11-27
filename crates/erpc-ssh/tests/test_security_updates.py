# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
import runpy
import unittest
from pathlib import Path
from types import SimpleNamespace as Row

source = Path(__file__).resolve().parents[1] / "src" / "node-security-updates.py"
summarize = runpy.run_path(str(source))["cached_security_candidates"]


class CachedSecurityUpdates(unittest.TestCase):
    ubuntu = Row(trusted=True, origin="Ubuntu", label="Ubuntu", archive="noble-security")
    debian = Row(trusted=True, origin="Debian", label="Debian-Security", archive="stable-security")
    unsigned = Row(trusted=False, origin="Ubuntu", label="Ubuntu", archive="noble-security")

    def package(self, installed, candidate, *origins):
        return Row(installed=None if installed is None else Row(version=installed),
                   candidate=Row(version=candidate, origins=origins))

    def summary(self, packages, time_left=True):
        return summarize(packages, lambda x, y: x - y, lambda: time_left)

    def test_installed_upgrades_only_and_dedup_origins(self):
        packages = [self.package(2, 3, self.ubuntu, self.ubuntu),
                    self.package(2, 2, self.debian), self.package(3, 1, self.ubuntu),
                    self.package(None, 2, self.ubuntu), self.package(1, 2, self.unsigned)]
        self.assertEqual(self.summary(packages), {"status": "available", "packages": 1})

    def test_no_trusted_evidence_or_timeout_is_unknown(self):
        package = self.package(2, 3, self.unsigned)
        unknown = {"status": "unknown", "packages": None}
        self.assertEqual(self.summary([]), unknown)
        self.assertEqual(self.summary([package]), unknown)
        self.assertEqual(self.summary([self.package(2, 3, self.debian)], False), unknown)

    def test_up_to_date_cached_candidate(self):
        self.assertEqual(self.summary([self.package(2, 2, self.debian)]),
                         {"status": "none_in_cached_candidates", "packages": 0})
