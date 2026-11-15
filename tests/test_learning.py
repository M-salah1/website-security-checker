#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Site Brain learning + per-phase timeout tests."""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.timeout import call_with_timeout
from conan.intelligence import learning as learn_mod

SAMPLE = {
    "target": "https://example.com", "score": 42, "grade": "C",
    "findings": [{"name": "Missing HSTS"}, {"name": "Missing CSP"}],
    "history": {"domain": "example.com"},
    "servers": {"server_header": "ECS", "ips": ["93.184.216.34"]},
    "tls": {"issuer": "Example CA"},
    "ports": {"open_ports": [{"port": 80}, {"port": 443}]},
    "js_api": {"endpoints": ["/api/users"]},
    "discovery": {"pages": ["/", "/robots.txt"]},
    "cookies": {"cookies": [{"name": "session"}]},
    "headers": {"checks": [{"name": "X-Frame-Options", "present": True},
                            {"name": "HSTS", "present": False}]},
    "methods": {"methods": ["GET", "HEAD", "OPTIONS"]},
    "redirects": {"chain": [(301, "https://example.com/")]},
}


class TestTimeout(unittest.TestCase):
    def test_fast_function_returns_value(self):
        self.assertEqual(call_with_timeout(lambda: 7, 5), 7)

    def test_slow_function_returns_timeout_marker(self):
        out = call_with_timeout(lambda: time.sleep(5), 0.2)
        self.assertTrue(out.get("timed_out"))
        self.assertIn("error", out)

    def test_exception_is_reraised(self):
        def boom():
            raise ValueError("x")

        with self.assertRaises(ValueError):
            call_with_timeout(boom, 5)


class TestLearning(unittest.TestCase):
    def test_build_profile_has_rules(self):
        profile = learn_mod.build_profile(SAMPLE)
        self.assertEqual(profile["domain"], "example.com")
        self.assertEqual(profile["server"], "ECS")
        self.assertEqual(profile["open_ports"], [80, 443])
        self.assertIn("/api/users", profile["endpoints"])
        self.assertTrue(any("server: ECS" in r for r in profile["rules"]))
        self.assertTrue(any("score: 42%" in r for r in profile["rules"]))

    def test_compare_detects_changes(self):
        old = learn_mod.build_profile(SAMPLE)
        new_scan = dict(SAMPLE)
        new_scan["servers"] = {"server_header": "nginx",
                               "ips": ["93.184.216.34"]}
        new_scan["js_api"] = {"endpoints": ["/api/users", "/api/orders"]}
        new_scan["cookies"] = {"cookies": []}
        new = learn_mod.build_profile(new_scan)
        changes = learn_mod.compare_profiles(old, new)
        kinds = {(c["field"], c["kind"]) for c in changes}
        self.assertIn(("server", "changed"), kinds)
        self.assertIn(("endpoints", "added"), kinds)
        self.assertIn(("cookies", "removed"), kinds)

    def test_learn_round_trip_and_change_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile1, changes1 = learn_mod.learn(SAMPLE, base_dir=tmp)
            self.assertEqual(changes1, [])
            self.assertTrue(os.path.exists(
                os.path.join(tmp, learn_mod.PROFILE_FILE)))
            new_scan = dict(SAMPLE)
            new_scan["score"] = 55
            new_scan["ports"] = {"open_ports": [{"port": 80},
                                                {"port": 443},
                                                {"port": 8080}]}
            _, changes2 = learn_mod.learn(new_scan, base_dir=tmp)
            kinds = {(c["field"], c["kind"]) for c in changes2}
            self.assertIn(("open_ports", "added"), kinds)
            self.assertIn(("score", "changed"), kinds)

    def test_mega_scan_learns_and_never_hangs(self):
        from conan.core.scope import ScopeManager
        from conan.laboratory import safe_lab
        from conan.scanners import mega as mega_mod
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("os.getcwd", return_value=tmp):
                server, url = safe_lab.start_lab()
                try:
                    scan = mega_mod.mega_scan(
                        url, scope=ScopeManager(), timeout=5)
                finally:
                    safe_lab.stop_lab(server)
        self.assertIn("learned_profile", scan)
        self.assertIn("learned_changes", scan)
        self.assertIsInstance(scan.get("phase_timeouts"), list)
        self.assertIn("learning", scan.get("deep_tests", []))
        self.assertTrue(scan["learned_profile"].get("rules"))


if __name__ == "__main__":
    unittest.main()
