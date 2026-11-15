#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Health monitor tests — live checks, skipped gracefully offline."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.scanners.health import check_health


class TestHealth(unittest.TestCase):
    def test_example_online(self):
        try:
            res = check_health("https://example.com", retries=1)
        except Exception as exc:
            self.skipTest("network unavailable: %s" % exc)
        self.assertEqual(res["classification"], "ONLINE")
        self.assertEqual(res["status"], 200)
        self.assertIsNotNone(res["total_ms"])

    def test_403_is_not_offline(self):
        # httpbin returns a real 403 — the server is up, not offline.
        try:
            res = check_health("https://httpbin.org/status/403", retries=0)
        except Exception as exc:
            self.skipTest("network unavailable: %s" % exc)
        if res["status"] is None:
            self.skipTest("could not reach httpbin: %s" % res["error"])
        self.assertEqual(res["status"], 403)
        self.assertEqual(res["classification"], "ONLINE")


if __name__ == "__main__":
    unittest.main()
