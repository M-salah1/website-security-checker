#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS engine tests — live, skipped gracefully offline."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDNS(unittest.TestCase):
    def test_example_dns(self):
        from conan.scanners.dns import analyze_dns
        try:
            res = analyze_dns("example.com")
        except Exception as exc:
            self.skipTest("network unavailable: %s" % exc)
        self.assertTrue(res["a"], "expected A records for example.com")
        self.assertTrue(res["ns"], "expected NS records for example.com")
        self.assertIn("dnssec", res)

    def test_discovery_classification(self):
        from conan.scanners.discovery import classify_status
        self.assertEqual(classify_status(200), "accessible")
        self.assertEqual(classify_status(301), "redirect")
        self.assertEqual(classify_status(401), "auth-required")
        self.assertEqual(classify_status(403), "forbidden")
        self.assertEqual(classify_status(404), "not-found")
        self.assertEqual(classify_status(429), "rate-limited")
        self.assertEqual(classify_status(500), "server-error")
        self.assertEqual(classify_status(503), "unavailable")
        self.assertEqual(classify_status(None, "timed out"), "timeout")


if __name__ == "__main__":
    unittest.main()
