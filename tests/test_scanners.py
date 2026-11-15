#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scanner tests — new v4.0 modules (offline pure parts + live, skips gracefully)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestIpIntel(unittest.TestCase):
    def test_ip_validation(self):
        from conan.scanners.ip_intelligence import is_valid_ip
        self.assertTrue(is_valid_ip("8.8.8.8"))
        self.assertTrue(is_valid_ip("::1"))
        self.assertFalse(is_valid_ip("not-an-ip"))

    def test_port_check_localhost_closed(self):
        from conan.scanners.ip_intelligence import check_port
        res = check_port("127.0.0.1", 59999, timeout=2)
        self.assertEqual(res["port"], 59999)
        self.assertFalse(res["open"])


class TestPaths(unittest.TestCase):
    def test_categorize(self):
        from conan.scanners.paths import categorize
        self.assertEqual(categorize(200), "PUBLIC")
        self.assertEqual(categorize(401), "AUTHENTICATION REQUIRED")
        self.assertEqual(categorize(403), "FORBIDDEN")
        self.assertEqual(categorize(404), "NOT FOUND")
        self.assertEqual(categorize(301), "REDIRECT")
        self.assertEqual(categorize(500), "SERVER ERROR")
        self.assertEqual(categorize(None, "timed out"), "TIMEOUT")


class TestExposure(unittest.TestCase):
    def test_secret_redaction_in_findings(self):
        from conan.scanners.exposure import scan_text_for_secrets
        findings = scan_text_for_secrets(
            "https://example.com/.env",
            'API_KEY="sk-live-1234567890abcdef"\nPASSWORD="hunter2"')
        self.assertTrue(findings)
        for f in findings:
            self.assertIn("[REDACTED]", f["evidence"])
            self.assertNotIn("sk-live-1234567890abcdef", f["evidence"])
            self.assertNotIn("hunter2", f["evidence"])

    def test_no_false_positive_on_clean_text(self):
        from conan.scanners.exposure import scan_text_for_secrets
        self.assertEqual(scan_text_for_secrets("https://example.com/", "hello world"), [])


class TestMalwareLab(unittest.TestCase):
    def test_eicar_detected(self):
        from conan.laboratory.static_analysis import analyze_text
        from conan.laboratory.test_samples import EICAR
        res = analyze_text("eicar-test.txt", EICAR)
        self.assertTrue(any(i["pattern"] == "EICAR test string" for i in res["indicators"]))

    def test_benign_is_clean(self):
        from conan.laboratory.static_analysis import analyze_text
        res = analyze_text("benign.js", "console.log('hello');")
        self.assertEqual(res["verdict"], "clean")

    def test_lab_simulation_runs(self):
        from conan.laboratory.simulator import run_lab_simulation
        rep = run_lab_simulation(log=None)
        self.assertEqual(len(rep["results"]), 3)
        self.assertTrue(any(r["sample"] == "eicar-test.txt" for r in rep["results"]))


class TestChildSafety(unittest.TestCase):
    def test_incident_metadata_only(self):
        from conan.scanners.child_safety import create_incident
        rec = create_incident("https://bad.example/x", "phishing", "reported by user")
        self.assertFalse(rec["content_downloaded"])
        self.assertFalse(rec["content_stored"])
        self.assertTrue(rec["metadata_hash"])
        self.assertTrue(rec["channels"])

    def test_bad_category_rejected(self):
        from conan.scanners.child_safety import create_incident
        with self.assertRaises(ValueError):
            create_incident("https://x.example/", "not-a-category")


class TestWebsiteLive(unittest.TestCase):
    def test_website_investigation(self):
        from conan.scanners.website import investigate_website
        try:
            scan = investigate_website("https://example.com", max_pages=5)
        except Exception as exc:
            self.skipTest("network unavailable: %s" % exc)
        self.assertEqual(scan["target"], "https://example.com")
        self.assertIn("findings", scan)
        self.assertIn("health", scan)
        self.assertIn("dns", scan)
        self.assertIn("phishing", scan)
        self.assertEqual(scan["health"]["classification"], "ONLINE")


if __name__ == "__main__":
    unittest.main()
