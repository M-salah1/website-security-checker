#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report tests — multilingual JSON/HTML, no secrets in output."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.reporting.html_report import build_html_report
from conan.reporting.json_report import build_json_report

SAMPLE_SCAN = {
    "tool": "CONAN FRAMEWORK v4.0", "target": "https://example.com",
    "scan_timestamp": "2026-11-15T00:00:00Z", "finished_at": "2026-11-15T00:00:01Z",
    "duration_s": 1.0, "language": "ar",
    "scope": {"kind": "passive"}, "dns": {"ips": ["93.184.216.34"], "ns": ["a.iana-servers.net"]},
    "tls": {"issuer": "DigiCert", "version": "TLSv1.3", "days_left": 90, "chain_verified": True},
    "headers": {}, "cookies": {"cookies": []}, "discovery": {"pages": []},
    "forms": [], "api": [], "auth_audit": {}, "registration_audit": {},
    "vulnerabilities": [{"name": "Missing HSTS", "severity": "high", "confidence": 95,
                         "status": "confirmed", "url": "https://example.com",
                         "evidence": "Header absent", "method": "headers",
                         "reproduction": "GET", "remediation": "Add HSTS",
                         "timestamp": "2026-11-15T00:00:00Z"}],
    "phishing": {"risk_score": 10, "classification": "LOW"},
    "health": {"classification": "ONLINE", "status": 200, "total_ms": 120},
    "score": 60, "grade": "C", "confidence": 95, "checks_count": 12,
    "severity_distribution": {"high": 1}, "recommendations": ["Add HSTS"],
}


class TestReports(unittest.TestCase):
    def test_json_report_sections(self):
        r = build_json_report(SAMPLE_SCAN)
        for key in ("target", "dns", "tls", "headers", "cookies", "discovery",
                    "forms", "auth_audit", "registration_audit", "vulnerabilities",
                    "phishing", "health", "score", "grade", "recommendations"):
            self.assertIn(key, r)
        self.assertEqual(r["confirmed_findings"], 1)

    def test_html_report_multilingual(self):
        for lang in ("ar", "fr", "en"):
            scan = dict(SAMPLE_SCAN)
            scan["language"] = lang
            html = build_html_report(scan)
            self.assertIn("CONAN FRAMEWORK", html)
            self.assertIn("https://example.com", html)
            if lang == "ar":
                self.assertIn('dir="rtl"', html)
            else:
                self.assertIn('dir="ltr"', html)

    def test_no_secrets_in_reports(self):
        import json
        scan = dict(SAMPLE_SCAN)
        scan["vulnerabilities"] = [dict(SAMPLE_SCAN["vulnerabilities"][0],
                                        evidence="token=abc123secret")]
        j = json.dumps(build_json_report(scan))
        self.assertNotIn("abc123secret", j)


if __name__ == "__main__":
    unittest.main()
