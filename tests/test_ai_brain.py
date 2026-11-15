#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Conan AI Brain tests — attack chains, verdict, priorities."""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.intelligence import ai_brain as brain

SAMPLE = {
    "target": "http://example.com", "score": 35, "grade": "F",
    "findings": [
        {"name": "Missing Content-Security-Policy", "severity": "medium",
         "confidence": 85, "status": "confirmed",
         "evidence": "Header Content-Security-Policy is missing",
         "remediation": "Add a strict CSP"},
        {"name": "Cookie without full protection", "severity": "medium",
         "confidence": 85, "status": "confirmed",
         "evidence": "Cookie session: Secure=False HttpOnly=False",
         "remediation": "Add Secure, HttpOnly and SameSite=Lax"},
        {"name": "Missing X-Frame-Options", "severity": "low",
         "confidence": 90, "status": "confirmed",
         "evidence": "Header X-Frame-Options is missing",
         "remediation": "Add X-Frame-Options: DENY"},
        {"name": "Site works without HTTPS", "severity": "high",
         "confidence": 95, "status": "confirmed",
         "evidence": "http://example.com serves content without HTTPS",
         "remediation": "Enable HTTPS and redirect http to https"},
    ],
    "forms": {"forms": [{"action": "http://example.com/login"}]},
    "servers": {"server_header": "Apache/2.4.52"},
    "ports": {"open_ports": [{"port": 22}, {"port": 80}]},
    "js_api": {"endpoints": ["/api/users"]},
    "permissions": {"cors": "*"},
    "learned_changes": [],
}


class TestAiBrain(unittest.TestCase):
    def test_xss_chain_detected(self):
        out = brain.analyze(SAMPLE, "en")
        ids = [c["id"] for c in out["chains"]]
        self.assertIn("xss-session-theft", ids)
        self.assertIn("clickjacking", ids)
        self.assertIn("session-hijack-wire", ids)
        self.assertIn("admin-service-exposed", ids)
        self.assertIn("cors-data-theft", ids)
        self.assertIn("fingerprint-targeting", ids)
        chain = next(c for c in out["chains"]
                     if c["id"] == "xss-session-theft")
        self.assertTrue(chain["evidence"])
        self.assertIn("Session theft", out["verdict"])

    def test_priorities_ranked_by_exploitability(self):
        out = brain.analyze(SAMPLE, "en")
        names = [p["name"] for p in out["priorities"]]
        # Highest severity x confidence first.
        self.assertEqual(names[0], "Site works without HTTPS")
        self.assertIn("Missing Content-Security-Policy", names)

    def test_next_tests_adapt_to_surface(self):
        out = brain.analyze(SAMPLE, "en")
        joined = " ".join(out["next_tests"])
        self.assertIn("Authentication audit", joined)
        self.assertIn("API audit", joined)
        self.assertIn("Full port scan", joined)
        self.assertIn("Session test", joined)

    def test_new_items_flagged_first(self):
        scan = dict(SAMPLE)
        scan["learned_changes"] = [
            {"field": "open_ports", "kind": "added",
             "detail": "open ports: + 8080"}]
        out = brain.analyze(scan, "en")
        self.assertTrue(out["new_since_last"])
        self.assertIn("8080", out["new_since_last"][0])

    def test_empty_scan_has_no_chains(self):
        out = brain.analyze({"target": "https://example.com", "score": 95,
                             "findings": []}, "ar")
        self.assertEqual(out["chains"], [])
        self.assertIn("95%", out["verdict"])

    def test_mega_scan_has_ai_brain(self):
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
        self.assertIn("ai_brain", scan)
        self.assertIn("verdict", scan["ai_brain"])
        self.assertIn("ai-brain", scan.get("deep_tests", []))
        # The lab is HTTP-only with weak cookies: the brain must see it.
        ids = [c["id"] for c in scan["ai_brain"].get("chains", [])]
        self.assertIn("session-hijack-wire", ids)


if __name__ == "__main__":
    unittest.main()
