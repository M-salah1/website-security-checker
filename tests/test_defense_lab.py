#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v5.0 Ethical Defender Edition tests — safe lab, defense center,
victim protection, animated report, 20-option menu. Offline; the lab
runs on 127.0.0.1 only."""
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.i18n import ar_display
from conan.core.menu import MenuApp
from conan.defense import hardening
from conan.defense.victim_support import (create_protection_case,
                                          evidence_checklist, safety_plan)
from conan.laboratory import safe_lab
from conan.reporting.animated_report import build_animated_html_report
from conan.scanners._http import get as http_get

SAMPLE_SCAN = {
    "tool": "CONAN FRAMEWORK v5.0", "target": "https://example.com",
    "scan_timestamp": "2026-11-15T00:00:00Z", "finished_at": "2026-11-15T00:00:01Z",
    "duration_s": 1.0, "language": "ar",
    "scope": {"kind": "passive"}, "dns": {"ips": ["93.184.216.34"], "ns": []},
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


class TestSafeLab(unittest.TestCase):
    def setUp(self):
        self.server, self.url = safe_lab.start_lab()

    def tearDown(self):
        safe_lab.stop_lab(self.server)

    def test_lab_is_localhost_only(self):
        self.assertTrue(self.url.startswith("http://127.0.0.1:"))

    def test_lab_pages(self):
        index = http_get(self.url)
        self.assertEqual(index["status"], 200)
        self.assertIn("SAFE LAB", index["body"])
        search = http_get(self.url + "/search?q=ConanMarker7x9")
        self.assertIn("ConanMarker7x9", search["body"])
        login = http_get(self.url + "/login")
        self.assertIn("<form", login["body"])
        self.assertNotIn("csrf", login["body"].lower())

    def test_lab_training_finds_demo_issues(self):
        res = safe_lab.run_lab_training(self.url)
        names = [f["name"] for f in res["findings"]]
        self.assertIn("Reflected input point (possible XSS)", names)
        self.assertIn("Suspected SQL injection", names)
        self.assertIn("State-changing form without CSRF token", names)
        for f in res["findings"]:
            self.assertTrue(f.get("training_note"))


class TestDefense(unittest.TestCase):
    def test_snippets(self):
        self.assertIn("Strict-Transport-Security", hardening.apache_snippet())
        self.assertIn("Content-Security-Policy", hardening.apache_snippet())
        self.assertIn("limit_req_zone", hardening.nginx_snippet())
        self.assertIn("server_tokens off", hardening.nginx_snippet())
        self.assertIn("frame-ancestors", hardening.csp_policy())

    def test_incident_plan_and_templates(self):
        self.assertEqual(len(hardening.incident_response_plan()), 7)
        self.assertTrue(hardening.rate_limit_guidance())
        tpl = hardening.takedown_request_template("https://bad.example/x", "threats")
        self.assertIn("https://bad.example/x", tpl)
        self.assertIn("Abuse", tpl)

    def test_hardening_checklist_maps_findings(self):
        steps = hardening.hardening_checklist([{"name": "Missing HSTS"}])
        self.assertTrue(any("HSTS" in s for s in steps))

    def test_no_attack_capability_in_defense(self):
        # The defense module must not contain attack tooling.
        import conan.defense.hardening as h
        import inspect
        src = inspect.getsource(h)
        for bad in ("brute", "DDoS", "exploit(", "payload", "hack back", "hack-back"):
            self.assertNotIn(bad, src.lower())


class TestVictimProtection(unittest.TestCase):
    def test_safety_plan_three_languages(self):
        for lang in ("ar", "en", "fr"):
            plan = safety_plan(lang)
            self.assertGreaterEqual(len(plan), 5)
            self.assertGreaterEqual(len(evidence_checklist(lang)), 5)
        self.assertTrue(any("المهد" in s for s in safety_plan("ar")))

    def test_protection_case_never_fetches(self):
        rec = create_protection_case("https://example.com/reported", "threats", "test")
        self.assertFalse(rec["content_downloaded"])
        self.assertFalse(rec["content_stored"])
        self.assertEqual(set(rec["safety_plan"]), {"ar", "en", "fr"})
        self.assertTrue(rec["channels"])


class TestAnimatedReport(unittest.TestCase):
    def test_animated_report_has_motion_and_real_data(self):
        html = build_animated_html_report(SAMPLE_SCAN)
        self.assertIn("@keyframes sweep", html)
        self.assertIn("radar", html)
        self.assertIn("60%", html)
        self.assertIn("Missing HSTS", html)
        self.assertIn('dir="rtl"', html)

    def test_animated_report_redacts_secrets(self):
        scan = dict(SAMPLE_SCAN)
        scan["vulnerabilities"] = [dict(SAMPLE_SCAN["vulnerabilities"][0],
                                        evidence="token=abc123secret")]
        self.assertNotIn("abc123secret", build_animated_html_report(scan))


class TestMenu20(unittest.TestCase):
    def test_main_menu_has_20_options(self):
        tmp = tempfile.TemporaryDirectory()
        cwd = os.getcwd()
        os.chdir(tmp.name)
        try:
            app = MenuApp(no_animation=True)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                app.main_menu()
            out = buf.getvalue()
            self.assertIn("20.", out)
            self.assertIn("17.", out)
            # Menu labels go through the Arabic display fix (pre-reversed
            # in Termux mode), so compare against the display form.
            self.assertIn(ar_display(app.t("menu_19"), "ar"), out)
            self.assertIn("0.", out)
        finally:
            os.chdir(cwd)
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
