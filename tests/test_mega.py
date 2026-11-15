#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mega scan tests — history parsing, deep identity, default flow."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.menu import MenuApp
from conan.intelligence.history import (ct_history, domain_history,
                                        fetch_security_contacts, http_methods,
                                        parse_ct_history, parse_security_txt)
from conan.scanners import mega as mega_mod


class TestHistoryParsing(unittest.TestCase):
    def test_parse_ct_history(self):
        entries = [
            {"name_value": "example.com\nwww.example.com",
             "not_before": "2020-03-01T00:00:00"},
            {"name_value": "old.example.com",
             "not_before": "2019-01-15T00:00:00"},
        ]
        out = parse_ct_history(entries)
        self.assertEqual(out["earliest_certificate"], "2019-01-15")
        self.assertEqual(out["latest_certificate"], "2020-03-01")
        self.assertIn("old.example.com", out["hostnames"])
        self.assertEqual(out["certificates"], 2)

    def test_parse_ct_history_empty(self):
        out = parse_ct_history([])
        self.assertFalse(out["available"])
        self.assertIsNone(out["earliest_certificate"])

    def test_parse_security_txt(self):
        text = ("Contact: mailto:security@example.com\n"
                "Contact: https://example.com/security\n"
                "Expires: 2027-01-01T00:00:00.000Z\n"
                "# a comment\n")
        out = parse_security_txt(text)
        self.assertIn("mailto:security@example.com", out["contacts"])
        self.assertEqual(len(out["contacts"]), 2)
        self.assertTrue(out["expires"].startswith("2027-01-01"))

    def test_ct_history_handles_failure(self):
        with mock.patch("conan.intelligence.history._fetch_json",
                        side_effect=Exception("no network")):
            out = ct_history("example.com")
        self.assertFalse(out["available"])
        self.assertIn("error", out)

    def test_http_methods_lab(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            out = http_methods(url)
        finally:
            safe_lab.stop_lab(server)
        self.assertIn("methods", out)
        self.assertIn("risky", out)

    def test_domain_history_local_target(self):
        out = domain_history("127.0.0.1", "http://127.0.0.1:9/")
        self.assertEqual(out["domain"], "127.0.0.1")
        self.assertIn("Local", out.get("note", ""))
        # Never invents previous names.
        self.assertEqual(out["previous_names"], "UNKNOWN")

    def test_domain_history_never_invents_admin(self):
        with mock.patch("conan.intelligence.history.investigate_domain",
                        return_value={"registration": {},
                                      "nameservers": [], "dns": {"ips": []},
                                      "hosting": {}, "server_header": "",
                                      "tls": {}, "certificate_transparency": {}}), \
             mock.patch("conan.intelligence.history.ct_history",
                        return_value={"earliest_certificate": None,
                                      "latest_certificate": None,
                                      "certificates": 0, "hostnames": []}), \
             mock.patch("conan.intelligence.history.fetch_security_contacts",
                        return_value={"contacts": []}):
            out = domain_history("example.com", "https://example.com/")
        self.assertEqual(out["admin_contact"], "UNKNOWN")
        self.assertEqual(out["previous_names"], "UNKNOWN")
        self.assertIn("Not publicly disclosed", out["admin_contact_source"])


class TestMegaScan(unittest.TestCase):
    def test_mega_scan_on_safe_lab(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            scan = mega_mod.mega_scan(url, scope=None, timeout=5)
        finally:
            safe_lab.stop_lab(server)
        self.assertEqual(scan["kind"], "mega-scan")
        self.assertIn("history", scan)
        self.assertIn("servers", scan)
        self.assertIn("methods", scan)
        self.assertIn("redirects", scan)
        self.assertIn("deep_tests", scan)
        self.assertTrue(len(scan["deep_tests"]) >= 15)
        self.assertIn("findings", scan)
        # The lab is deliberately vulnerable: a real measured score of
        # 0 is honest; only a failed measurement is INCOMPLETE (None).
        self.assertTrue(scan["score"] is None or scan["score"] >= 0)
        self.assertIn("coverage", scan)
        # Local lab: no public history, deep paths need authorization.
        self.assertEqual(scan["history"]["previous_names"], "UNKNOWN")
        self.assertEqual(scan["deep_paths"], [])

    def test_mega_flow_back_opens_menu(self):
        # Entry flow: welcome pause, language 1, then `menu` in the
        # console opens the classic menu; 20 there exits back to the
        # console, and EOF ends it. run() must return 0.
        with mock.patch("builtins.input", side_effect=["", "1", "menu", "20", "exit"]):
            with mock.patch("conan.core.terminal.is_tty", return_value=False):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    with mock.patch("os.getcwd",
                                   return_value=tempfile.mkdtemp()):
                        app = MenuApp(no_animation=True)
                        rc = app.run()
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("20.", out)


if __name__ == "__main__":
    unittest.main()
