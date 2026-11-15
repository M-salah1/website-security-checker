#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Telegram delivery tests — report content, chunking, token safety."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.menu import MenuApp
from conan.reporting import telegram as tg

SAMPLE_SCAN = {
    "target": "https://example.com", "score": 42, "grade": "C",
    "confidence": 88,
    "findings": [
        {"severity": "high", "name": "Missing HSTS",
         "evidence": "Header Strict-Transport-Security is absent"},
        {"severity": "low", "name": "Missing Permissions-Policy",
         "evidence": "Header Permissions-Policy is absent"},
    ],
    "history": {"domain": "example.com", "country": "United States",
                "hosting_org": "Example Org", "created": "1995-08-14",
                "registrar": "Example Registrar",
                "earliest_certificate": "2019-01-15"},
    "servers": {"server_header": "ECS", "ips": ["93.184.216.34"]},
    "origin": {"ips": ["93.184.216.34"], "cdn_detected": False},
    "deep_paths": [{"path": "/robots.txt", "category": "PUBLIC"},
                   {"path": "/admin", "category": "NOT FOUND"}],
    "js_api": {"endpoints": ["/api/users", "/api/v1/orders"]},
    "recommendations": ["Add HSTS header", "Add Permissions-Policy"],
}


class FakeResp:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestTelegram(unittest.TestCase):
    def test_build_report_has_tool_developer_target_results(self):
        text = tg.build_telegram_report(SAMPLE_SCAN, "ar")
        self.assertIn("CONAN FRAMEWORK", text)
        self.assertIn("Hafed Mehdi Salah Eddine", text)
        self.assertIn("https://example.com", text)
        self.assertIn("42%", text)
        self.assertIn("Missing HSTS", text)
        self.assertIn("/api/users", text)
        self.assertIn("93.184.216.34", text)
        # The builder never sees a token, so none can leak through it.
        self.assertNotIn("123456:ABC", text)

    def test_split_message_respects_limit(self):
        text = "\n".join("line %d" % i for i in range(500))
        chunks = tg.split_message(text, limit=1000)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= 1000 for c in chunks))
        self.assertEqual("\n".join(c.strip() for c in chunks).count("line"), 500)

    def test_send_telegram_chunks_and_posts(self):
        calls = []

        def fake_urlopen(req, timeout=15):
            calls.append((req.full_url, json.loads(req.data.decode())))
            return FakeResp({"ok": True, "result": {"message_id": 1}})

        long_text = "x" * 5000
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            sent, error = tg.send_telegram("TOKEN123", "98765", long_text)
        self.assertIsNone(error)
        self.assertEqual(sent, 2)
        self.assertEqual(len(calls), 2)
        self.assertIn("TOKEN123", calls[0][0])
        self.assertEqual(calls[0][1]["chat_id"], "98765")

    def test_send_telegram_api_error(self):
        def fake_urlopen(req, timeout=15):
            return FakeResp({"ok": False, "description": "Forbidden: bot was blocked"})

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            sent, error = tg.send_telegram("TOKEN123", "98765", "hi")
        self.assertEqual(sent, 0)
        self.assertIn("blocked", error)

    def test_send_telegram_missing_credentials(self):
        sent, error = tg.send_telegram("", "98765", "hi")
        self.assertEqual(sent, 0)
        self.assertIsNotNone(error)

    def test_dashboard_send_flow_never_prints_token(self):
        with mock.patch("os.getcwd", return_value=tempfile.mkdtemp()):
            app = MenuApp(no_animation=True)
        app.i18n.set("ar")
        rec = {"case_id": "CN-1", "scan": SAMPLE_SCAN}
        with mock.patch("builtins.input", return_value="98765"), \
             mock.patch("getpass.getpass", return_value="FAKE_TOKEN_123"), \
             mock.patch("conan.reporting.telegram.send_telegram",
                        return_value=(2, None)) as m:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                app.opt_send_telegram(rec)
        out = buf.getvalue()
        self.assertIn("Telegram", out)
        self.assertNotIn("FAKE_TOKEN_123", out)
        m.assert_called_once()
        args = m.call_args[0]
        self.assertEqual(args[0], "FAKE_TOKEN_123")
        self.assertEqual(args[1], "98765")
        self.assertIn("https://example.com", args[2])

    def test_dashboard_send_flow_failure(self):
        with mock.patch("os.getcwd", return_value=tempfile.mkdtemp()):
            app = MenuApp(no_animation=True)
        app.i18n.set("en")
        rec = {"case_id": "CN-1", "scan": SAMPLE_SCAN}
        with mock.patch("builtins.input", return_value="98765"), \
             mock.patch("getpass.getpass", return_value="FAKE_TOKEN_123"), \
             mock.patch("conan.reporting.telegram.send_telegram",
                        return_value=(0, "Forbidden: bot was blocked")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                app.opt_send_telegram(rec)
        self.assertIn("failed", buf.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
