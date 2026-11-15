#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verification Mode tests — the secret is never in any output."""
import contextlib
import io
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.menu import MenuApp
from conan.scanners import verify as verify_mod

SECRET = "SECRET-ABC-123"
COOKIE_VAL = "COOKIE-VAL-999"


class _Site(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/public.txt":
            body = ("config dump\napi_key=%s\n" % SECRET).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/other.txt":
            body = b"nothing here"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"<html><body>home</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie",
                             "session=%s; Path=/" % COOKIE_VAL)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.scan = {
            "target": cls.base,
            "scope": {"authorized": True},
            "exposure": {"public_files": [
                {"url": cls.base + "/public.txt"},
                {"url": cls.base + "/other.txt"}]},
            "discovery": {"pages": []},
            "deep_paths": [],
        }

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_exposed_secret_found_with_location_only(self):
        out = verify_mod.verify_secret(self.scan, SECRET)
        self.assertEqual(len(out["found"]), 1)
        self.assertIn("/public.txt", out["found"][0]["where"])
        # The secret itself is never in the result.
        self.assertNotIn(SECRET, str(out))

    def test_cookie_value_match_without_showing_it(self):
        out = verify_mod.verify_secret(self.scan, COOKIE_VAL)
        self.assertTrue(out["cookie_match"])
        self.assertEqual(out["found"], [])
        self.assertNotIn(COOKIE_VAL, str(out))

    def test_absent_value_not_found(self):
        out = verify_mod.verify_secret(self.scan, "NOPE-NOT-HERE-777")
        self.assertEqual(out["found"], [])
        self.assertFalse(out["cookie_match"])
        self.assertGreater(out["checked"], 0)

    def test_dashboard_verify_never_prints_secret(self):
        with mock.patch("os.getcwd", return_value=tempfile.mkdtemp()):
            app = MenuApp(no_animation=True)
        app.i18n.set("en")
        rec = {"case_id": "CN-1", "scan": self.scan}
        with mock.patch("getpass.getpass", return_value=SECRET), \
             mock.patch("builtins.input", return_value=""):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                app.opt_verify(rec)
        out = buf.getvalue()
        self.assertIn("FOUND", out)
        self.assertIn("/public.txt", out)
        self.assertNotIn(SECRET, out)

    def test_dashboard_verify_requires_authorization(self):
        with mock.patch("os.getcwd", return_value=tempfile.mkdtemp()):
            app = MenuApp(no_animation=True)
        app.i18n.set("en")
        scan = dict(self.scan)
        scan["scope"] = {"authorized": False}
        rec = {"case_id": "CN-1", "scan": scan}
        with mock.patch("getpass.getpass") as gp:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                app.opt_verify(rec)
        gp.assert_not_called()
        self.assertIn("authorized", buf.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
