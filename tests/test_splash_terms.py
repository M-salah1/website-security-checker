#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Splash screen + ethical terms acceptance tests."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.menu import MenuApp


def _app():
    # Fresh temp dir per app: no settings/scope leak between tests.
    with mock.patch("os.getcwd", return_value=tempfile.mkdtemp()):
        return MenuApp(no_animation=True)


class TestSplashAndTerms(unittest.TestCase):
    def test_splash_introduces_tool_and_developer(self):
        app = _app()
        app.i18n.set("ar")
        buf = io.StringIO()
        with mock.patch("builtins.input", return_value=""):
            with contextlib.redirect_stdout(buf):
                app.show_splash()
        out = buf.getvalue()
        self.assertIn("CONAN FRAMEWORK", out)
        self.assertIn("Hafed Mehdi Salah Eddine", out)
        self.assertIn("M-salah1", out)
        self.assertIn("FOX COMPANY", out)

    def test_ask_url_accepts_bare_domain(self):
        app = _app()
        with mock.patch("builtins.input", return_value="example.com"):
            self.assertEqual(app.ask_url(), "https://example.com")
        with mock.patch("builtins.input", return_value="aadl.dz"):
            self.assertEqual(app.ask_url(), "https://aadl.dz")

    def test_accept_terms_y_records_authorization(self):
        app = _app()
        with mock.patch("builtins.input", return_value="y"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                accepted = app.accept_terms("https://example.com")
        self.assertTrue(accepted)
        self.assertTrue(app.scope.is_authorized("https://example.com"))
        self.assertIn("أخلاقي", buf.getvalue())

    def test_accept_terms_n_declines(self):
        app = _app()
        with mock.patch("builtins.input", return_value="n"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                accepted = app.accept_terms("https://example.com")
        self.assertFalse(accepted)
        self.assertFalse(app.scope.is_authorized("https://example.com"))

    def test_end_to_end_splash_terms_mega_scan(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            inputs = ["1", "", url, "y", "0", "x"]
            with mock.patch("builtins.input", side_effect=inputs):
                with mock.patch("conan.core.terminal.is_tty", return_value=False):
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        with mock.patch("os.getcwd",
                                       return_value=tempfile.mkdtemp()):
                            app = MenuApp(no_animation=True)
                            rc = app.run()
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("Hafed Mehdi Salah Eddine", out)
            self.assertIn("FOX COMPANY", out)
        finally:
            safe_lab.stop_lab(server)


if __name__ == "__main__":
    unittest.main()
