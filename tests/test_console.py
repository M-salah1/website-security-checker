#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Command console tests — help, scan, bare URL, menu, exit."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.i18n import set_reverse_arabic
from conan.core.menu import MenuApp


def _run_console(inputs):
    buf = io.StringIO()
    with mock.patch("builtins.input", side_effect=inputs):
        with mock.patch("conan.core.terminal.is_tty", return_value=False):
            with contextlib.redirect_stdout(buf):
                with mock.patch("os.getcwd", return_value=tempfile.mkdtemp()):
                    app = MenuApp(no_animation=True)
                    rc = app.run()
    return rc, buf.getvalue()


class TestConsole(unittest.TestCase):
    def tearDown(self):
        # MenuApp turns the Arabic-reverse flag on; reset it so other
        # test modules see the default off state.
        set_reverse_arabic(False)

    def test_help_and_exit(self):
        rc, out = _run_console(["", "1", "help", "exit"])
        self.assertEqual(rc, 0)
        self.assertIn("scan <url>", out)
        self.assertIn("menu", out)
        self.assertIn("CONAN FRAMEWORK", out)

    def test_unknown_command_then_exit(self):
        rc, out = _run_console(["", "1", "hello", "exit"])
        self.assertEqual(rc, 0)
        self.assertIn("help", out)

    def test_bare_url_routes_to_scan(self):
        app = MenuApp(no_animation=True)
        with mock.patch.object(MenuApp, "_scan_command", return_value=True) as m:
            with mock.patch("builtins.input", side_effect=["https://example.com", "exit"]):
                with mock.patch("conan.core.terminal.is_tty", return_value=False):
                    buf = io.StringIO()
                    with contextlib.redirect_stdout(buf):
                        rc = app.console_loop()
        self.assertEqual(rc, 0)
        m.assert_called_once_with("https://example.com")

    def test_console_scan_flow_on_safe_lab(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            rc, out = _run_console(["", "1", "scan " + url, "y", "0", "x", "exit"])
        finally:
            safe_lab.stop_lab(server)
        self.assertEqual(rc, 0)
        self.assertIn("Hafed Mehdi Salah Eddine", out)
        self.assertIn("FOX COMPANY", out)
        # Piped output disables the animated loader, so the completion
        # line (not the "Scanning..." line) proves the scan ran.
        self.assertIn("Investigation complete", out)


if __name__ == "__main__":
    unittest.main()
