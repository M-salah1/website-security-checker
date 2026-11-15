#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Navigation tests — menu wizard input handling (offline, simulated stdin)."""
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.menu import MenuApp, _valid_url, _valid_ip
from conan.core.navigation import NavCommand


class TestValidation(unittest.TestCase):
    def test_valid_url(self):
        self.assertTrue(_valid_url("https://example.com"))
        self.assertTrue(_valid_url("http://localhost:8000/x"))
        self.assertFalse(_valid_url("example.com"))
        self.assertFalse(_valid_url("ftp://example.com"))
        self.assertFalse(_valid_url(""))

    def test_valid_ip(self):
        self.assertTrue(_valid_ip("8.8.8.8"))
        self.assertTrue(_valid_ip("2001:4860:4860::8888"))
        self.assertFalse(_valid_ip("999.1.1.1"))
        self.assertFalse(_valid_ip("example.com"))


class TestMenuInput(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def test_back_command_raises(self):
        app = MenuApp(no_animation=True)
        with mock.patch("builtins.input", return_value="BACK"):
            with self.assertRaises(NavCommand) as ctx:
                app.ask("Enter URL")
            self.assertEqual(ctx.exception.command, "BACK")

    def test_exit_command_raises(self):
        app = MenuApp(no_animation=True)
        with mock.patch("builtins.input", return_value="exit"):
            with self.assertRaises(NavCommand) as ctx:
                app.ask("Enter URL")
            self.assertEqual(ctx.exception.command, "EXIT")

    def test_ask_url_rejects_then_accepts(self):
        app = MenuApp(no_animation=True)
        with mock.patch("builtins.input", side_effect=["not-a-url", "https://example.com"]):
            self.assertEqual(app.ask_url(), "https://example.com")

    def test_ask_ip_rejects_then_accepts(self):
        app = MenuApp(no_animation=True)
        with mock.patch("builtins.input", side_effect=["bad", "8.8.8.8"]):
            self.assertEqual(app.ask_ip(), "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
