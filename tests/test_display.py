#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Display tests — Arabic Termux fix + single-line loader."""
import contextlib
import io
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core import terminal
from conan.core.animation import Investigation, play_intro
from conan.core.configuration import DEFAULTS
from conan.core.i18n import (I18n, ar_display, get_reverse_arabic,
                              reverse_arabic_runs, set_reverse_arabic)


class TestReverseArabic(unittest.TestCase):
    def tearDown(self):
        set_reverse_arabic(False)

    def test_word_reversed(self):
        # The user's own example: write "يبرع" so the terminal shows "عربي".
        self.assertEqual(reverse_arabic_runs("عربي"), "يبرع")

    def test_mixed_line_keeps_digits_and_latin(self):
        self.assertEqual(reverse_arabic_runs("اضغط 0 للرجوع"),
                         "طغضا 0 عوجرلل")
        self.assertEqual(reverse_arabic_runs("https://example.com"), "https://example.com")
        self.assertEqual(reverse_arabic_runs("17"), "17")

    def test_ar_display_off_by_default(self):
        set_reverse_arabic(False)
        self.assertEqual(ar_display("عربي", "ar"), "عربي")
        self.assertFalse(get_reverse_arabic())

    def test_ar_display_on_reverses_only_arabic(self):
        set_reverse_arabic(True)
        self.assertEqual(ar_display("عربي", "ar"), "يبرع")
        self.assertEqual(ar_display("hello", "en"), "hello")
        self.assertEqual(ar_display("القائمة 17", "ar"), "ةمئاقلا 17")

    def test_out_reverse_mode_has_no_rlm(self):
        set_reverse_arabic(True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            I18n("ar").out("عربي")
        self.assertEqual(buf.getvalue(), "يبرع\n")

    def test_out_normal_mode_has_rlm(self):
        set_reverse_arabic(False)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            I18n("ar").out("عربي")
        self.assertTrue(buf.getvalue().startswith("\u200f"))

    def test_reverse_setting_defaults_on(self):
        self.assertTrue(DEFAULTS.get("reverse_arabic"))


class TestSingleLineLoader(unittest.TestCase):
    def test_log_stays_on_the_same_line(self):
        # With a TTY, log() must not print new lines: the latest message
        # joins the single animation line instead.
        with mock.patch.object(terminal, "is_tty", return_value=True):
            inv = Investigation(enabled=True, total=3)
            self.assertTrue(inv.enabled)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                inv.start()
                time.sleep(0.35)
                inv.log("[+] DNS resolved")
                inv.phase("headers")
                time.sleep(0.35)
                inv.log("[+] Headers done")
                time.sleep(0.25)  # let one frame draw the latest message
                inv.done()
            out = buf.getvalue()
        self.assertIn("[+] Headers done", out)
        # Only the final "complete" line ends with a newline.
        self.assertEqual(out.count("\n"), 1)

    def test_log_prints_when_not_a_tty(self):
        with mock.patch.object(terminal, "is_tty", return_value=False):
            inv = Investigation(enabled=True, total=1)
            self.assertFalse(inv.enabled)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                inv.log("[+] plain log")
            self.assertIn("[+] plain log", buf.getvalue())

    def test_intro_does_nothing_without_tty(self):
        with mock.patch.object(terminal, "is_tty", return_value=False):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                play_intro(enabled=True)
            self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
