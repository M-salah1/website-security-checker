#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phishing engine tests — pure functions offline, one live check."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.scanners.phishing import _has_homograph, _levenshtein, _similarity


class TestPhishingPure(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(_levenshtein("example", "example"), 0)
        self.assertEqual(_levenshtein("example", "examp1e"), 1)
        self.assertEqual(_levenshtein("", "abc"), 3)

    def test_similarity(self):
        self.assertAlmostEqual(_similarity("paypal.com", "paypal.com"), 1.0)
        self.assertGreater(_similarity("paypa1.com", "paypal.com"), 0.8)
        self.assertLess(_similarity("totallydifferent.com", "paypal.com"), 0.5)

    def test_homograph(self):
        self.assertTrue(_has_homograph("xn--pple-43d.com"))
        self.assertTrue(_has_homograph("exаmple.com"))  # cyrillic 'а'
        self.assertFalse(_has_homograph("example.com"))


class TestPhishingLive(unittest.TestCase):
    def test_example_is_low_risk(self):
        from conan.scanners.phishing import analyze_phishing
        try:
            res = analyze_phishing("https://example.com")
        except Exception as exc:
            self.skipTest("network unavailable: %s" % exc)
        self.assertEqual(res["classification"], "LOW")
        self.assertLessEqual(res["risk_score"], 30)


if __name__ == "__main__":
    unittest.main()
