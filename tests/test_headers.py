#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Header + cookie tests — live site + offline parsing."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeHeaders(dict):
    def get_all(self, name):
        return [v for k, v in self.items() if k.lower() == name.lower()]


class TestHeadersLive(unittest.TestCase):
    def test_example_headers(self):
        from conan.scanners.headers import analyze_headers
        try:
            res = analyze_headers("https://example.com")
        except Exception as exc:
            self.skipTest("network unavailable: %s" % exc)
        self.assertTrue(res.get("verifiable"))
        self.assertTrue(any(c["name"] == "HSTS" for c in res["checks"]))
        self.assertTrue(any(f["name"] == "Missing HSTS" for f in res["findings"]))


class TestCookiesOffline(unittest.TestCase):
    def test_cookie_parsing_and_masking(self):
        from conan.core import engine
        hdrs = FakeHeaders()
        hdrs["Set-Cookie"] = "sessionid=abc123secret; Path=/; HttpOnly"
        cookies = engine.parse_cookies(hdrs)
        self.assertEqual(len(cookies), 1)
        self.assertEqual(cookies[0]["name"], "sessionid")
        self.assertTrue(cookies[0]["httponly"])
        self.assertFalse(cookies[0]["secure"])
        # values are never exposed in the parsed output
        self.assertNotIn("abc123secret", str(cookies))

    def test_cookie_classification(self):
        from conan.scanners.cookies import classify_cookie
        self.assertEqual(classify_cookie({"name": "PHPSESSID"}), "session")
        self.assertEqual(classify_cookie({"name": "prefs"}), "persistent")


if __name__ == "__main__":
    unittest.main()
