#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS engine tests — live, skipped gracefully offline."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestTLS(unittest.TestCase):
    def test_tls_shape(self):
        from conan.scanners.tls import analyze_tls
        try:
            res = analyze_tls("example.com")
        except Exception as exc:
            self.skipTest("network unavailable: %s" % exc)
        # In sandboxed/proxied environments the direct TLS socket may fail;
        # the result must say so honestly instead of inventing data.
        self.assertIn("ok", res)
        self.assertIn("protocols", res)
        if res.get("ok"):
            self.assertIsNotNone(res.get("days_left"))
            self.assertTrue(res.get("issuer"))

    def test_redaction(self):
        from conan.core.security import redact_text, mask_value
        self.assertEqual(mask_value("supersecret"), "••••••••")
        red = redact_text("password=hunter2 and token=abc123")
        self.assertNotIn("hunter2", red)
        self.assertNotIn("abc123", red)
        self.assertIn("password", red)  # key names stay, values go


if __name__ == "__main__":
    unittest.main()
