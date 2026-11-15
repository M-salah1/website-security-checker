#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scope manager tests — offline."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.scope import ScopeManager, ScopeError


class TestScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope = ScopeManager(base_dir=self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_localhost_always_in_scope(self):
        self.assertTrue(self.scope.is_authorized("http://localhost:8000/test"))
        self.assertTrue(self.scope.is_authorized("http://127.0.0.1/"))

    def test_unknown_domain_not_authorized(self):
        self.assertFalse(self.scope.is_authorized("https://example.com/"))

    def test_authorize_and_persist(self):
        self.scope.authorize("https://example.com/", kind="owned")
        self.assertTrue(self.scope.is_authorized("https://example.com/page"))
        reloaded = ScopeManager(base_dir=self.tmp.name)
        self.assertTrue(reloaded.is_authorized("https://example.com/"))

    def test_require_authorized_raises(self):
        with self.assertRaises(ScopeError):
            self.scope.require_authorized("https://example.com/", "XSS test")

    def test_excluded_paths(self):
        self.assertTrue(self.scope.is_excluded("https://example.com/logout"))
        self.assertFalse(self.scope.is_excluded("https://example.com/about"))

    def test_bad_url_rejected(self):
        with self.assertRaises(ScopeError):
            self.scope.authorize("not-a-url", kind="owned")

    def test_local_kind_requires_private_host(self):
        with self.assertRaises(ScopeError):
            self.scope.authorize("https://example.com/", kind="local")


if __name__ == "__main__":
    unittest.main()
