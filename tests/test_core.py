#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Core tests — i18n, navigation, cases, redaction (offline)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.i18n import I18n, translate
from conan.core.navigation import NavigationStack, NavCommand, SessionStore
from conan.core.security import redact_text
from conan.storage.cases import CaseStore, evidence_hash


class TestI18n(unittest.TestCase):
    def test_all_languages_have_all_keys(self):
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "conan", "localization")
        keys = None
        for lang in ("ar", "fr", "en"):
            with open(os.path.join(base, lang + ".json"), encoding="utf-8") as f:
                data = json.load(f)
            if keys is None:
                keys = set(data)
            else:
                self.assertEqual(keys, set(data), "key mismatch in %s" % lang)

    def test_translate(self):
        self.assertEqual(translate("menu_17", "ar"), "خروج")
        self.assertEqual(translate("menu_17", "fr"), "Quitter")
        self.assertEqual(translate("menu_17", "en"), "Exit")

    def test_rtl_marker(self):
        i = I18n("ar")
        self.assertTrue(i.rtl("x").startswith("\u200f"))
        i.set("en")
        self.assertEqual(i.rtl("x"), "x")


class TestNavigation(unittest.TestCase):
    def test_stack(self):
        n = NavigationStack()
        n.push("home")
        n.push("scan", {"url": "https://example.com"})
        self.assertEqual(n.depth(), 2)
        self.assertEqual(n.current()["screen"], "scan")
        n.pop()
        self.assertEqual(n.current()["screen"], "home")
        n.home()
        self.assertEqual(n.depth(), 1)

    def test_sessions_persist(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = SessionStore(base_dir=tmp)
            s.add("CN-20261115-0001", "website-investigation",
                  "https://example.com", {"score": 28})
            s2 = SessionStore(base_dir=tmp)
            self.assertEqual(s2.get("CN-20261115-0001")["target"],
                             "https://example.com")


class TestCases(unittest.TestCase):
    def test_case_create_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CaseStore(base_dir=tmp)
            rec = store.create("website-investigation", "https://example.com",
                               ["dns"], "passive",
                               {"score": 28, "grade": "F", "confidence": 88,
                                "duration_s": 1.0,
                                "findings": [{"name": "Missing HSTS"}]})
            self.assertTrue(rec["case_id"].startswith("CN-"))
            self.assertEqual(rec["evidence_hash"],
                             evidence_hash([{"name": "Missing HSTS"}]))
            files = store.export_evidence(rec["case_id"], os.path.join(tmp, "ev"))
            self.assertEqual(len(files), 3)
            self.assertTrue(all(os.path.exists(f) for f in files))


class TestRedaction(unittest.TestCase):
    def test_passwords_and_tokens_never_shown(self):
        red = redact_text("api_key=sk-1234567890 password=hunter2 token=abc123")
        for secret in ("sk-1234567890", "hunter2", "abc123"):
            self.assertNotIn(secret, red)


if __name__ == "__main__":
    unittest.main()
