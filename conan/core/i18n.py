#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internationalization — ar / fr / en from JSON files.

The selected language is remembered in conan-settings.json (configuration).
Arabic output is prefixed with the RLM marker (U+200F) so terminal lines
render right-to-left instead of reversed.
"""
import json
import os

SUPPORTED = ("ar", "fr", "en")
RLM = "\u200f"

_cache = {}


def _locales_dir():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "localization")


def _load(lang):
    if lang in _cache:
        return _cache[lang]
    path = os.path.join(_locales_dir(), lang + ".json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    _cache[lang] = data
    return data


def translate(key, lang="ar"):
    """Return the localized string for `key`, falling back to English, then the key."""
    for cand in (lang, "en"):
        text = _load(cand).get(key)
        if text:
            return text
    return key


class I18n:
    def __init__(self, lang="ar"):
        self.lang = lang if lang in SUPPORTED else "ar"

    def set(self, lang):
        if lang in SUPPORTED:
            self.lang = lang

    def t(self, key):
        return translate(key, self.lang)

    def out(self, text):
        """Print a line, RTL-safe for Arabic."""
        if self.lang == "ar":
            print(RLM + str(text))
        else:
            print(str(text))

    def rtl(self, text):
        return RLM + str(text) if self.lang == "ar" else str(text)
