#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internationalization — ar / fr / en from JSON files.

The selected language is remembered in conan-settings.json (configuration).
Arabic output is prefixed with the RLM marker (U+200F) so terminal lines
render right-to-left instead of reversed.
"""
import json
import os
import re

SUPPORTED = ("ar", "fr", "en")
RLM = "\u200f"

_cache = {}

# ---------------------------------------------------------------------------
# Arabic display fix for Termux.
#
# Some terminals (notably Termux) display an Arabic run in reverse visual
# order, so "عربي" shows up as "يبرع". When reverse mode is ON, every run
# of Arabic letters is printed pre-reversed ("يبرع"), so the terminal flips
# it back and the user reads "عربي". Latin text, digits, URLs and
# punctuation are never touched — only Arabic-letter runs are reversed.
# Default ON (the user asked for it); toggle in Settings (menu 16) or in
# conan-settings.json ("reverse_arabic": false).
# ---------------------------------------------------------------------------
_ARABIC_RUN = re.compile(
    r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]+")

_REVERSE_ARABIC = False


def set_reverse_arabic(value):
    global _REVERSE_ARABIC
    _REVERSE_ARABIC = bool(value)


def get_reverse_arabic():
    return _REVERSE_ARABIC


def reverse_arabic_runs(text):
    """Reverse each Arabic-letter run in `text`; leave the rest as-is."""
    if not text:
        return text
    return _ARABIC_RUN.sub(lambda m: m.group(0)[::-1], str(text))


def ar_display(text, lang="ar"):
    """Display form of `text`: reversed Arabic runs when reverse mode is on."""
    if lang == "ar" and _REVERSE_ARABIC:
        return reverse_arabic_runs(text)
    return text


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
        """Print a line, RTL-safe for Arabic.

        Normal mode: prefix RLM so the line reads right-to-left.
        Reverse mode (Termux fix): print the Arabic runs pre-reversed
        and do NOT add RLM — the terminal flips them back to readable.
        """
        if self.lang == "ar":
            if _REVERSE_ARABIC:
                print(reverse_arabic_runs(str(text)))
            else:
                print(RLM + str(text))
        else:
            print(str(text))

    def rtl(self, text):
        if self.lang != "ar":
            return str(text)
        if _REVERSE_ARABIC:
            return reverse_arabic_runs(str(text))
        return RLM + str(text)
