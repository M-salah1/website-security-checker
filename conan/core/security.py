#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Secret redaction — the hard rule of CONAN FRAMEWORK.

Passwords, session tokens, API keys and cookie values are NEVER printed,
logged or stored in reports. When a scanner finds a secret, it reports the
exposure (where, what kind of secret, which key name) with the value masked,
and advises rotation. This module is the single place that enforces it.
"""
import re

MASK = "••••••••"

# key names that mark a value as secret (case-insensitive)
_SECRET_KEY_WORDS = ("PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
                     "AUTH", "SESSION", "PRIVATE", "CREDENTIAL", "BEARER")

# value patterns: password=..., token: "...", Authorization: Bearer xxx, etc.
_VALUE_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[^'\"\s,;]{1,80}"),
    re.compile(r"(?i)(authorization\s*:\s*(bearer|basic)\s+)[^\s,;]{1,80}"),
    re.compile(r"(?i)(set-cookie\s*:\s*[^=;\s]+)=\s*[^;\s]{1,120}"),
]


def is_secret_key(name):
    if not name:
        return False
    up = str(name).upper()
    return any(w in up for w in _SECRET_KEY_WORDS)


def mask_value(value):
    """Always return the mask — values never leave this function."""
    return MASK


def redact_text(text):
    """Replace secret values inside a larger text with the mask.

    Key names are kept (so the user knows WHICH secret leaked), values are not.
    """
    if not text:
        return text
    out = str(text)
    for pat in _VALUE_PATTERNS:
        out = pat.sub(lambda m: m.group(0).split("=", 1)[0].split(":", 1)[0] + "=" + MASK
                      if "=" in m.group(0) else m.group(1) + MASK, out)
    return out


def redact_headers(headers):
    """Return a copy of headers with sensitive values masked."""
    if not headers:
        return {}
    out = {}
    for k, v in dict(headers).items():
        lk = str(k).lower()
        if lk in ("authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"):
            out[k] = MASK
        elif is_secret_key(k):
            out[k] = MASK
        else:
            out[k] = v
    return out


def safe_detail(detail, max_len=200):
    """Detail text safe for reports: redacted and length-bounded."""
    return redact_text(detail or "")[:max_len]
