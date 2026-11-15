#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safe static analysis of website assets and local files.

Looks for suspicious JavaScript patterns, obfuscation indicators, unexpected
external scripts, suspicious redirects and known test signatures (EICAR).
Everything is read-only: no code is executed, nothing is uploaded.
"""
import hashlib
import re

from .test_samples import EICAR

SUSPICIOUS_PATTERNS = [
    (r"eval\s*\(", "eval() usage", "medium"),
    (r"document\.write\s*\(", "document.write() usage", "low"),
    (r"atob\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]", "base64 blob decoded at runtime", "medium"),
    (r"fromCharCode\s*\(", "fromCharCode obfuscation", "medium"),
    (r"window\.location\s*=\s*['\"]https?://[^'\"]+['\"]", "forced redirect", "medium"),
    (r"onerror\s*=", "onerror handler", "low"),
    (r"<iframe[^>]*src\s*=\s*['\"]https?://", "external iframe", "low"),
    (r"crypto\.subtle|WebAssembly\.instantiate", "crypto/WASM usage", "low"),
]

EXTERNAL_SCRIPT_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
REDIRECT_RE = re.compile(r"(?:location\.href|location\.replace|window\.location)\s*=\s*['\"]([^'\"]+)['\"]", re.I)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def analyze_text(name, text, base_url=""):
    """Static analysis of one text asset. Returns indicators + file hash."""
    indicators = []
    body = text or ""
    if EICAR in body:
        indicators.append({"pattern": "EICAR test string", "severity": "info",
                           "note": "Standard antivirus test file — harmless by design"})
    for pat, label, sev in SUSPICIOUS_PATTERNS:
        if re.search(pat, body, re.I):
            indicators.append({"pattern": label, "severity": sev,
                               "note": "Pattern observed in %s" % name})
    # entropy-ish obfuscation heuristic: very long single line of encoded text
    for line in body.splitlines():
        if len(line) > 2000 and re.search(r"[A-Za-z0-9+/=]{200,}", line):
            indicators.append({"pattern": "long encoded line (possible obfuscation)",
                               "severity": "medium",
                               "note": "Line of %d chars in %s" % (len(line), name)})
            break
    return {"name": name, "sha256": sha256_hex(body), "size": len(body),
            "indicators": indicators,
            "verdict": "suspicious" if any(i["severity"] in ("medium", "high")
                                           for i in indicators)
                      else "clean"}


def analyze_html(html, base_url=""):
    """Analyze a page: external scripts, redirects, embedded JS."""
    result = analyze_text("page", html or "", base_url)
    externals = []
    for src in EXTERNAL_SCRIPT_RE.findall(html or ""):
        externals.append(src)
    redirects = REDIRECT_RE.findall(html or "")
    result["external_scripts"] = externals
    result["redirects"] = redirects
    if externals:
        result["indicators"].append({"pattern": "%d external scripts" % len(externals),
                                     "severity": "info",
                                     "note": ", ".join(externals[:5])})
    return result
