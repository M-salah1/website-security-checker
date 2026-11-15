#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security-headers engine — deep analysis with evidence status."""
from ..core import engine
from ..core.evidence import finding
from ._http import get

REQUIRED = [
    ("strict-transport-security", "HSTS", "high",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "Content-Security-Policy", "medium",
     "Add a CSP, start with default-src 'self' (missing CSP does not prove XSS)"),
    ("x-frame-options", "X-Frame-Options", "medium",
     "Add X-Frame-Options: DENY or SAMEORIGIN"),
    ("x-content-type-options", "X-Content-Type-Options nosniff", "medium",
     "Add X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Referrer-Policy", "low",
     "Add Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "Permissions-Policy", "low",
     "Add Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "low",
     "Add Cross-Origin-Opener-Policy: same-origin"),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy", "low",
     "Add Cross-Origin-Embedder-Policy: require-corp"),
]


def analyze_headers(url, timeout=15):
    """Return checks with evidence + findings. A missing header is a missing
    protection layer — never presented as a confirmed exploit."""
    r = get(url, timeout=timeout)
    if r["status"] is None:
        return {"url": url, "status": None, "checks": [], "findings": [],
                "error": r["error"], "verifiable": False}
    lower = {str(k).lower(): v for k, v in dict(r["headers"]).items()}
    csp = lower.get("content-security-policy", "")
    csp_info = engine.analyze_csp(csp)
    hsts_info = engine.analyze_hsts(lower.get("strict-transport-security", ""))
    checks, findings = [], []
    for hdr, title, sev, fix in REQUIRED:
        present = bool(lower.get(hdr))
        if hdr == "x-frame-options" and not present and "frame-ancestors" in csp:
            present = True
        checks.append({"name": title, "present": present, "value": lower.get(hdr, ""),
                       "evidence": "confirmed"})
        if not present:
            findings.append(finding(
                "Missing %s" % title, sev, 95, url,
                "Header %s is absent from the HTTP response" % hdr,
                "HTTP response header inspection",
                "GET %s and inspect response headers" % url, fix,
                status="confirmed"))
    if csp_info.get("unsafe_inline") or csp_info.get("unsafe_eval"):
        findings.append(finding(
            "Weak CSP", "medium", 85, url,
            "CSP contains unsafe-inline or unsafe-eval",
            "CSP directive analysis",
            "GET %s and read the Content-Security-Policy header" % url,
            "Remove unsafe-inline/eval; use nonce or hash",
            status="confirmed"))
    if hsts_info.get("max_age") is not None and hsts_info["max_age"] < 31536000:
        findings.append(finding(
            "HSTS max-age too short", "medium", 85, url,
            "HSTS max-age=%d" % hsts_info["max_age"],
            "HSTS directive analysis",
            "GET %s and read Strict-Transport-Security" % url,
            "Raise max-age to at least 31536000",
            status="confirmed"))
    return {"url": url, "status": r["status"], "checks": checks,
            "findings": findings, "error": None, "verifiable": True,
            "hsts": hsts_info, "csp": csp_info}
