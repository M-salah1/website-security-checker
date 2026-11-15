#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Anti-phishing / website authenticity analyzer.

Risk score 0..100 with reasons and evidence. Rules are conservative:
- HTTPS alone never proves legitimacy.
- A new domain alone never proves fraud.
- Classification: LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN.
"""
import re
import urllib.parse

from ..core import engine
from ._http import get

SUSPICIOUS_WORDS = ("secure", "login", "verify", "update", "account", "bank",
                    "wallet", "support", "free", "bonus", "gift", "confirm",
                    "password", "signin", "auth")


def _levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]


def _has_homograph(host):
    """Non-ASCII / mixed-script / punycode indicators."""
    if host.startswith("xn--") or ".xn--" in host:
        return True
    return any(ord(ch) > 127 for ch in host)


def _similarity(a, b):
    if not a or not b:
        return 0.0
    dist = _levenshtein(a, b)
    return max(0.0, 1.0 - dist / float(max(len(a), len(b))))


def analyze_phishing(url, official_domain=None, timeout=15):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    domain = engine.registrable_domain(host)
    reasons = []
    score = 0  # risk points, 0..100

    # 1) homograph / IDN
    if _has_homograph(host):
        score += 30
        reasons.append("Unicode/IDN homograph indicators (punycode or non-ASCII in host)")
    # 2) spelling similarity to the official domain
    if official_domain:
        off = official_domain.lower().lstrip("www.")
        sim = _similarity(domain, off)
        if domain != off and sim >= 0.75:
            score += 30
            reasons.append("Domain is %.0f%% similar to official domain %s (possible typosquat)"
                           % (sim * 100, off))
        elif domain == off:
            score -= 10
            reasons.append("Domain matches the official domain supplied by the user")
    # 3) suspicious subdomains / words
    parts = host.split(".")
    if len(parts) > 3:
        score += 10
        reasons.append("Unusually deep subdomain chain (%d labels)" % len(parts))
    if any(w in host for w in SUSPICIOUS_WORDS) and official_domain \
            and domain != official_domain.lower().lstrip("www."):
        score += 10
        reasons.append("Suspicious keyword in host (%s)" % host)
    # 4) domain age (when WHOIS is reliable)
    whois = engine.get_whois(domain)
    created = whois.get("created") or ""
    if created:
        try:
            import datetime
            dt = datetime.datetime.strptime(created.split("T")[0], "%Y-%m-%d")
            age_days = (datetime.datetime.now() - dt).days
            if age_days < 30:
                score += 10
                reasons.append("Domain is very new (%d days old) — one signal among others, not proof of fraud" % age_days)
            elif age_days > 365:
                score -= 5
                reasons.append("Domain is %d days old" % age_days)
        except Exception:
            pass
    else:
        reasons.append("Domain age could not be verified (WHOIS redacted or unavailable)")
    # 5) TLS
    tls = engine.check_tls(host) if parsed.scheme == "https" else {"ok": False}
    if parsed.scheme != "https":
        score += 15
        reasons.append("Site does not use HTTPS")
    elif not tls.get("ok"):
        score += 10
        reasons.append("TLS certificate could not be validated here")
    # 6) redirects + login form destinations
    r = get(url, timeout=timeout)
    if r["status"] is not None:
        if len(r["chain"]) >= 3:
            score += 10
            reasons.append("Long redirect chain (%d hops)" % len(r["chain"]))
        forms = []
        try:
            from .forms import extract_forms
            forms = extract_forms(r["body"], url)
        except Exception:
            forms = []
        login_forms = [f for f in forms if "login" in f["kinds"] or "password" in f["kinds"]]
        for f in login_forms:
            dest = urllib.parse.urlparse(f["action"]).hostname or ""
            if dest and dest.lower() != host:
                score += 20
                reasons.append("Login form submits to a different domain: %s" % dest)
    else:
        reasons.append("Site could not be fetched for form analysis (%s)" % (r["error"] or ""))
    score = max(0, min(100, score))
    if score >= 70:
        cls = "CRITICAL"
    elif score >= 45:
        cls = "HIGH"
    elif score >= 20:
        cls = "MEDIUM"
    elif score > 0:
        cls = "LOW"
    else:
        cls = "LOW"
    confidence = 90 if official_domain else 70
    return {"url": url, "domain": domain, "host": host,
            "risk_score": score, "classification": cls,
            "reasons": reasons, "confidence": confidence,
            "domain_age": created, "tls_ok": bool(tls.get("ok"))}
