#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verification Mode — compare owner-provided secrets against what the
scan found, WITHOUT ever displaying, storing or logging the secret.

The real scenario: a site owner gives the tester a value (a password,
an API key, a cookie value, a username) plus authorization, and asks:
"did your scan find a hole that leads to THIS?" — or the owner plants
a FAKE value and asks: "is this real or fake?" The tester already HAS
the value from the owner. What they need is the comparison, not a
second copy of the secret.

How it works: the tester types the value hidden (getpass). Conan
re-fetches, in memory only, the public places the scan found (exposed
files, discovered pages, public paths) and checks whether the exact
value appears in any of them — and whether a session cookie value
equals it. The answer is only YES/NO + the location. The value itself
never appears in any output, report, log, case or file, and the local
reference is wiped right after the check.

Why the value is never displayed: a displayed secret is a leaked
secret. It lands in terminal scrollback, screenshots, saved reports
and history files — and that leak is exactly what would destroy the
tester's credibility with the owner. The comparison is the job; the
display is the risk.

Authorization: verification runs only after an authorized scan (the
user's own site or a site with written permission from its owner).
"""
from ..core.timeout import call_with_timeout
from ._http import get as http_get

MAX_CHECKS = 25


def candidate_urls(scan):
    """Public places the scan found, to re-check for the value."""
    base = (scan.get("target") or "").rstrip("/")
    urls = []
    if base:
        urls.append(base + "/")
    for f in (scan.get("exposure") or {}).get("public_files") or []:
        if isinstance(f, dict) and f.get("url"):
            urls.append(f["url"])
    for p in (scan.get("discovery") or {}).get("pages") or []:
        u = p.get("url") if isinstance(p, dict) else str(p)
        if u:
            urls.append(u)
    for d in (scan.get("deep_paths") or []):
        if isinstance(d, dict) and d.get("category") == "PUBLIC" \
                and d.get("path") and base:
            urls.append(base + d["path"])
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:MAX_CHECKS]


def _body_contains(url, secret, timeout=10):
    r = http_get(url, timeout=timeout, max_bytes=200000)
    return bool(r.get("body") and secret in r["body"])


def _cookie_matches(url, secret, timeout=10):
    """Does any Set-Cookie value on the URL equal the secret?
    Checked in memory only; the value is never returned."""
    r = http_get(url, timeout=timeout, max_bytes=0)
    headers = r.get("headers")
    raw = []
    try:
        get_all = getattr(headers, "get_all", None)
        raw = get_all("Set-Cookie") or [] if callable(get_all) else []
    except Exception:
        raw = []
    for header in raw:
        first = header.split(";", 1)[0]
        if "=" in first:
            value = first.split("=", 1)[1].strip()
            if value and value == secret:
                return True
    return False


def verify_secret(scan, secret, timeout=10):
    """Check whether `secret` appears in any public place the scan
    found. Returns {"found": [{where, kind}], "checked": n,
    "cookie_match": bool}. The secret is never in the result."""
    if not secret:
        return {"found": [], "checked": 0, "cookie_match": False,
                "error": "empty value"}
    found = []
    urls = candidate_urls(scan)
    for url in urls:
        try:
            hit = call_with_timeout(
                lambda u=url: _body_contains(u, secret, timeout), 15)
        except Exception:
            hit = False
        if hit is True:
            found.append({"where": url, "kind": "page/file body"})
    cookie_match = False
    base = (scan.get("target") or "").rstrip("/")
    if base:
        try:
            cookie_match = bool(call_with_timeout(
                lambda: _cookie_matches(base + "/", secret, timeout), 15))
        except Exception:
            cookie_match = False
    return {"found": found, "checked": len(urls),
            "cookie_match": cookie_match}
