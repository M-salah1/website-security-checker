#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cookie inspector — per-cookie analysis, values always masked."""
from ..core import engine
from ..core.evidence import finding
from ._http import get


def classify_cookie(cookie):
    """Session vs persistent: a cookie without Expires/Max-Age is a session cookie."""
    name = cookie.get("name", "")
    lower = name.lower()
    session_names = ("session", "sess", "phpsessid", "jsessionid", "connect.sid",
                     "laravel_session", "xsrf-token", "csrftoken", "auth")
    is_session = any(w in lower for w in session_names)
    return "session" if is_session else "persistent"


def analyze_cookies(url, timeout=15):
    """Fetch the URL and analyze every Set-Cookie independently."""
    r = get(url, timeout=timeout)
    cookies = engine.parse_cookies(r["headers"]) if r["status"] is not None else []
    findings = []
    for c in cookies:
        c["classification"] = classify_cookie(c)
        if not c["secure"] or not c["httponly"]:
            findings.append(finding(
                "Cookie without full protection", "medium", 85, url,
                "Cookie %s: Secure=%s HttpOnly=%s SameSite=%s (value masked)"
                % (c["name"], c["secure"], c["httponly"], c["samesite"] or "-"),
                "Set-Cookie header analysis (per-cookie)",
                "Send a request and inspect the Set-Cookie header of %s" % c["name"],
                "Add Secure, HttpOnly and SameSite=Lax to %s" % c["name"],
                status="confirmed"))
        if not c["samesite"]:
            findings.append(finding(
                "Cookie without SameSite", "low", 80, url,
                "Cookie %s has no SameSite attribute" % c["name"],
                "Set-Cookie header analysis (per-cookie)",
                "Send a request and inspect the Set-Cookie header of %s" % c["name"],
                "Add SameSite=Lax or Strict to %s" % c["name"],
                status="confirmed"))
    return {"url": url, "status": r["status"], "cookies": cookies,
            "findings": findings, "error": r["error"]}
