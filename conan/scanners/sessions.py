#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Session analysis — cookie rotation, expiry and attributes.

Only the scanner's own session cookies are inspected. Other users' sessions
are never touched. Values are always masked.
"""
from ..core import engine


def analyze_session(cookies_before, cookies_after):
    """Compare session cookies before/after an action (e.g. login).

    Returns rotation status and attribute checks.
    """
    before = {c["name"]: c for c in (cookies_before or [])}
    after = {c["name"]: c for c in (cookies_after or [])}
    out = {"rotated": [], "not_rotated": [], "missing_after": [],
           "secure_issues": []}
    for name, cb in before.items():
        ca = after.get(name)
        if ca is None:
            out["missing_after"].append(name)
            continue
        # values are never compared for display; rotation is inferred only
        # from the cookie's presence change — we cannot see values here
        # because parse_cookies masks them. Rotation is therefore reported
        # by the auth auditor using raw header length changes instead.
        if not ca["secure"] or not ca["httponly"]:
            out["secure_issues"].append(name)
    return out


def session_cookie_names(cookies):
    return [c["name"] for c in (cookies or [])
            if "sess" in c["name"].lower() or "session" in c["name"].lower()
            or c["name"].lower() in ("phpsessid", "jsessionid", "connect.sid",
                                     "laravel_session", "csrftoken")]


def rotation_check(raw_before, raw_after):
    """Did the session identifier change after login?

    raw_before/raw_after are the raw Set-Cookie header strings of the
    scanner's own requests. Only a boolean is returned — never the values.
    """
    def _sess(raw):
        import re
        m = re.search(r"(?i)(?:session|phpsessid|jsessionid|laravel_session|connect\.sid)=([^;]+)", raw or "")
        return m.group(1) if m else ""
    b, a = _sess(raw_before), _sess(raw_after)
    if not b or not a:
        return {"rotated": None, "note": "no session cookie observed"}
    return {"rotated": b != a,
            "note": "session id changed after login" if b != a else "same session id after login"}
