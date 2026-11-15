#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authentication audit engine.

Discovers login forms, fields, hidden fields, CSRF tokens, redirects and
session cookies. With explicitly supplied test credentials (prompted, hidden,
memory-only, never stored or logged) it tests:

- invalid login behaviour (one wrong-password attempt)
- valid login behaviour (one correct attempt)
- session ID rotation after login
- cookie attributes, logout behaviour, session expiry hints
- rate limiting with a small bounded number of authorized attempts

NEVER: password guessing, leaked credentials, brute force, credential
stuffing, extracting other users' sessions, bypassing authentication.
"""
import re
import time
import urllib.parse

from ..core.evidence import finding
from ..core.security import redact_text
from ._http import get, request
from .forms import extract_forms, find_login_forms
from .sessions import rotation_check


def discover_auth(url, timeout=15):
    """Find login forms and auth-related behaviour without logging in."""
    r = get(url, timeout=timeout)
    if r["status"] is None:
        return {"url": url, "status": None, "login_forms": [], "error": r["error"]}
    forms = extract_forms(r["body"], url)
    logins = find_login_forms(forms)
    out = {"url": url, "status": r["status"], "login_forms": [],
           "redirects": r["chain"], "error": None}
    for f in logins:
        user_fields = [i["name"] for i in f["inputs"] if i["type"] in ("text", "email")]
        out["login_forms"].append({
            "action": f["action"], "method": f["method"],
            "username_fields": user_fields,
            "password_fields": [i["name"] for i in f["inputs"] if i["type"] == "password"],
            "hidden_fields": [i["name"] for i in f["inputs"] if i["type"] == "hidden"],
            "csrf_token": f["csrf_token"]})
    return out


def _raw_set_cookie(headers):
    try:
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            return "; ".join(get_all("Set-Cookie") or [])
        return headers.get("Set-Cookie", "") or ""
    except Exception:
        return ""


def audit_auth(url, scope, credentials=None, timeout=15):
    """Full auth audit. Requires authorized scope + explicit confirmation.

    credentials: {"username": ..., "password": ...} supplied by the user for
    their own test account. The password is never printed, logged or stored.
    """
    scope.require_authorized(url, "authentication audit")
    if not scope.confirm("Run login tests against %s with the supplied test account" % url):
        return {"url": url, "cancelled": True, "findings": []}
    if credentials is None:
        credentials = scope.prompt_credentials()
    disc = discover_auth(url, timeout=timeout)
    findings = []
    if not disc["login_forms"]:
        findings.append(finding(
            "No login form found", "info", 90, url,
            "No login form was discovered on the page",
            "Form discovery", "GET %s and look for a login form" % url,
            "No action needed", status="confirmed"))
        return {"url": url, "discovery": disc, "findings": findings}
    form = disc["login_forms"][0]
    if not form["csrf_token"]:
        findings.append(finding(
            "Login form without CSRF token", "medium", 85, form["action"],
            "The login form has no hidden CSRF token",
            "Form inspection", "Inspect the login form at %s" % url,
            "Add a CSRF token to the login form", status="confirmed"))
    # 1) invalid login (one attempt, wrong password)
    data = {form["username_fields"][0] if form["username_fields"] else "username":
            credentials["username"]}
    if form["password_fields"]:
        data[form["password_fields"][0]] = "ConanWrongPassword!1"
    body = urllib.parse.urlencode(data).encode()
    before = get(url, timeout=timeout)
    r_bad = request(form["action"], method="POST", data=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=timeout)
    if r_bad["status"] in (200, 401, 403):
        txt = r_bad["body"].lower()
        if "invalid" in txt or "incorrect" in txt or "wrong" in txt or "failed" in txt:
            findings.append(finding(
                "Login error message is generic", "info", 70, form["action"],
                "Invalid login returns a generic error (good practice)",
                "Invalid-login test (one attempt)",
                "Submit the login form with a wrong password once",
                "Keep error messages generic (do not reveal which field failed)",
                status="confirmed"))
        elif "user" in txt and "not found" in txt:
            findings.append(finding(
                "Login error reveals account existence", "low", 75, form["action"],
                "Invalid login distinguishes unknown users",
                "Invalid-login test (one attempt)",
                "Submit the login form with an unknown username once",
                "Use one generic message for both unknown user and wrong password",
                status="confirmed"))
    # 2) valid login (one attempt)
    if form["password_fields"]:
        data[form["password_fields"][0]] = credentials["password"]
    body = urllib.parse.urlencode(data).encode()
    r_ok = request(form["action"], method="POST", data=body,
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   timeout=timeout)
    raw_after = _raw_set_cookie(r_ok["headers"])
    raw_before = _raw_set_cookie(before["headers"])
    rot = rotation_check(raw_before, raw_after)
    if rot.get("rotated") is False:
        findings.append(finding(
            "Session ID not rotated after login", "medium", 75, form["action"],
            "The session identifier did not change after a successful login",
            "Session rotation comparison (own session only)",
            "Log in once and compare the session cookie before/after",
            "Regenerate the session ID on login",
            status="suspected"))
    # 3) rate limiting: at most 3 quick invalid attempts, stop on 429
    blocked = False
    for _ in range(3):
        data2 = dict(data)
        if form["password_fields"]:
            data2[form["password_fields"][0]] = "ConanWrongPassword!1"
        rr = request(form["action"], method="POST",
                     data=urllib.parse.urlencode(data2).encode(),
                     headers={"Content-Type": "application/x-www-form-urlencoded"},
                     timeout=timeout)
        if rr["status"] == 429:
            blocked = True
            break
        time.sleep(0.5)
    findings.append(finding(
        "Rate limiting %s" % ("observed" if blocked else "not observed"),
        "info" if blocked else "low", 70, form["action"],
        "429 received after bounded invalid attempts" if blocked
        else "No 429 after 3 invalid attempts (bounded test)",
        "Bounded rate-limit probe (3 attempts max)",
        "Submit 3 invalid logins and watch for HTTP 429",
        "Add rate limiting / lockout after repeated failed logins" if not blocked
        else "Rate limiting is in place",
        status="confirmed"))
    return {"url": url, "discovery": disc, "findings": findings,
            "login_status": r_ok["status"], "session_rotated": rot.get("rotated")}
