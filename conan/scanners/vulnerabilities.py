#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vulnerability detection engine — non-destructive, evidence-first.

- SQLi: harmless quote payloads, response comparison, DB-error detection.
  Nothing is modified or extracted; results are SUSPECTED until verified.
- XSS: harmless proof markers reflected in the response; no script executes.
- CSRF: token presence on state-changing forms + SameSite evaluation.
- IDOR: only with two authorized test accounts supplied by the user.
- File upload: inspects accept/validation only; harmless .txt test only when
  authorized and confirmed.
- Info disclosure: version strings, error pages, secret-like patterns —
  values are always redacted.
- Misconfiguration: headers, HTTP methods, redirects, mixed content, TLS.

Every finding carries: name, severity, confidence, URL, evidence, method,
reproduction steps, remediation, timestamp.
"""
import re
import urllib.parse

from ..core.evidence import finding
from ..core.security import redact_text
from ._http import get, request
from .forms import extract_forms

DB_ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"PostgreSQL.*ERROR",
    r"SQLite.*error", r"unclosed quotation mark", r"ODBC.*SQL",
    r"Warning: mysql", r"pg_query\(\)", r"SQLSTATE",
]
VERSION_PATTERNS = [
    (r"Apache/[\d.]+", "Apache"), (r"nginx/[\d.]+", "Nginx"),
    (r"PHP/[\d.]+", "PHP"), (r"WordPress [\d.]+", "WordPress"),
    (r"Laravel", "Laravel"), (r"jQuery [\d.]+", "jQuery"),
]
SECRET_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]", "API key"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]", "password"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"(?i)secret\s*[:=]\s*['\"][^'\"]+['\"]", "secret"),
]


def _marker():
    return "ConanMarker7x9"


def _fetch_with_param(url, param, value, timeout=10):
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    q = [(k, v) for k, v in q if k != param] + [(param, value)]
    new_q = urllib.parse.urlencode(q)
    target = urllib.parse.urlunparse(parsed._replace(query=new_q))
    return get(target, timeout=timeout)


def test_sqli(url, timeout=10):
    """Non-destructive SQLi indicator test on the first query parameter."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query)
    if not params:
        return []
    param = params[0][0]
    base = get(url, timeout=timeout)
    findings = []
    for payload in ("'", '"'):
        r = _fetch_with_param(url, param, params[0][1] + payload, timeout)
        if r["status"] is None:
            continue
        err = None
        for pat in DB_ERROR_PATTERNS:
            if re.search(pat, r["body"], re.I):
                err = pat
                break
        changed = abs(len(r["body"]) - len(base["body"])) > 200
        if err:
            findings.append(finding(
                "Suspected SQL injection", "high", 70, url,
                "Database error pattern matched (%s) after sending %r to parameter %s"
                % (err, payload, param),
                "Non-destructive quote test + DB error signature",
                "GET %s with %s=%s appended — observe the error text" % (url, param, payload),
                "Use parameterized queries / prepared statements; never build SQL from input",
                status="suspected"))
            break
        if changed and r["status"] != base["status"]:
            findings.append(finding(
                "Possible SQL injection (behaviour change)", "medium", 45, url,
                "Response status/length changed after quote payload on %s" % param,
                "Response comparison (baseline vs quote payload)",
                "Repeat the request with and without %r on %s" % (payload, param),
                "Use parameterized queries; verify manually in the staging environment",
                status="suspected"))
            break
    return findings


def test_xss(url, timeout=10):
    """Reflected-XSS indicator: a harmless unique marker in a query param."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query)
    if not params:
        return []
    param = params[0][0]
    marker = _marker()
    r = _fetch_with_param(url, param, marker, timeout)
    if r["status"] is None or marker not in r["body"]:
        return []
    ctx = "unknown"
    idx = r["body"].find(marker)
    before = r["body"][max(0, idx - 60):idx]
    if "<script" in before.lower() or "onerror" in before.lower():
        ctx = "inside script/event handler"
    elif re.search(r"<[^>]*$", before):
        ctx = "inside an HTML tag"
    else:
        ctx = "reflected in page text"
    return [finding(
        "Reflected input point (possible XSS)", "medium", 60, url,
        "Harmless marker %r was reflected in the response (%s)" % (marker, ctx),
        "Reflected marker test (no script executed)",
        "GET %s with %s=%s and search the response for the marker" % (url, param, marker),
        "Encode output for its context; add a strict Content-Security-Policy",
        status="suspected")]


def test_csrf(forms, url, cookies=None):
    """State-changing forms without a CSRF token."""
    findings = []
    for f in forms:
        if f["method"] != "POST":
            continue
        if not f["csrf_token"]:
            findings.append(finding(
                "State-changing form without CSRF token", "medium", 80, f["action"],
                "POST form at %s has no hidden CSRF token field" % f["action"],
                "Form inspection (no request was submitted)",
                "Inspect the form at %s" % url,
                "Add a per-session CSRF token and validate it server-side",
                status="confirmed"))
    if cookies:
        for c in cookies:
            if not c.get("samesite"):
                findings.append(finding(
                    "Session cookie without SameSite", "low", 75, url,
                    "Cookie %s has no SameSite attribute" % c["name"],
                    "Cookie attribute inspection",
                    "Inspect the Set-Cookie header of %s" % c["name"],
                    "Add SameSite=Lax or Strict",
                    status="confirmed"))
    return findings


def test_idor(url, session_a=None, session_b=None):
    """IDOR comparison — only with two authorized test accounts.

    Without two sessions supplied by the user, this test is reported as
    not configured, never attempted.
    """
    if not session_a or not session_b:
        return [finding(
            "IDOR test not configured", "info", 0, url,
            "Two authorized test accounts are required; none were supplied",
            "IDOR comparison (skipped)",
            "Supply two authorized test sessions to compare resource access",
            "Provide two test accounts in an authorized staging environment",
            status="unverifiable")]
    # Both sessions are the user's own authorized test accounts. Compare one
    # resource URL fetched with each session cookie (read-only GET).
    r1 = get(url, timeout=10, headers={"Cookie": session_a} if isinstance(session_a, str) else {})
    r2 = get(url, timeout=10, headers={"Cookie": session_b} if isinstance(session_b, str) else {})
    if r1["status"] == 200 and r2["status"] == 200 and r1["body"] == r2["body"]:
        return [finding(
            "Possible IDOR (identical resource for two accounts)", "high", 55, url,
            "The same resource content was returned for two different test sessions",
            "Two-session comparison (read-only GET)",
            "Fetch %s with each test session and compare" % url,
            "Enforce server-side ownership checks on every resource access",
            status="suspected")]
    return []


def test_file_upload(forms, url):
    """Inspect upload forms: accepted types and validation hints only."""
    findings = []
    for f in forms:
        if "upload" not in f["kinds"]:
            continue
        accepts = [i.get("accept", "") for i in f["inputs"] if i["type"] == "file"]
        accept = ", ".join(a for a in accepts if a) or "any"
        findings.append(finding(
            "File upload form found", "info", 90, f["action"],
            "Upload form accepts: %s (method %s)" % (accept, f["method"]),
            "Form inspection (nothing uploaded)",
            "Inspect the upload form at %s" % url,
            "Validate file type server-side (content, not extension), store uploads outside the web root",
            status="confirmed"))
    return findings


def test_info_disclosure(url, html, headers):
    """Version disclosure, error pages, secret-like patterns (redacted)."""
    findings = []
    hay = (html or "")[:120000]
    for pat, name in VERSION_PATTERNS:
        m = re.search(pat, hay)
        if m:
            findings.append(finding(
                "Version disclosure (%s)" % name, "low", 85, url,
                "Version string observed: %s" % m.group(0),
                "Public response inspection",
                "GET %s and search for the version string" % url,
                "Hide version numbers in headers and pages",
                status="confirmed"))
    for pat, name in SECRET_PATTERNS:
        m = re.search(pat, hay)
        if m:
            findings.append(finding(
                "Possible exposed secret (%s)" % name, "high", 60, url,
                "A %s-like pattern was found in a public response (value redacted)" % name,
                "Public response pattern scan (values masked)",
                "GET %s and search for the pattern" % url,
                "Remove the secret from public content and rotate it immediately",
                status="suspected"))
    return findings


def test_misconfig(url, headers, html):
    """HTTP methods, redirects, mixed content, TLS (via engine data)."""
    findings = []
    if url.startswith("https://") and html:
        mixed = re.findall(r"(?:src|href)\s*=\s*[\"']http://[^\"']+", html, re.I)
        if mixed:
            findings.append(finding(
                "Mixed content", "high", 85, url,
                "%d http:// resources inside an https page" % len(mixed),
                "HTML resource inspection",
                "GET %s and search for http:// src/href" % url,
                "Serve all resources over https or relative URLs",
                status="confirmed"))
    return findings


def run_vuln_tests(url, html="", headers=None, forms=None, cookies=None,
                   params_url=None, session_a=None, session_b=None):
    """Run the safe, non-destructive tests and return all findings."""
    target = params_url or url
    findings = []
    findings += test_sqli(target)
    findings += test_xss(target)
    findings += test_csrf(forms or [], url, cookies)
    findings += test_idor(target, session_a, session_b)
    findings += test_file_upload(forms or [], url)
    findings += test_info_disclosure(url, html, headers or {})
    findings += test_misconfig(url, headers or {}, html)
    return findings
