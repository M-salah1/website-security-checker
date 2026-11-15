#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN DEFENSE CENTER — hardening, deterrence and incident response.

Everything here is DEFENSIVE and runs on the user's OWN server or in
their own report — it never touches an attacker's system:

- Hardening configuration text (Apache / Nginx / CSP) the user installs
  on their own site to block attacks before they happen.
- Rate-limit and blocklist guidance built from scan evidence.
- An incident-response plan (detect → contain → eradicate → recover).
- A takedown / abuse-report letter template (text only — the user sends
  it to the registrar or host; Conan never sends anything itself).

What is deliberately NOT here: hacking back, attacking an attacker's
machine, DDoS, credential attacks, or any "counter-attack". Deterrence
in this tool means: make the target hard, collect evidence properly,
and report through official channels so the authorities act.
"""
import textwrap

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: https:; font-src 'self'; object-src 'none'; "
       "base-uri 'self'; frame-ancestors 'self'; form-action 'self'; "
       "upgrade-insecure-requests")


def csp_policy():
    return CSP


def apache_snippet():
    return textwrap.dedent("""\
        # CONAN hardening — Apache (.htaccess or vhost), your own server only
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" env=HTTPS
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"
        Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
        Header always set Content-Security-Policy "%s"
        # Hide version info
        ServerTokens Prod
        ServerSignature Off
        # Block common sensitive paths
        RedirectMatch 404 "(?i)\\.(env|git|svn|sql|bak)$"
        """ % CSP)


def nginx_snippet():
    return textwrap.dedent("""\
        # CONAN hardening — Nginx (server block), your own server only
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Content-Security-Policy "%s" always;
        server_tokens off;
        # Rate limiting — 10 requests/second per IP, burst 20 (deterrence, not attack)
        limit_req_zone $binary_remote_addr zone=conan:10m rate=10r/s;
        limit_req zone=conan burst=20 nodelay;
        # Block common sensitive paths
        location ~* \\.(env|git|svn|sql|bak)$ { return 404; }
        """ % CSP)


def rate_limit_guidance():
    return [
        "Login pages: max 5 failed attempts per 15 minutes per IP, then lock the account temporarily and alert the owner.",
        "Contact and password-reset forms: max 3 submissions per hour per IP.",
        "APIs: token bucket per key (e.g. 100 requests/minute), return 429 with Retry-After.",
        "Block an IP only after repeated, logged abuse — and always keep the logs as evidence.",
        "Never publish the blocklist: it tells attackers exactly what you detect.",
    ]


def incident_response_plan():
    return [
        ("1. DETECT", "Confirm what happened from logs and the Conan scan; do not delete anything yet."),
        ("2. CONTAIN", "Revoke exposed sessions and API keys, block the abusive IP at the firewall, put the affected page in maintenance mode if needed."),
        ("3. PRESERVE EVIDENCE", "Export logs, save the URLs, timestamps and message screenshots, hash the files (SHA-256) and store them offline."),
        ("4. ERADICATE", "Patch the vulnerability the scan found, rotate every secret that may have leaked, force password resets for affected accounts."),
        ("5. RECOVER", "Restore from a known-clean backup, re-run a full Conan scan and confirm the score improved."),
        ("6. REPORT", "Report threats, harassment or child-safety incidents to the police and the official channels (NCMEC / INHOPE / INTERPOL)."),
        ("7. LEARN", "Write down what failed, add the check to your deployment checklist, and schedule the next scan."),
    ]


def takedown_request_template(target_url, kind="abusive content"):
    return textwrap.dedent("""\
        Subject: Abuse report — %s at %s

        Hello Abuse Team,

        I am reporting %s hosted at or linked from the following URL:

        %s

        This content involves threats / harassment / illegal material.
        I have preserved evidence (URLs, timestamps and screenshots with
        SHA-256 hashes) and I am also reporting it to law enforcement.

        Please investigate and remove the content, and confirm the action
        taken. I am available to provide the preserved evidence to the
        authorities on request.

        Thank you,
        (your name — only send this from your own email address)
        """ % (kind, target_url, kind, target_url))


def hardening_checklist(findings):
    """Map scan findings to concrete hardening steps (text only)."""
    mapping = {
        "Missing HSTS": "Enable HSTS (see Apache/Nginx snippet) and serve everything over HTTPS.",
        "Missing Content-Security-Policy": "Deploy the strict CSP from csp_policy() and test it in report-only mode first.",
        "Missing X-Frame-Options": "Add X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors).",
        "Missing X-Content-Type-Options nosniff": "Add X-Content-Type-Options: nosniff.",
        "Missing Referrer-Policy": "Add Referrer-Policy: strict-origin-when-cross-origin.",
        "Missing Permissions-Policy": "Add Permissions-Policy disabling camera, microphone and geolocation.",
        "Insecure cookies": "Set Secure + HttpOnly + SameSite=Lax/Strict on every session cookie.",
        "Missing security.txt": "Publish /.well-known/security.txt with a contact address.",
    }
    out = []
    for f in findings or []:
        step = mapping.get(f.get("name", ""))
        if step and step not in out:
            out.append(step)
    if not out:
        out.append("No matching findings — run a full scan (menu 1) first, then return here for a tailored checklist.")
    return out
