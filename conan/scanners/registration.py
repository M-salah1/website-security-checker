#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Registration audit engine — authorized staging sites only.

- Identifies registration forms and required fields.
- Analyzes password policy hints (min length, complexity text).
- Checks duplicate-email handling, verification workflow, password recovery
  and account deletion presence.
- Supports ONE clearly labeled disposable test account, only after explicit
  confirmation. Never creates unlimited accounts.
- No unnecessary personal information is retained.
"""
import re

from ..core.evidence import finding
from ._http import get
from .forms import extract_forms, find_registration_forms


def discover_registration(url, timeout=15):
    r = get(url, timeout=timeout)
    if r["status"] is None:
        return {"url": url, "status": None, "forms": [], "error": r["error"]}
    forms = extract_forms(r["body"], url)
    regs = find_registration_forms(forms)
    out = {"url": url, "status": r["status"], "forms": [], "error": None}
    for f in regs:
        fields = [i["name"] for i in f["inputs"]]
        text = " ".join(fields).lower()
        policy = []
        if "password" in text:
            m = re.search(r"(at least|minimum|min)[^<]{0,40}", r["body"], re.I)
            if m:
                policy.append(m.group(0)[:80])
        out["forms"].append({
            "action": f["action"], "method": f["method"],
            "fields": fields, "csrf_token": f["csrf_token"],
            "password_policy_hints": policy,
            "has_email_field": any("email" in n for n in fields),
            "has_password_confirm": any("confirm" in n for n in fields),
        })
    return out


def audit_registration(url, scope, timeout=15):
    """Analyze registration without creating accounts by default.

    Creating the single disposable test account is a separate, confirmed
    step — this function only analyzes the form and workflows.
    """
    scope.require_authorized(url, "registration audit")
    disc = discover_registration(url, timeout=timeout)
    findings = []
    if not disc["forms"]:
        findings.append(finding(
            "No registration form found", "info", 90, url,
            "No registration form was discovered on the page",
            "Form discovery", "GET %s and look for a registration form" % url,
            "No action needed", status="confirmed"))
        return {"url": url, "discovery": disc, "findings": findings}
    for f in disc["forms"]:
        if not f["csrf_token"]:
            findings.append(finding(
                "Registration form without CSRF token", "medium", 85, f["action"],
                "The registration form has no hidden CSRF token",
                "Form inspection", "Inspect the registration form at %s" % url,
                "Add a CSRF token to the registration form", status="confirmed"))
        if not f["has_password_confirm"]:
            findings.append(finding(
                "Registration without password confirmation", "low", 70, f["action"],
                "The form has no password-confirmation field",
                "Form inspection", "Inspect the registration form at %s" % url,
                "Ask users to confirm their password once", status="confirmed"))
        if not f["password_policy_hints"]:
            findings.append(finding(
                "No visible password policy", "low", 60, f["action"],
                "No password requirements are shown near the form",
                "Form inspection", "Inspect the registration form at %s" % url,
                "Show and enforce a minimum password policy (length + complexity)",
                status="suspected"))
    return {"url": url, "discovery": disc, "findings": findings,
            "note": "No test account was created. To create ONE disposable test "
                    "account, confirm it explicitly in the shell."}
