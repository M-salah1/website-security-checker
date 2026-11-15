#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSON reporting — the full technical report (secrets already redacted)."""
import json


def build_json_report(scan):
    """Assemble the 16-section report dict from a scan result."""
    audit = scan.get("audit") or {}
    findings = scan.get("findings") or []
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    suspected = [f for f in findings if f.get("status") == "suspected"]
    return {
        "tool": "CONAN FRAMEWORK v3.0 — ADVANCED WEBSITE SECURITY DETECTIVE",
        "developer": "Hafed Mehdi Salah Eddine — Algeria 🇩🇿",
        "github": "M-salah1",
        "target": scan.get("target"),
        "scan_timestamp": scan.get("started_at"),
        "finished_at": scan.get("finished_at"),
        "duration_s": scan.get("duration_s"),
        "scope": scan.get("scope"),
        "dns": scan.get("dns"),
        "tls": scan.get("tls"),
        "headers": scan.get("headers"),
        "cookies": scan.get("cookies"),
        "discovery": scan.get("discovery"),
        "forms": scan.get("forms"),
        "api": scan.get("api"),
        "auth_audit": scan.get("auth_audit"),
        "registration_audit": scan.get("registration_audit"),
        "vulnerabilities": findings,
        "phishing": scan.get("phishing"),
        "health": scan.get("health"),
        "score": scan.get("score"),
        "grade": scan.get("grade"),
        "confidence": scan.get("confidence"),
        "checks_count": scan.get("checks_count"),
        "confirmed_findings": len(confirmed),
        "suspected_findings": len(suspected),
        "severity_distribution": scan.get("severity_distribution"),
        "audit_summary": {
            "score": audit.get("score"),
            "grade": audit.get("grade"),
            "counts": audit.get("counts"),
            "top_fixes": audit.get("top_fixes"),
        },
        "recommendations": scan.get("recommendations") or [],
        "note": "Passive + authorized-active audit only. No secrets are stored "
                "in this report: passwords and session values are always masked.",
    }


def save_json_report(scan, path):
    report = build_json_report(scan)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return report
