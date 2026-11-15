#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reputation intelligence — public signals only.

Combines the anti-phishing score, health classification and hosting flags
into one reputation summary. No paid feeds, no API keys. When a source is
unavailable the field is UNKNOWN, never invented.
"""
from ..scanners import health as health_mod
from ..scanners import phishing as phishing_mod


def reputation_report(url, official_domain=None, timeout=12):
    """Reputation summary from public, measurable signals."""
    phish = phishing_mod.analyze_phishing(url, official_domain=official_domain,
                                          timeout=timeout)
    health = health_mod.check_health(url, retries=0, timeout=timeout)
    signals = []
    if phish["risk_score"] >= 45:
        signals.append("elevated phishing risk (%d/100)" % phish["risk_score"])
    if health["classification"] != "ONLINE":
        signals.append("availability: %s" % health["classification"])
    verdict = "UNKNOWN"
    if phish["classification"] in ("CRITICAL", "HIGH"):
        verdict = "HIGH RISK"
    elif phish["classification"] == "MEDIUM":
        verdict = "SUSPICIOUS"
    elif phish["classification"] == "LOW" and health["classification"] == "ONLINE":
        verdict = "LEGITIMATE INDICATORS"
    return {"url": url, "verdict": verdict,
            "phishing_risk": phish["risk_score"],
            "phishing_classification": phish["classification"],
            "availability": health["classification"],
            "signals": signals,
            "reasons": phish["reasons"],
            "note": "Public signals only. No single signal proves legitimacy or fraud."}
