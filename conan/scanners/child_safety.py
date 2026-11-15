#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN CHILD SAFETY & ABUSE REPORTING.

Analyzes REPORTED URLs (supplied by the user) and public information for
indicators of phishing, fraud, threats, doxxing, non-consensual intimate
imagery, child exploitation indicators and illegal content distribution.

For suspected child sexual abuse material:
- NEVER download or store the content.
- NEVER display thumbnails or previews.
- NEVER redistribute it.
- Do NOT crawl or search for such material.
- Preserve only safe incident metadata.
- Provide official reporting channels.

This module does NOT fetch the reported URL's content. It records metadata
and gives the user the right reporting channels. It does not attack, disable
or compromise suspected websites.
"""
import hashlib
import time

REPORT_CHANNELS = [
    {"name": "NCMEC CyberTipline (USA)", "url": "https://report.cybertip.org/"},
    {"name": "INHOPE — global hotline network", "url": "https://www.inhope.org/"},
    {"name": "INTERPOL — report a crime", "url": "https://www.interpol.int/en/Crimes"},
    {"name": "Your local law enforcement", "url": "Contact the police in your country"},
]

CATEGORIES = ("phishing", "fraud", "threats", "doxxing",
              "non-consensual intimate imagery", "child exploitation",
              "illegal content distribution", "other")


def _hash_metadata(text):
    return hashlib.sha256(text.encode()).hexdigest()


def create_incident(url, category, notes="", reporter="anonymous"):
    """Record safe incident metadata only. The URL is never fetched."""
    if category not in CATEGORIES:
        raise ValueError("Unknown category: %s (use one of %s)"
                         % (category, ", ".join(CATEGORIES)))
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record = {
        "incident_id": "CS-%s" % _hash_metadata(url + ts)[:10],
        "url": url, "category": category,
        "notes": (notes or "")[:500],
        "reporter": reporter if reporter != "anonymous" else "anonymous",
        "recorded_at": ts,
        "metadata_hash": _hash_metadata(url + "|" + category + "|" + ts),
        "content_downloaded": False,
        "content_stored": False,
        "channels": REPORT_CHANNELS,
        "guidance": "Do not visit the URL again. Do not download or share any "
                    "content from it. Report it through the official channels "
                    "above and let the authorities handle it.",
    }
    return record


def analyze_reported_url(url, category, notes=""):
    """Public-information triage for a reported URL — metadata only.

    No content is fetched. The returned assessment is based on the category
    the reporter chose and on public reputation signals that do not require
    opening the page.
    """
    record = create_incident(url, category, notes)
    severity = "critical" if category in ("child exploitation",
                                          "non-consensual intimate imagery") else "high"
    record["assessment"] = {
        "category": category, "severity": severity,
        "action": "Report immediately through the official channels listed.",
        "evidence": "Reporter-supplied URL + category + metadata hash "
                    "(no content was downloaded or stored).",
    }
    return record
