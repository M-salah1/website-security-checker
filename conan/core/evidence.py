#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence model — every finding must carry evidence and confidence.

status:
  confirmed    — the test positively observed the issue
  suspected    — an indicator was seen, needs manual verification
  unverifiable — the environment could not verify this check (not counted)

confidence: 0..100, how sure the detector is about this finding.
"""
import datetime


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def finding(name, severity, confidence, url, evidence, method,
            reproduction, remediation, status="suspected"):
    """Build one finding dict. `evidence` must never contain secret values."""
    if severity not in ("critical", "high", "medium", "low", "info"):
        raise ValueError("bad severity: %r" % severity)
    if status not in ("confirmed", "suspected", "unverifiable"):
        raise ValueError("bad status: %r" % status)
    return {
        "name": name,
        "severity": severity,
        "confidence": int(max(0, min(100, confidence))),
        "status": status,
        "url": url,
        "evidence": evidence,
        "method": method,
        "reproduction": reproduction,
        "remediation": remediation,
        "timestamp": utc_now(),
    }


def severity_rank(severity):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)


def sort_findings(findings):
    return sorted(findings, key=lambda f: (severity_rank(f["severity"]), -f["confidence"]))


def count_by_severity(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
