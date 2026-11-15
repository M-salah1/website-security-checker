#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan comparison — new findings, fixed findings, header changes."""
from .database import get_scan


def _finding_keys(scan):
    out = set()
    for f in (scan or {}).get("findings") or []:
        out.add((f.get("name", ""), f.get("url", "")))
    return out


def _header_state(scan):
    out = {}
    for c in ((scan.get("headers") or {}).get("checks") or []):
        out[c.get("name", "")] = bool(c.get("present"))
    return out


def compare_scans(scan_a, scan_b):
    """Compare two scan dicts (a = older, b = newer)."""
    ka, kb = _finding_keys(scan_a), _finding_keys(scan_b)
    ha, hb = _header_state(scan_a), _header_state(scan_b)
    header_changes = []
    for name in sorted(set(ha) | set(hb)):
        if ha.get(name) != hb.get(name):
            header_changes.append({"header": name,
                                   "before": ha.get(name), "after": hb.get(name)})
    return {
        "new_findings": sorted(kb - ka),
        "fixed_findings": sorted(ka - kb),
        "header_changes": header_changes,
        "score_before": (scan_a or {}).get("score"),
        "score_after": (scan_b or {}).get("score"),
        "score_delta": ((scan_b or {}).get("score") or 0) - ((scan_a or {}).get("score") or 0),
    }


def compare_stored(db_path, id_a, id_b, base_dir=None):
    a = get_scan(db_path, id_a, base_dir)
    b = get_scan(db_path, id_b, base_dir)
    if a is None or b is None:
        return None
    return compare_scans(a, b)
