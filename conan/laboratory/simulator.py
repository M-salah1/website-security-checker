#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Malware laboratory simulator — isolated, educational, harmless.

Runs ONLY in a local temp directory with harmless test samples:
- creates the EICAR test file and the obfuscated demo, scans them,
- simulates filesystem monitoring (writes are observed in the temp dir),
- simulates suspicious-process detection (lists the lab's own process only),
- generates an educational report.

Nothing here is real malware. No network access, no persistence, no
execution of the samples.
"""
import os
import tempfile
import time

from .static_analysis import analyze_text
from .test_samples import SAMPLES


def run_lab_simulation(log=print):
    """Run the full lab demo. Returns the educational report dict."""
    events = []

    def emit(msg):
        events.append(msg)
        if log:
            log(msg)

    tmp = tempfile.mkdtemp(prefix="conan-lab-")
    emit("[LAB] Isolated lab directory: %s" % tmp)
    emit("[LAB] No network access. No sample is executed.")
    results = []
    for sample in SAMPLES:
        path = os.path.join(tmp, sample["name"])
        with open(path, "w", encoding="utf-8") as f:
            f.write(sample["content"])
        emit("[LAB] File created (monitored): %s" % sample["name"])
        analysis = analyze_text(sample["name"], sample["content"])
        results.append({"sample": sample["name"], "kind": sample["kind"],
                        "verdict": analysis["verdict"],
                        "indicators": analysis["indicators"],
                        "sha256": analysis["sha256"]})
        for ind in analysis["indicators"]:
            emit("[DETECT] %s — %s (%s)" % (sample["name"], ind["pattern"], ind["severity"]))
        os.remove(path)
        emit("[LAB] File securely removed: %s" % sample["name"])
    # simulated process monitoring: only our own process
    emit("[LAB] Process monitor: watching lab process %d only (PID %d)" % (os.getpid(), os.getpid()))
    emit("[LAB] No suspicious child processes observed.")
    try:
        os.rmdir(tmp)
    except Exception:
        pass
    emit("[LAB] Lab directory cleaned up.")
    return {"lab_dir": tmp, "events": events, "results": results,
            "note": "Educational simulation with harmless test samples only."}


def run_malware_detection(url_html="", assets=None):
    """Static detection over fetched website assets (read-only)."""
    from .static_analysis import analyze_html
    out = []
    if url_html:
        out.append(analyze_html(url_html))
    for name, text in (assets or []):
        out.append(analyze_text(name, text))
    return out
