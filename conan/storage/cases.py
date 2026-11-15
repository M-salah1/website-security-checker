#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Investigation cases — unique case IDs, SHA-256 evidence hashes, export.

Every investigation gets a case identifier like CN-20261115-0001.
The case record stores: target, date/time, selected modules, scope
authorization, findings, evidence references, SHA-256 hash of the evidence,
confidence, remediation, scan duration. Reports (JSON/HTML) are exported
with the case ID; secrets are redacted before storage.
"""
import hashlib
import json
import os
import time

CASES_FILE = "conan-cases.json"


def new_case_id(existing):
    today = time.strftime("%Y%m%d", time.gmtime())
    n = 1
    while True:
        cid = "CN-%s-%04d" % (today, n)
        if cid not in existing:
            return cid
        n += 1


def evidence_hash(data):
    blob = json.dumps(data, ensure_ascii=False, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


class CaseStore:
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.getcwd()
        self.path = os.path.join(self.base_dir, CASES_FILE)
        self.cases = {}
        self.load()

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.cases = data
        except Exception:
            self.cases = {}

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.cases, f, ensure_ascii=False, indent=2)

    def create(self, kind, target, modules, scope, scan):
        cid = new_case_id(set(self.cases))
        record = {
            "case_id": cid, "kind": kind, "target": target,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modules": modules, "scope": scope,
            "score": scan.get("score"), "grade": scan.get("grade"),
            "confidence": scan.get("confidence"),
            "duration_s": scan.get("duration_s"),
            "findings_count": len(scan.get("findings", [])),
            "evidence_hash": evidence_hash(scan.get("findings", [])),
            "scan": scan,
        }
        self.cases[cid] = record
        self.save()
        return record

    def get(self, case_id):
        return self.cases.get(case_id)

    def list(self, limit=20):
        items = sorted(self.cases.values(), key=lambda c: c.get("created_at", ""),
                       reverse=True)
        return items[:limit]

    def export_json(self, case_id, path):
        rec = self.get(case_id)
        if not rec:
            return None
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        return path

    def export_evidence(self, case_id, directory):
        """Export JSON + HTML + hash file for a case."""
        from ..reporting.html_report import build_html_report
        rec = self.get(case_id)
        if not rec:
            return None
        os.makedirs(directory, exist_ok=True)
        base = os.path.join(directory, case_id)
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        with open(base + ".html", "w", encoding="utf-8") as f:
            f.write(build_html_report(rec["scan"]))
        with open(base + ".sha256", "w", encoding="utf-8") as f:
            f.write("%s  %s.json\n" % (rec["evidence_hash"], case_id))
        return [base + ".json", base + ".html", base + ".sha256"]
