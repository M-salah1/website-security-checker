#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN 2.0 engine tests — parallel modules, honest scoring, resume.

Covers the fixes for the aadl.dz failure (549s, 25/29 phases, 0%):
parallel path probing, IP-based port scanning, parallel domain
identity, the INCOMPLETE score, the 29/29 progress count, per-module
status, and resuming a partial scan.
"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.scanners import mega as mega_mod
from conan.scanners.domain_intelligence import investigate_domain
from conan.scanners.paths import discover_paths
from conan.scanners.ports import adaptive_probe, scan_ports


class Engine2Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)


class TestParallelPaths(Engine2Base):
    def test_discover_paths_parallel_on_lab(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            t0 = time.time()
            out = discover_paths(url, wordlist=["/", "/robots.txt",
                                                "/nope-xyz", "/admin"],
                                 timeout=5, max_paths=8)
            dt = time.time() - t0
        finally:
            safe_lab.stop_lab(server)
        self.assertEqual(len(out), 4)
        by_path = {e["path"]: e for e in out}
        self.assertEqual(by_path["/"]["category"], "PUBLIC")
        self.assertEqual(by_path["/nope-xyz"]["category"], "NOT FOUND")
        # Parallel: 4 requests must not take 4 x timeout.
        self.assertLess(dt, 20)


class TestPortsByIP(Engine2Base):
    def test_scan_ports_by_resolved_ip(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            port = int(url.rsplit(":", 1)[1].rstrip("/"))
            found = scan_ports("127.0.0.1", [port, port + 1],
                               ip="127.0.0.1")
        finally:
            safe_lab.stop_lab(server)
        self.assertEqual([f["port"] for f in found], [port])

    def test_adaptive_probe_by_ip(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            port = int(url.rsplit(":", 1)[1].rstrip("/"))
            out = adaptive_probe("127.0.0.1", url, common_ports=[port],
                                 ip="127.0.0.1")
        finally:
            safe_lab.stop_lab(server)
        self.assertEqual([f["port"] for f in out["open_ports"]], [port])
        self.assertEqual(out["method"], "Sunlight/Echo adaptive probe")


class TestInvestigateDomainParallel(Engine2Base):
    def test_local_target_returns_fast(self):
        t0 = time.time()
        out = investigate_domain("127.0.0.1", timeout=3)
        dt = time.time() - t0
        self.assertEqual(out["domain"], "127.0.0.1")
        self.assertLess(dt, 20)


class TestMegaEngine2(Engine2Base):
    def test_lab_scan_ticks_all_29_phases_and_reports_status(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        ticked = set()
        try:
            t0 = time.time()
            scan = mega_mod.mega_scan(url, scope=None, timeout=5,
                                      progress=ticked.add)
            dt = time.time() - t0
        finally:
            safe_lab.stop_lab(server)
        # Every DEEP_TESTS phase is ticked exactly once (distinct
        # counting): a complete run reads 29/29, never 25/29.
        self.assertEqual(set(mega_mod.DEEP_TESTS) - ticked, set())
        self.assertIn("module_status", scan)
        for name in ("core-audit", "domain-history", "learning", "ai-brain"):
            self.assertIn(name, scan["module_status"])
            self.assertIn(scan["module_status"][name]["status"],
                          ("completed", "timeout", "error", "not_tested"))
        self.assertIn("coverage", scan)
        self.assertGreaterEqual(scan["coverage"]["percent"], 0)
        self.assertLess(dt, 120)

    def test_slow_core_audit_is_incomplete_not_zero(self):
        """A core audit that never returns must not produce a 0% score."""
        def _slow(*args, **kwargs):
            time.sleep(10)
            return {"target": "http://127.0.0.1:9/", "score": 50,
                    "grade": "C", "confidence": 50, "findings": []}

        deadlines = {"core-audit": 2, "domain-history": 5,
                     "published-contacts": 5, "js-api-reverse": 5,
                     "real-ip": 5, "permissions": 5, "http-methods": 5,
                     "redirect-chain": 5}
        with mock.patch(
                "conan.scanners.mega.website_mod.investigate_website",
                side_effect=_slow):
            t0 = time.time()
            scan = mega_mod.mega_scan(
                "http://127.0.0.1:9/", scope=None, timeout=3,
                settings={"phase_deadlines": deadlines,
                          "scan_budget_s": 60})
            dt = time.time() - t0
        self.assertIsNone(scan["score"])
        self.assertEqual(scan["grade"], "INCOMPLETE")
        self.assertEqual(scan["module_status"]["core-audit"]["status"],
                         "timeout")
        self.assertIn("coverage", scan)
        self.assertLess(scan["coverage"]["percent"], 50)
        self.assertNotIn("None%", scan["ai_brain"]["verdict"])
        # Bounded: the whole scan finishes far below the old 549s.
        self.assertLess(dt, 60)

    def test_resume_reuses_completed_phases(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            first = mega_mod.mega_scan(url, scope=None, timeout=5)
            # Simulate an interrupted run: keep only two phases.
            mega_mod._save_partial(
                url, first, {"domain-history", "published-contacts"})
            second = mega_mod.mega_scan(url, scope=None, timeout=5)
        finally:
            safe_lab.stop_lab(server)
        self.assertIn("domain-history", second.get("resumed_from", []))
        self.assertIn("published-contacts", second.get("resumed_from", []))
        self.assertTrue(
            second["module_status"]["domain-history"].get("resumed"))
        # The resumed results survived the new core scan.
        self.assertEqual(second["history"], first["history"])

    def test_module_runs_saved_to_sqlite(self):
        from conan.laboratory import safe_lab
        from conan.storage import database as db_mod
        server, url = safe_lab.start_lab()
        try:
            scan = mega_mod.mega_scan(url, scope=None, timeout=5)
            db_path = os.path.join(self.tmp, "conan-scans.db")
            db_mod.init_db(db_path)
            scan_id = db_mod.save_scan(db_path, scan, base_dir=self.tmp)
        finally:
            safe_lab.stop_lab(server)
        import sqlite3
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                "SELECT module, status FROM module_runs"
                " WHERE scan_id = ?", (scan_id,)).fetchall()
        finally:
            conn.close()
        self.assertGreater(len(rows), 5)
        names = {r[0] for r in rows}
        self.assertIn("core-audit", names)
        self.assertIn("domain-history", names)


if __name__ == "__main__":
    unittest.main()
