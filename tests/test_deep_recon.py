#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep recon tests — JS/API reverse engineering, real IP, contacts."""
import contextlib
import io
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.intelligence.contacts import discover_contacts, extract_contacts
from conan.scanners import mega as mega_mod
from conan.scanners.js_api import analyze_js, extract_from_js
from conan.scanners.origin_ip import investigate_origin

JS_SAMPLE = """
const r = await fetch('/api/users?page=1');
const g = await fetch('/graphql', {method: 'POST'});
const s = new WebSocket('wss://example.com/live');
axios.get("/api/v1/orders");
const token = "sk-secret-should-never-appear";
"""

HTML_SAMPLE = """
<html><head><title>Example</title></head><body>
<a href="mailto:admin@example.com">Contact the admin</a>
<p>Our support team answers within 24h.</p>
<p>Admin panel is restricted.</p>
</body></html>
"""


class _Site(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/app.js":
            body = JS_SAMPLE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
        else:
            body = ('<html><head><script src="/app.js"></script></head>'
                    '<body>hi</body></html>').encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestDeepRecon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_extract_from_js(self):
        out = extract_from_js(JS_SAMPLE)
        self.assertIn("/api/users?page=1", out["endpoints"])
        self.assertIn("/api/v1/orders", out["endpoints"])
        self.assertTrue(out["graphql"])
        self.assertIn("wss://example.com/live", out["websockets"])
        # Secret values are never collected.
        blob = json.dumps(out)
        self.assertNotIn("sk-secret", blob)

    def test_analyze_js_fetches_public_scripts(self):
        html = '<html><head><script src="/app.js"></script></head></html>'
        out = analyze_js(self.base + "/", html)
        self.assertEqual(out["scripts_scanned"], 1)
        self.assertIn("/api/users?page=1", out["endpoints"])
        self.assertTrue(out["graphql"])

    def test_extract_contacts(self):
        out = extract_contacts(HTML_SAMPLE)
        self.assertIn("admin@example.com", out["emails"])
        self.assertTrue(any("admin" in line.lower() for line in out["contact_lines"]))

    def test_discover_contacts_local(self):
        out = discover_contacts(self.base + "/", HTML_SAMPLE, [], timeout=5)
        self.assertIn("admin@example.com", out["emails"])

    def test_investigate_origin_local(self):
        out = investigate_origin("127.0.0.1", "http://127.0.0.1:9/")
        self.assertIn("127.0.0.1", out["ips"])
        self.assertFalse(out["cdn_detected"])
        self.assertIn("Local", out.get("note", ""))

    def test_mega_scan_has_deep_recon_sections(self):
        from conan.laboratory import safe_lab
        server, url = safe_lab.start_lab()
        try:
            scan = mega_mod.mega_scan(url, scope=None, timeout=5)
        finally:
            safe_lab.stop_lab(server)
        for key in ("js_api", "origin", "contacts", "permissions"):
            self.assertIn(key, scan)
        self.assertIn("js-api-reverse", scan["deep_tests"])
        self.assertIn("real-ip", scan["deep_tests"])
        # Cookie values never leak into the scan data.
        blob = json.dumps(scan, default=str)
        self.assertNotIn("lab_session=demo", blob)
        self.assertNotIn("=demo", blob)


if __name__ == "__main__":
    unittest.main()
