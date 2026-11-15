#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Port scanning + Sunlight/Echo adaptive probe tests (localhost only)."""
import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core.animation import Investigation
from conan.scanners import ports as ports_mod


class _Site(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>Test Site</title></head><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestPorts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_address[1]
        cls.base = "http://127.0.0.1:%d/" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_scan_ports_finds_open_not_closed(self):
        found = ports_mod.scan_ports("127.0.0.1", [self.port, 1])
        ports = [f["port"] for f in found]
        self.assertIn(self.port, ports)
        self.assertNotIn(1, ports)

    def test_scan_ports_progress_counts_each_port(self):
        seen = []
        ports_mod.scan_ports("127.0.0.1", [self.port, 1, 2],
                             progress=lambda: seen.append(1))
        self.assertEqual(len(seen), 3)

    def test_banner_grab(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            conn.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
            conn.close()
            listener.close()

        threading.Thread(target=serve, daemon=True).start()
        found = ports_mod.scan_ports("127.0.0.1", [port])
        self.assertEqual(len(found), 1)
        self.assertIn("SSH-2.0", found[0]["banner"])

    def test_probe_entry_points_serves_site(self):
        entries = ports_mod.probe_entry_points(
            "127.0.0.1", [{"port": self.port, "service": "HTTP"}],
            self.base)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "200")
        self.assertTrue(entries[0]["serves_site"])

    def test_adaptive_probe_phases(self):
        out = ports_mod.adaptive_probe(
            "127.0.0.1", self.base, common_ports=[self.port, 1])
        self.assertEqual(out["method"], "Sunlight/Echo adaptive probe")
        self.assertIn(self.port, [p["port"] for p in out["open_ports"]])
        self.assertIn(self.port, out["doors_serving_site"])
        # Phase 2: the echo adapts — related ports of the open one.
        self.assertGreaterEqual(out["phase2_related"], 0)

    def test_investigation_percent(self):
        inv = Investigation(enabled=False, total=10, quiet=True)
        self.assertEqual(inv.percent(), 0)
        inv.phase("a")
        inv.phase("b")
        inv.phase("c")
        self.assertEqual(inv.percent(), 30)
        # Phases are counted by distinct name: repeating the same
        # phase does not inflate the percentage.
        for _ in range(20):
            inv.phase("c")
        self.assertEqual(inv.percent(), 30)
        for name in ("d", "e", "f", "g", "h", "i", "j"):
            inv.phase(name)
        self.assertEqual(inv.percent(), 99)


if __name__ == "__main__":
    unittest.main()
