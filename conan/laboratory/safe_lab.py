#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN SAFE LAB — a safe, local training environment.

A tiny website that is deliberately vulnerable BY DESIGN, served only on
127.0.0.1 (localhost, never on the network) so an ethical hacker can
practice the Conan scanners without touching any real site:

- /search?q=   reflects the query value (reflected-input demo)
- /profile?id= returns a SIMULATED database-error text when the id
  contains a quote (no real database exists anywhere in this lab)
- /login      a form with no CSRF token and no real authentication
              (POST is answered locally, nothing is stored or checked)
- /upload     a form that accepts any file type (inspection only)
- every page deliberately misses security headers and sets a cookie
  without Secure/HttpOnly, so the scanners have real findings to report.

Everything is labelled as a demo. The lab binds to 127.0.0.1 only, uses a
random free port, and is stopped by the caller. No credentials, no real
data, no network access.
"""
import html as html_mod
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB_COOKIE = "lab_session=demo; Path=/"

INDEX = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>CONAN SAFE LAB — training demo only</title></head><body>
<h1>🔍 CONAN SAFE LAB</h1>
<p><b>Training demo only — localhost, no real data, no real accounts.</b></p>
<ul>
<li><a href="/search?q=ConanMarker7x9">/search?q=…</a> — reflected input demo</li>
<li><a href="/profile?id=1">/profile?id=1</a> — simulated error demo (try id=1')</li>
<li><a href="/login">/login</a> — form without CSRF token (demo, no auth)</li>
<li><a href="/upload">/upload</a> — upload form, any type (inspection only)</li>
</ul></body></html>"""

SEARCH = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Lab search</title></head><body>
<h1>Lab search</h1><p>You searched for: %s</p>
<p><a href="/">back to lab index</a></p></body></html>"""

PROFILE_OK = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Lab profile</title></head><body>
<h1>Demo profile %s</h1><p>Name: Demo User (fictional)</p></body></html>"""

PROFILE_ERROR = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Lab profile</title></head><body>
<h1>Simulated error (lab demo text, no real database)</h1>
<p>Warning: mysql_fetch_array(): SQL syntax error near '' at line 1 — simulated lab message.</p>
</body></html>"""

LOGIN = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Lab login</title></head><body>
<h1>Demo login (no real authentication)</h1>
<form action="/login" method="POST">
<input type="text" name="username" placeholder="demo user">
<input type="password" name="password" placeholder="demo password">
<input type="submit" value="Login">
</form><p>No credentials are stored or checked.</p></body></html>"""

UPLOAD = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Lab upload</title></head><body>
<h1>Demo upload form (inspection only)</h1>
<form action="/upload" method="POST" enctype="multipart/form-data">
<input type="file" name="file"><input type="submit" value="Upload">
</form><p>Nothing is uploaded or stored.</p></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", LAB_COOKIE)
        # Deliberately no security headers — that is the lesson.
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/":
            self._send(INDEX)
        elif parsed.path == "/search":
            value = q.get("q", [""])[0]
            self._send(SEARCH % html_mod.escape(value))
        elif parsed.path == "/profile":
            pid = q.get("id", ["1"])[0]
            if "'" in pid or '"' in pid:
                self._send(PROFILE_ERROR)
            else:
                self._send(PROFILE_OK % html_mod.escape(pid))
        elif parsed.path == "/login":
            self._send(LOGIN)
        elif parsed.path == "/upload":
            self._send(UPLOAD)
        else:
            self._send("<h1>404 — lab demo</h1>", status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        # Demo only: never authenticate, never store anything.
        self._send("<h1>Demo login failed</h1>"
                   "<p>No credentials are stored or checked in the lab.</p>")


def start_lab(port=0):
    """Start the lab on 127.0.0.1 only. Returns (server, base_url)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


def stop_lab(server):
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass


def run_lab_training(base_url):
    """Run the real Conan scanners against the lab and explain each hit.

    Returns a dict with the findings and a training note per finding.
    Nothing here touches a real site — the target is always localhost.
    """
    from ..scanners import cookies as cookies_mod
    from ..scanners import forms as forms_mod
    from ..scanners import headers as headers_mod
    from ..scanners import vulnerabilities as vuln_mod
    from ..scanners._http import get as http_get

    search_url = base_url + "/search?q=ConanMarker7x9"
    profile_url = base_url + "/profile?id=1"
    findings = []
    findings += headers_mod.analyze_headers(base_url).get("findings", [])
    findings += cookies_mod.analyze_cookies(base_url).get("findings", [])
    forms = forms_mod.fetch_forms(base_url + "/login").get("forms", [])
    forms += forms_mod.fetch_forms(base_url + "/upload").get("forms", [])
    findings += vuln_mod.test_csrf(forms, base_url)
    findings += vuln_mod.test_file_upload(forms, base_url)
    findings += vuln_mod.test_xss(search_url)
    findings += vuln_mod.test_sqli(profile_url + "'")
    html = http_get(base_url)["body"]
    findings += vuln_mod.test_info_disclosure(base_url, html, {})
    notes = {
        "Reflected input point (possible XSS)":
            "Lesson: user input was reflected. Fix: encode output for its context + strict CSP.",
        "Suspected SQL injection":
            "Lesson: a quote changed the response. Fix: parameterized queries, never string-built SQL.",
        "State-changing form without CSRF token":
            "Lesson: the login form has no token. Fix: per-session CSRF token, validated server-side.",
        "File upload form found":
            "Lesson: the upload accepts any type. Fix: validate content server-side, store outside web root.",
    }
    for f in findings:
        f["training_note"] = notes.get(f["name"], f.get("remediation", ""))
    return {"lab_url": base_url, "findings": findings,
            "note": "Safe lab on localhost only. Every finding above is a "
                    "training demo — fix it in your own code the same way."}
