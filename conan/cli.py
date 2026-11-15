#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interactive shell for CONAN FRAMEWORK v5.8.

Commands: help, about, version, clear, exit, scan, discover, paths, headers,
tls, cookies, forms, api, phishing, health, xss, sqli, csrf, auth-test,
registration-test, session-test, report, report html, report json, history,
settings, language, scope, status.

Active tests (xss, sqli, auth-test, registration-test) require an authorized
scope — see `scope add`. Passwords and session values are never displayed.
"""
import argparse
import json
import os
import sys
import time

try:
    import readline
except Exception:
    readline = None

from . import __version__
from .core import engine
from .core.animation import Investigation, play_intro
from .core.configuration import load_settings, save_settings
from .core.i18n import ar_display, set_reverse_arabic
from .core.evidence import count_by_severity, sort_findings
from .core.scope import ScopeManager, ScopeError
from .core import terminal
from .reporting.html_report import save_html_report
from .reporting.json_report import build_json_report, save_json_report
from .scanners import api as api_mod
from .scanners import authentication as auth_mod
from .scanners import cookies as cookies_mod
from .scanners import discovery as disc_mod
from .scanners import dns as dns_mod
from .scanners import forms as forms_mod
from .scanners import headers as headers_mod
from .scanners import health as health_mod
from .scanners import phishing as phishing_mod
from .scanners import registration as reg_mod
from .scanners import sessions as sessions_mod
from .scanners import tls as tls_mod
from .scanners import vulnerabilities as vuln_mod
from .scanners._http import get as http_get
from .storage import database as db_mod
from .storage.history import compare_stored

COMMANDS = ["help", "about", "version", "clear", "exit", "quit", "scan",
            "discover", "paths", "headers", "tls", "dns", "cookies", "forms", "api",
            "phishing", "health", "xss", "sqli", "csrf", "auth-test",
            "registration-test", "session-test", "report", "history",
            "settings", "language", "scope", "status"]

SHELL_STR = {
    "welcome": {
        "en": "Type 'help' to see commands. Use only on your own sites or with written authorization.",
        "fr": "Tapez 'help' pour voir les commandes. Utilisez uniquement sur vos propres sites ou avec une autorisation écrite.",
        "ar": "اكتب 'help' لعرض الأوامر. استعمل فقط على مواقعك أو بإذن كتابي.",
    },
    "no_target": {
        "en": "No target set. Usage: scan <url>  or  <command> <url>",
        "fr": "Aucune cible. Usage : scan <url>  ou  <commande> <url>",
        "ar": "لا يوجد هدف. الاستعمال: scan <url>  أو  <أمر> <url>",
    },
    "not_authorized": {
        "en": "Not authorized. Run: scope add <url> owned",
        "fr": "Non autorisé. Exécutez : scope add <url> owned",
        "ar": "غير مصرّح. نفّذ: scope add <url> owned",
    },
    "interrupted": {
        "en": "Interrupted.",
        "fr": "Interrompu.",
        "ar": "تمت المقاطعة.",
    },
}

SEV_AR_TO_EN = {"عالي": "high", "متوسط": "medium", "منخفض": "low"}

# Engine findings carry Arabic titles; map them to the English titles used by
# the new scanners so the same issue is not reported twice.
TITLE_AR_TO_EN = {
    "غياب HSTS": "Missing HSTS",
    "غياب Content-Security-Policy": "Missing Content-Security-Policy",
    "خطر Clickjacking": "Missing X-Frame-Options",
    "غياب nosniff": "Missing X-Content-Type-Options nosniff",
    "غياب Referrer-Policy": "Missing Referrer-Policy",
    "غياب Permissions-Policy": "Missing Permissions-Policy",
    "غياب Cross-Origin-Opener-Policy": "Missing Cross-Origin-Opener-Policy",
    "غياب Cross-Origin-Embedder-Policy": "Missing Cross-Origin-Embedder-Policy",
    "لا يوجد security.txt": "Missing security.txt",
    "كوكيز آمنة": "Insecure cookies",
    "تعذر التحقق من شهادة TLS": "TLS certificate could not be verified",
    "شهادة TLS على وشك الانتهاء": "TLS certificate expiring soon",
    "ملف حساس مكشوف علناً": "Sensitive file exposed publicly",
}


def _dedupe_findings(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f["severity"], f["name"], f["url"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _lang():
    return engine.LANG if hasattr(engine, "LANG") else "ar"


def _tr(key):
    text = SHELL_STR.get(key, {}).get(_lang(), SHELL_STR[key]["en"])
    return ar_display(text, _lang())


def _engine_findings(audit, target):
    out = []
    for v in audit.get("vulnerabilities", []):
        out.append({
            "name": TITLE_AR_TO_EN.get(v["title"], v["title"]),
            "severity": SEV_AR_TO_EN.get(v["severity"], "low"),
            "confidence": 90, "status": "confirmed", "url": target,
            "evidence": v["detail"], "method": "Conan engine audit",
            "reproduction": "Run: scan %s" % target,
            "remediation": v["fix"],
            "timestamp": audit.get("checked_at_utc", ""),
            "fixes": v.get("fixes") or {},
        })
    return out


def _recommendations(findings, audit):
    recs = list(audit.get("top_fixes") or [])
    for f in findings:
        if f["severity"] in ("critical", "high") and f["remediation"] not in recs:
            recs.append(f["remediation"])
    return recs[:8]


class Shell:
    def __init__(self, no_animation=False, lang=None):
        self.settings = load_settings()
        set_reverse_arabic(self.settings.get("reverse_arabic", True))
        if lang:
            self.settings["language"] = lang
        engine.set_lang(self.settings.get("language", "ar"))
        self.scope = ScopeManager()
        self.scope.rate_limit = float(self.settings.get("rate_limit", 0.5))
        self.scope.max_depth = int(self.settings.get("max_depth", 2))
        self.scope.max_pages = int(self.settings.get("max_pages", 50))
        self.scope.max_duration = int(self.settings.get("max_duration", 300))
        self.no_animation = no_animation
        self.db_path = self.settings.get("db_path", "conan-scans.db")
        try:
            db_mod.init_db(self.db_path)
        except Exception:
            pass
        self.last_scan = None
        self.last_target = None
        self._setup_readline()

    # -- shell plumbing ---------------------------------------------------
    def _setup_readline(self):
        if readline is None:
            return
        try:
            readline.set_history_length(200)
            histfile = os.path.join(os.getcwd(), ".conan-shell-history")
            try:
                readline.read_history_file(histfile)
            except Exception:
                pass
            self._histfile = histfile
        except Exception:
            self._histfile = None

        def completer(text, state):
            opts = [c for c in COMMANDS if c.startswith(text)]
            if state < len(opts):
                return opts[state]
            return None

        try:
            readline.set_completer(completer)
            readline.parse_and_bind("tab: complete")
        except Exception:
            pass

    def _save_history(self):
        if readline is not None and getattr(self, "_histfile", None):
            try:
                readline.write_history_file(self._histfile)
            except Exception:
                pass

    def _anim(self, total, quiet=False):
        enabled = self.settings.get("animation", True) and not self.no_animation
        return Investigation(enabled=enabled, total=total, quiet=quiet)

    def _need_url(self, arg):
        url = (arg or "").strip() or self.last_target
        if not url:
            print(_tr("no_target"))
            return None
        return engine.normalize_url(url)

    # -- the full scan pipeline -------------------------------------------
    def run_scan(self, url, quiet=False):
        url = engine.normalize_url(url)
        self.last_target = url
        t0 = time.time()
        inv = self._anim(total=11, quiet=quiet)
        scan = {"tool": "CONAN FRAMEWORK v5.8", "target": url,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "language": _lang(), "findings": []}
        inv.start()
        try:
            inv.log("[+] Initializing Conan engine...")
            inv.phase("Health check")
            try:
                health = health_mod.check_health(url, retries=1)
                scan["health"] = health
                inv.log("[+] Availability: %s (HTTP %s)" % (health["classification"], health["status"]))
            except Exception as exc:
                scan["health"] = {"classification": "UNKNOWN", "error": str(exc)}

            inv.phase("DNS resolution")
            try:
                dns = dns_mod.analyze_dns(engine.normalize_url(url).split("/")[2])
                scan["dns"] = dns
                inv.log("[+] DNS resolved: %s" % ", ".join(dns["ips"][:2]))
            except Exception as exc:
                scan["dns"] = {"error": str(exc)}

            inv.phase("TLS handshake")
            try:
                host = engine.normalize_url(url).split("/")[2]
                scan["tls"] = tls_mod.analyze_tls(host)
            except Exception as exc:
                scan["tls"] = {"error": str(exc)}

            inv.phase("Core security audit")
            try:
                audit = engine.run_check(url)
                scan["audit"] = audit
                scan["score"] = audit["score"]
                scan["grade"] = audit["grade"]
                scan["confidence"] = audit.get("confidence", 100)
                scan["findings"] += _engine_findings(audit, url)
                inv.log("[+] Core audit: score %d%% (%s)" % (audit["score"], audit["grade"]))
            except Exception as exc:
                scan["audit"] = {"error": str(exc)}
                scan["score"], scan["grade"], scan["confidence"] = 0, "F", 0

            inv.phase("Discovery crawl")
            try:
                disc = disc_mod.crawl(url, max_depth=self.scope.max_depth,
                                      max_pages=self.scope.max_pages,
                                      delay=self.scope.rate_limit)
                scan["discovery"] = disc
                inv.log("[+] Discovered %d pages" % disc["pages_crawled"])
            except Exception as exc:
                scan["discovery"] = {"error": str(exc), "pages": []}

            inv.phase("Security headers")
            try:
                scan["headers"] = headers_mod.analyze_headers(url)
                scan["findings"] += scan["headers"]["findings"]
            except Exception as exc:
                scan["headers"] = {"error": str(exc)}

            inv.phase("Cookies")
            try:
                scan["cookies"] = cookies_mod.analyze_cookies(url)
                scan["findings"] += scan["cookies"]["findings"]
            except Exception as exc:
                scan["cookies"] = {"error": str(exc)}

            inv.phase("Forms & API")
            try:
                forms = forms_mod.fetch_forms(url)
                scan["forms"] = forms.get("forms", [])
                scan["api"] = api_mod.discover_api(url, http_get(url)["body"])
            except Exception as exc:
                scan["forms"], scan["api"] = [], []
                scan["forms_error"] = str(exc)

            inv.phase("Phishing analysis")
            try:
                scan["phishing"] = phishing_mod.analyze_phishing(url)
            except Exception as exc:
                scan["phishing"] = {"error": str(exc)}

            inv.phase("Vulnerability tests (passive)")
            try:
                html = http_get(url)["body"]
                scan["findings"] += vuln_mod.run_vuln_tests(
                    url, html=html, headers={}, forms=scan.get("forms", []),
                    cookies=(scan.get("cookies") or {}).get("cookies", []))
            except Exception as exc:
                scan["vuln_error"] = str(exc)

            inv.phase("Finalizing report")
            scan["findings"] = sort_findings(_dedupe_findings(scan["findings"]))
            scan["severity_distribution"] = count_by_severity(scan["findings"])
            scan["checks_count"] = len((scan.get("audit") or {}).get("checks", [])) + 10
            scan["recommendations"] = _recommendations(scan["findings"], scan.get("audit") or {})
            scan["scope"] = {"kind": "authorized" if self.scope.is_authorized(url) else "passive",
                             "authorized": self.scope.is_authorized(url)}
            scan["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            scan["duration_s"] = round(time.time() - t0, 1)
            try:
                scan_id = db_mod.save_scan(self.db_path, scan)
                scan["scan_id"] = scan_id
                db_mod.save_availability(self.db_path, url, scan.get("health") or {},
                                         scan["finished_at"])
            except Exception:
                scan["scan_id"] = None
        finally:
            inv.done()
        self.last_scan = scan
        return scan

    def print_summary(self, scan):
        print(terminal.rule())
        print(terminal.orange("🔍 CONAN FRAMEWORK v5.8 — %s" % scan["target"]))
        print("Score: %s%%  Grade: %s  Confidence: %s%%  Duration: %s s" % (
            scan.get("score"), scan.get("grade"), scan.get("confidence"),
            scan.get("duration_s")))
        print("Health: %s  Phishing: %s (%s/100)" % (
            (scan.get("health") or {}).get("classification"),
            (scan.get("phishing") or {}).get("classification"),
            (scan.get("phishing") or {}).get("risk_score")))
        dist = scan.get("severity_distribution") or {}
        print("Findings: " + ", ".join("%s=%d" % (k, v) for k, v in dist.items() if v))
        for f in (scan.get("findings") or [])[:8]:
            print("  [%s/%s] %s" % (f["severity"].upper(), f["status"], f["name"]))
        if scan.get("scan_id"):
            print("Saved to history as scan #%s" % scan["scan_id"])
        print(terminal.rule())

    # -- individual commands ----------------------------------------------
    def cmd_help(self, arg):
        print(terminal.banner())
        print("""
  help                    Show this help
  about / version         About the tool / version
  clear                   Clear the screen
  exit / quit             Exit
  scan <url>              Full security scan (all modules)
  discover <url>          Crawl and map the website
  paths <url>             List discovered paths with status
  headers <url>           Analyze security headers
  tls <url>               TLS certificate + protocols
  cookies <url>           Inspect cookies (values masked)
  forms <url>             List HTML forms
  api <url>               Discover public API endpoints
  phishing <url> [official]  Phishing / authenticity analysis
  health <url>            Availability + timing
  xss <url>               Reflected-XSS indicator (authorized only)
  sqli <url>              SQLi indicator (authorized only)
  csrf <url>              CSRF token inspection (no submission)
  auth-test <url>         Authentication audit (authorized + confirmed)
  registration-test <url> Registration audit (authorized only)
  session-test <url>      Session cookie analysis
  report                  Show last scan summary
  report html             Save HTML report
  report json             Save JSON report
  history                 List saved scans
  history compare <a> <b> Compare two scans
  settings                Show settings
  settings <key> <value>  Change a setting
  language [en|fr|ar]     Interface language
  scope                   Show authorized targets
  scope add <url> <kind>  Authorize a target (owned/authorized/staging/local)
  status                  Current target, scope and settings
""")

    def cmd_scan(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        scan = self.run_scan(url)
        self.print_summary(scan)

    def cmd_discover(self, arg, paths_only=False):
        url = self._need_url(arg)
        if not url:
            return
        print("Crawling %s ..." % url)
        disc = disc_mod.crawl(url, max_depth=self.scope.max_depth,
                              max_pages=self.scope.max_pages,
                              delay=self.scope.rate_limit)
        for p in disc["pages"]:
            print("  [%s] %s  %s  %dms  (%s)" % (
                p["status"], p["classification"], p["url"],
                p["response_ms"], p["source"]))
        print("Pages: %d  Scripts: %d  API refs: %d" % (
            disc["pages_crawled"], len(disc["scripts"]), len(disc["api_refs"])))

    def cmd_headers(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        res = headers_mod.analyze_headers(url)
        if not res.get("verifiable"):
            print("Could not fetch the site: %s" % res.get("error"))
            return
        for c in res["checks"]:
            print(terminal.status_line(c["present"], "%s: %s" % (c["name"], c["value"] or "-")))
        for f in res["findings"]:
            print("  [%s] %s" % (f["severity"].upper(), f["name"]))

    def cmd_tls(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        host = url.split("/")[2]
        res = tls_mod.analyze_tls(host)
        if not res.get("ok"):
            print("TLS check failed here: %s" % (res.get("error") or ""))
            print("Unverifiable in this environment — not a verdict on the site.")
            return
        print("Issuer: %s" % res.get("issuer"))
        print("Version: %s  Cipher: %s" % (res.get("version"), res.get("cipher")))
        print("Days left: %s  Chain verified: %s" % (res.get("days_left"), res.get("chain_verified")))
        print("SANs: %s" % ", ".join(res.get("sans", [])[:5]))
        print("Protocols: %s" % ", ".join("%s=%s" % (k, v) for k, v in res.get("protocols", {}).items()))

    def cmd_dns(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        host = url.split("/")[2] if "://" in url else url
        res = dns_mod.analyze_dns(host)
        print("IPv4: %s" % ", ".join(res["ipv4"] or ["-"]))
        print("IPv6: %s" % ", ".join(res["ipv6"] or ["-"]))
        print("A: %s" % ", ".join(res["a"] or ["-"]))
        print("AAAA: %s" % ", ".join(res["aaaa"] or ["-"]))
        print("CNAME: %s" % ", ".join(res["cname"] or ["-"]))
        print("MX: %s" % ", ".join(res["mx"] or ["-"]))
        print("NS: %s" % ", ".join(res["ns"] or ["-"]))
        print("TXT: %s" % ", ".join(res["txt"] or ["-"]))
        print("DNSSEC: %s" % res["dnssec"].get("enabled"))
        print("Resolution: %d ms" % res["resolution_ms"])

    def cmd_cookies(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        res = cookies_mod.analyze_cookies(url)
        if not res["cookies"]:
            print("No cookies set by this site.")
        for c in res["cookies"]:
            print("  %s: value=•••••••• Secure=%s HttpOnly=%s SameSite=%s (%s)" % (
                c["name"], c["secure"], c["httponly"], c["samesite"] or "-", c["classification"]))
        for f in res["findings"]:
            print("  [%s] %s" % (f["severity"].upper(), f["name"]))

    def cmd_forms(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        res = forms_mod.fetch_forms(url)
        if not res["forms"]:
            print("No forms found on this page.")
        for f in res["forms"]:
            print("  %s [%s] kinds=%s csrf=%s inputs=%s" % (
                f["action"], f["method"], ",".join(f["kinds"]), f["csrf_token"],
                ",".join(i["name"] or i["type"] for i in f["inputs"])))

    def cmd_api(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        html = http_get(url)["body"]
        eps = api_mod.discover_api(url, html)
        for e in eps:
            print("  %s %s  [%s] %s  %s" % (e["method"], e["endpoint"], e["source"],
                                           e["status"], e["content_type"]))
        if not eps:
            print("No public API endpoints discovered.")

    def cmd_phishing(self, arg):
        parts = (arg or "").split()
        url = self._need_url(parts[0] if parts else "")
        if not url:
            return
        official = parts[1] if len(parts) > 1 else None
        res = phishing_mod.analyze_phishing(url, official_domain=official)
        print("Risk score: %d/100 — %s (confidence %d%%)" % (
            res["risk_score"], res["classification"], res["confidence"]))
        for r in res["reasons"]:
            print("  - %s" % r)

    def cmd_health(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        res = health_mod.check_health(url, retries=1)
        print("Status: %s  HTTP: %s  TCP: %sms  TTFB: %sms  Total: %sms" % (
            res["classification"], res["status"], res["tcp_ms"],
            res["ttfb_ms"], res["total_ms"]))
        try:
            db_mod.save_availability(self.db_path, url, res,
                                     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        except Exception:
            pass

    def _require_scope(self, url, what):
        try:
            self.scope.require_authorized(url, what)
            return True
        except ScopeError as exc:
            print(str(exc))
            print(_tr("not_authorized"))
            return False

    def cmd_xss(self, arg):
        url = self._need_url(arg)
        if not url or not self._require_scope(url, "XSS test"):
            return
        res = vuln_mod.test_xss(url)
        if not res:
            print("No reflected input points found (marker was not reflected).")
        for f in res:
            print("  [%s/%s] %s — %s" % (f["severity"].upper(), f["status"], f["name"], f["evidence"]))

    def cmd_sqli(self, arg):
        url = self._need_url(arg)
        if not url or not self._require_scope(url, "SQLi test"):
            return
        res = vuln_mod.test_sqli(url)
        if not res:
            print("No SQL error indicators found (non-destructive test).")
        for f in res:
            print("  [%s/%s] %s — %s" % (f["severity"].upper(), f["status"], f["name"], f["evidence"]))

    def cmd_csrf(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        forms = forms_mod.fetch_forms(url).get("forms", [])
        cookies = cookies_mod.analyze_cookies(url).get("cookies", [])
        res = vuln_mod.test_csrf(forms, url, cookies)
        if not res:
            print("No state-changing forms without CSRF tokens found.")
        for f in res:
            print("  [%s] %s — %s" % (f["severity"].upper(), f["name"], f["evidence"]))
        print("(Inspection only — no form was submitted.)")

    def cmd_auth_test(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        try:
            res = auth_mod.audit_auth(url, self.scope)
        except ScopeError as exc:
            print(str(exc))
            return
        if res.get("cancelled"):
            print("Cancelled.")
            return
        for f in res["findings"]:
            print("  [%s/%s] %s — %s" % (f["severity"].upper(), f["status"], f["name"], f["evidence"]))
        print("Login HTTP status: %s  Session rotated: %s" % (
            res.get("login_status"), res.get("session_rotated")))

    def cmd_registration_test(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        try:
            res = reg_mod.audit_registration(url, self.scope)
        except ScopeError as exc:
            print(str(exc))
            return
        for f in res["findings"]:
            print("  [%s/%s] %s — %s" % (f["severity"].upper(), f["status"], f["name"], f["evidence"]))
        print(res.get("note", ""))

    def cmd_session_test(self, arg):
        url = self._need_url(arg)
        if not url:
            return
        r1 = http_get(url)
        r2 = http_get(url)
        from .scanners.sessions import rotation_check
        c1 = engine.parse_cookies(r1["headers"])
        c2 = engine.parse_cookies(r2["headers"])
        rot = rotation_check(_raw_cookies(r1["headers"]), _raw_cookies(r2["headers"]))
        if not c1:
            print("No session cookies observed on this site.")
        print("Session cookies: %s" % ", ".join(c["name"] for c in c1))
        print("Rotation between two requests: %s (%s)" % (rot.get("rotated"), rot.get("note")))
        for c in c1:
            print("  %s: value=•••••••• Secure=%s HttpOnly=%s SameSite=%s" % (
                c["name"], c["secure"], c["httponly"], c["samesite"] or "-"))

    def cmd_report(self, arg):
        if not self.last_scan:
            print("No scan yet. Run: scan <url>")
            return
        fmt = (arg or "").strip().lower()
        if fmt == "html":
            save_html_report(self.last_scan, "conan-report.html")
            print("Saved: conan-report.html")
        elif fmt == "json":
            save_json_report(self.last_scan, "conan-report.json")
            print("Saved: conan-report.json")
        else:
            self.print_summary(self.last_scan)

    def cmd_history(self, arg):
        parts = (arg or "").split()
        if len(parts) >= 3 and parts[0] == "compare":
            try:
                comp = compare_stored(self.db_path, int(parts[1]), int(parts[2]))
            except Exception as exc:
                print("Compare failed: %s" % exc)
                return
            if comp is None:
                print("One of the scans was not found.")
                return
            print("Score: %s -> %s (delta %+d)" % (comp["score_before"], comp["score_after"], comp["score_delta"]))
            print("New findings: %s" % comp["new_findings"])
            print("Fixed findings: %s" % comp["fixed_findings"])
            print("Header changes: %s" % comp["header_changes"])
            return
        for row in db_mod.list_scans(self.db_path):
            print("  #%s | %s | %s | %s%% %s | %s" % (
                row["id"], row["started_at"], row["target"], row["score"],
                row["grade"], row["health"]))

    def cmd_settings(self, arg):
        parts = (arg or "").split()
        if len(parts) >= 2:
            key, value = parts[0], parts[1]
            if key in self.settings:
                old = self.settings[key]
                if isinstance(old, bool):
                    value = value.lower() in ("1", "true", "yes", "on")
                elif isinstance(old, int):
                    value = int(value)
                elif isinstance(old, float):
                    value = float(value)
                self.settings[key] = value
                save_settings(self.settings)
                print("Setting %s = %s" % (key, value))
            else:
                print("Unknown setting: %s" % key)
            return
        for k, v in self.settings.items():
            print("  %s = %s" % (k, v))

    def cmd_language(self, arg):
        code = (arg or "").strip().lower()
        if code in ("en", "fr", "ar"):
            self.settings["language"] = code
            save_settings(self.settings)
            engine.set_lang(code)
            print("Language: %s" % code)
        else:
            print("Current language: %s (en/fr/ar)" % _lang())

    def cmd_scope(self, arg):
        parts = (arg or "").split()
        if len(parts) >= 2 and parts[0] == "add":
            url = parts[1]
            kind = parts[2] if len(parts) > 2 else "owned"
            try:
                entry = self.scope.authorize(engine.normalize_url(url), kind)
                print("Authorized: %s (%s)" % (entry["host"], entry["kind"]))
            except ScopeError as exc:
                print(str(exc))
            return
        if not self.scope.targets:
            print("No authorized targets yet. Localhost is always in scope.")
        for t in self.scope.targets:
            print("  %s (%s)" % (t["host"], t["kind"]))
        print("Rate limit: %ss  Max depth: %s  Max pages: %s  Max duration: %ss" % (
            self.scope.rate_limit, self.scope.max_depth, self.scope.max_pages,
            self.scope.max_duration))

    def cmd_status(self, arg):
        print("Target: %s" % (self.last_target or "-"))
        print("Language: %s  Animation: %s" % (_lang(), self.settings.get("animation")))
        print("Scope targets: %d" % len(self.scope.targets))
        print("Scans in history: %d" % len(db_mod.list_scans(self.db_path, limit=1000)))
        print("Last scan: %s" % (self.last_scan["target"] if self.last_scan else "-"))

    # -- main loop ----------------------------------------------------------
    def run(self):
        play_intro(enabled=self.settings.get("animation", True)
                   and not self.no_animation)
        print(terminal.banner())
        print(_tr("welcome"))
        while True:
            try:
                line = input(terminal.orange("conan") + " > ")
            except KeyboardInterrupt:
                print("\n" + _tr("interrupted"))
                continue
            except EOFError:
                print()
                break
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""
            try:
                if cmd in ("exit", "quit"):
                    break
                elif cmd == "help":
                    self.cmd_help(arg)
                elif cmd in ("about", "version"):
                    print(terminal.banner())
                    print("CONAN FRAMEWORK v%s — ULTIMATE CYBER INVESTIGATION SYSTEM" % __version__)
                    print("Developer: Hafed Mehdi Salah Eddine — Algeria 🇩🇿 — GitHub: M-salah1 — © 2026")
                elif cmd == "clear":
                    os.system("cls" if os.name == "nt" else "clear")
                elif cmd == "scan":
                    self.cmd_scan(arg)
                elif cmd == "discover":
                    self.cmd_discover(arg)
                elif cmd == "paths":
                    self.cmd_discover(arg, paths_only=True)
                elif cmd == "headers":
                    self.cmd_headers(arg)
                elif cmd == "tls":
                    self.cmd_tls(arg)
                elif cmd == "dns":
                    self.cmd_dns(arg)
                elif cmd == "cookies":
                    self.cmd_cookies(arg)
                elif cmd == "forms":
                    self.cmd_forms(arg)
                elif cmd == "api":
                    self.cmd_api(arg)
                elif cmd == "phishing":
                    self.cmd_phishing(arg)
                elif cmd == "health":
                    self.cmd_health(arg)
                elif cmd == "xss":
                    self.cmd_xss(arg)
                elif cmd == "sqli":
                    self.cmd_sqli(arg)
                elif cmd == "csrf":
                    self.cmd_csrf(arg)
                elif cmd == "auth-test":
                    self.cmd_auth_test(arg)
                elif cmd == "registration-test":
                    self.cmd_registration_test(arg)
                elif cmd == "session-test":
                    self.cmd_session_test(arg)
                elif cmd == "report":
                    self.cmd_report(arg)
                elif cmd == "history":
                    self.cmd_history(arg)
                elif cmd == "settings":
                    self.cmd_settings(arg)
                elif cmd == "language":
                    self.cmd_language(arg)
                elif cmd == "scope":
                    self.cmd_scope(arg)
                elif cmd == "status":
                    self.cmd_status(arg)
                else:
                    print("Unknown command: %s (type 'help')" % cmd)
            except KeyboardInterrupt:
                print("\n" + _tr("interrupted"))
            except ScopeError as exc:
                print(str(exc))
            except Exception as exc:
                print("Error: %s" % exc)
        self._save_history()
        print("Goodbye — المحقق كونان")
        return 0


def _raw_cookies(headers):
    try:
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            return "; ".join(get_all("Set-Cookie") or [])
        return headers.get("Set-Cookie", "") or ""
    except Exception:
        return ""


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="conan",
        description="CONAN FRAMEWORK v5.8 — Advanced Website Security Detective")
    ap.add_argument("url", nargs="?", help="Target URL to scan")
    ap.add_argument("--lang", choices=["en", "fr", "ar"], default=None)
    ap.add_argument("--json", action="store_true", help="Print the unified JSON report")
    ap.add_argument("--html", help="Save the HTML report to a file")
    ap.add_argument("--pdf", help="Save the owner PDF report to a file")
    ap.add_argument("--owner-html", help="Save the owner HTML report to a file")
    ap.add_argument("--no-animation", action="store_true", help="Disable scan animations")
    ap.add_argument("--about", action="store_true")
    ap.add_argument("--developer", action="store_true")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args(argv)

    if args.version:
        print("CONAN FRAMEWORK v%s" % __version__)
        return 0
    if args.about or args.developer:
        print(terminal.banner())
        print("Developer: Hafed Mehdi Salah Eddine — Algeria 🇩🇿")
        print("GitHub: M-salah1 — Copyright © 2026")
        return 0

    shell = Shell(no_animation=args.no_animation, lang=args.lang)
    if not args.url:
        return shell.run()

    # Direct scan mode (keeps the old `python3 conan.py <url>` behaviour)
    scan = shell.run_scan(args.url, quiet=args.json)
    if args.json:
        print(json.dumps(build_json_report(scan), ensure_ascii=False, indent=2))
    else:
        try:
            engine.print_report(scan["audit"])
        except Exception:
            shell.print_summary(scan)
        shell.print_summary(scan)
    if args.html:
        save_html_report(scan, args.html)
        print("Saved HTML report:", args.html)
    if args.owner_html:
        with open(args.owner_html, "w", encoding="utf-8") as f:
            f.write(engine.generate_owner_html(scan["audit"]))
        print("Saved owner HTML report:", args.owner_html)
    if args.pdf:
        with open(args.pdf, "wb") as f:
            f.write(engine.generate_pdf_report(scan["audit"]))
        print("Saved PDF report:", args.pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
