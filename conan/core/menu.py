#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main menu + smart investigation wizard for CONAN FRAMEWORK v4.0.

Welcome screen -> language selection (remembered) -> 17-option menu.
The wizard asks for URL/IP, validates it, checks scope/authorization, asks
only essential extra questions, runs the modules and shows organized
results. Navigation commands BACK / HOME / MENU / CANCEL / EXIT work at
every prompt; BACK preserves completed results (they live in the case
store and the session store, not on the screen).
"""
import ipaddress
import os
import sys
import time
import urllib.parse

from . import terminal
from .animation import Investigation
from .authorization import AuthorizationManager, ScopeError
from .configuration import load_settings, save_settings
from .i18n import I18n
from .navigation import NavCommand, NavigationStack, SessionStore, is_nav_command
from .. import __version__
from ..scanners import api as api_mod
from ..scanners import authentication as auth_mod
from ..scanners import child_safety as child_mod
from ..scanners import cookies as cookies_mod
from ..scanners import domain_intelligence as domain_mod
from ..scanners import exposure as exposure_mod
from ..scanners import forms as forms_mod
from ..scanners import headers as headers_mod
from ..scanners import health as health_mod
from ..scanners import ip_intelligence as ip_mod
from ..scanners import malware as malware_mod
from ..scanners import paths as paths_mod
from ..scanners import phishing as phishing_mod
from ..scanners import registration as reg_mod
from ..scanners import vulnerabilities as vuln_mod
from ..scanners import website as website_mod
from ..scanners._http import get as http_get
from ..intelligence import organization as org_mod
from ..intelligence import osint as osint_mod
from ..intelligence import relationships as rel_mod
from ..intelligence import reputation as rep_mod
from ..laboratory import simulator as lab_mod
from ..reporting.html_report import save_html_report
from ..reporting.json_report import save_json_report
from ..storage import database as db_mod
from ..storage.cases import CaseStore
from ..storage.history import compare_stored


def _valid_url(text):
    text = (text or "").strip()
    try:
        p = urllib.parse.urlparse(text)
        return p.scheme in ("http", "https") and bool(p.hostname)
    except Exception:
        return False


def _valid_ip(text):
    try:
        ipaddress.ip_address((text or "").strip())
        return True
    except Exception:
        return False


class MenuApp:
    def __init__(self, no_animation=False):
        self.settings = load_settings()
        self.i18n = I18n(self.settings.get("language", "ar"))
        self.no_animation = no_animation
        self.scope = AuthorizationManager()
        self.nav = NavigationStack()
        self.sessions = SessionStore()
        self.cases = CaseStore()
        self.db_path = self.settings.get("db_path", "conan-scans.db")
        try:
            db_mod.init_db(self.db_path)
        except Exception:
            pass
        self.last_result = None
        self.last_case = None

    # -- i/o helpers -------------------------------------------------------
    def t(self, key):
        return self.i18n.t(key)

    def out(self, text=""):
        self.i18n.out(text)

    def ask(self, prompt):
        """Read one line; navigation words raise NavCommand."""
        try:
            line = input(self.i18n.rtl(prompt + " ")).strip()
        except KeyboardInterrupt:
            raise NavCommand("CANCEL")
        except EOFError:
            raise NavCommand("EXIT")
        if is_nav_command(line):
            raise NavCommand(line.upper())
        return line

    def ask_url(self):
        while True:
            url = self.ask(self.t("enter_url"))
            if _valid_url(url):
                return url.rstrip("/")
            self.out(self.t("invalid_url"))

    def ask_ip(self):
        while True:
            ip = self.ask(self.t("enter_ip"))
            if _valid_ip(ip):
                return ip.strip()
            self.out(self.t("invalid_ip"))

    def ask_domain(self):
        while True:
            d = self.ask(self.t("enter_url"))
            d = d.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
            if d and "." in d:
                return d
            self.out(self.t("invalid_url"))

    def confirm(self, msg):
        try:
            ans = input(self.i18n.rtl(msg + " [y/N] ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes", "o", "oui", "نعم", "ن")

    def pause(self):
        try:
            input(self.i18n.rtl(self.t("press_enter")))
        except (EOFError, KeyboardInterrupt):
            pass

    # -- screens -----------------------------------------------------------
    def welcome(self):
        print(terminal.orange("   🔍  " + self.t("app_title")))
        print(terminal.orange("   " + self.t("app_subtitle")))
        print(terminal.grey("   ────────────────────────────────────────────────"))
        self.out("   %s: Hafed Mehdi Salah Eddine" % self.t("developer"))
        self.out("   %s: M-salah1" % self.t("github"))
        self.out("   %s: Algeria 🇩🇿" % self.t("country"))
        print(terminal.grey("   CONAN FRAMEWORK v%s  •  Copyright © 2026" % __version__))
        print()

    def language_screen(self):
        self.out(self.t("choose_language") + ":")
        print("   1. العربية")
        print("   2. Français")
        print("   3. English")
        current = {"ar": "1", "fr": "2", "en": "3"}.get(self.i18n.lang, "1")
        try:
            choice = input(self.i18n.rtl(self.t("enter_choice") + " [%s] " % current)).strip()
        except (EOFError, KeyboardInterrupt):
            choice = ""
        choice = choice or current
        lang = {"1": "ar", "2": "fr", "3": "en"}.get(choice, self.i18n.lang)
        self.i18n.set(lang)
        self.settings["language"] = lang
        save_settings(self.settings)
        # sync the v3 engine language too
        try:
            from ..core import engine
            engine.set_lang(lang)
        except Exception:
            pass

    def main_menu(self):
        print(terminal.rule())
        print(terminal.orange("   " + self.t("main_menu")))
        for i in range(1, 18):
            print("   %2d. %s" % (i, self.t("menu_%d" % i)))
        print(terminal.rule())
        self.out(self.t("back_hint"))

    # -- case / results ----------------------------------------------------
    def _anim(self, total):
        enabled = self.settings.get("animation", True) and not self.no_animation
        return Investigation(enabled=enabled, total=total)

    def finish_case(self, kind, target, modules, scope_kind, scan):
        scan["language"] = self.i18n.lang
        rec = self.cases.create(kind, target, modules, scope_kind, scan)
        self.sessions.add(rec["case_id"], kind, target,
                          {"score": scan.get("score"), "grade": scan.get("grade"),
                           "findings": len(scan.get("findings", []))})
        self.last_case = rec
        self.last_result = scan
        return rec

    def show_dashboard(self, rec):
        scan = rec["scan"]
        print(terminal.rule())
        print(terminal.orange("🔍 %s — %s" % (rec["case_id"], scan.get("target"))))
        self.out("%s: %s%%   %s: %s   %s: %s%%   %s: %s s" % (
            self.t("score"), scan.get("score"), self.t("grade"), scan.get("grade"),
            self.t("confidence"), scan.get("confidence"), self.t("duration"),
            scan.get("duration_s")))
        dist = scan.get("severity_distribution") or {}
        self.out("%s: %s" % (self.t("findings"),
                             ", ".join("%s=%d" % (k, v) for k, v in dist.items() if v)))
        for f in (scan.get("findings") or [])[:8]:
            print("  [%s/%s] %s" % (f["severity"].upper(), f["status"], f["name"]))
        print(terminal.rule())
        self.out("1. %s   2. JSON   3. HTML   4. %s" % (
            self.t("findings"), self.t("main_menu")))
        try:
            choice = self.ask(self.t("enter_choice"))
        except NavCommand:
            return
        if choice == "1":
            for f in (scan.get("findings") or []):
                print("  [%s/%s] %s" % (f["severity"].upper(), f["status"], f["name"]))
                print("      %s" % f.get("evidence", "")[:180])
                print("      Fix: %s" % f.get("remediation", "")[:180])
            self.pause()
        elif choice == "2":
            save_json_report(scan, "conan-report.json")
            self.out(self.t("export_done") + ": conan-report.json")
        elif choice == "3":
            save_html_report(scan, "conan-report.html")
            self.out(self.t("export_done") + ": conan-report.html")

    # -- menu options ------------------------------------------------------
    def opt_website_investigation(self):
        self.nav.push("website")
        url = self.ask_url()
        # Passive modules run without authorization; only the active parts
        # (paths discovery, file inspection) need it — website.py handles
        # that by skipping them when unauthorized.
        pass
        inv = self._anim(total=12)
        inv.start()
        try:
            scan = website_mod.investigate_website(
                url, scope=self.scope,
                max_pages=int(self.settings.get("max_pages", 20)),
                progress=lambda name: inv.phase(name))
        finally:
            inv.done()
        rec = self.finish_case("website-investigation", url,
                               ["dns", "tls", "headers", "cookies", "health",
                                "discovery", "forms", "api", "exposure",
                                "phishing", "paths", "vulnerabilities"],
                               "authorized" if self.scope.is_authorized(url) else "passive",
                               scan)
        self.show_dashboard(rec)

    def opt_vuln_audit(self):
        self.nav.push("vuln-audit")
        url = self.ask_url()
        self.scope.check_or_ask(url, "vulnerability audit")
        inv = self._anim(total=5)
        inv.start()
        try:
            inv.phase("headers")
            headers = headers_mod.analyze_headers(url)
            inv.phase("cookies")
            cookies = cookies_mod.analyze_cookies(url)
            inv.phase("forms")
            forms = forms_mod.fetch_forms(url)
            inv.phase("csrf")
            findings = list(headers.get("findings", [])) + list(cookies.get("findings", []))
            findings += vuln_mod.test_csrf(forms.get("forms", []), url,
                                           cookies.get("cookies", []))
            inv.phase("xss+sqli")
            findings += vuln_mod.test_sqli(url)
            findings += vuln_mod.test_xss(url)
            findings += vuln_mod.test_file_upload(forms.get("forms", []), url)
        finally:
            inv.done()
        scan = {"tool": "CONAN FRAMEWORK v4.0", "target": url,
                "kind": "vulnerability-audit",
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration_s": 0, "findings": findings,
                "score": None, "grade": None, "confidence": 90,
                "checks_count": 5, "severity_distribution": {},
                "recommendations": [], "scope": {"kind": "authorized"}}
        from ..core.evidence import count_by_severity, sort_findings
        scan["findings"] = sort_findings(findings)
        scan["severity_distribution"] = count_by_severity(findings)
        rec = self.finish_case("vulnerability-audit", url,
                               ["headers", "cookies", "forms", "csrf", "sqli",
                                "xss", "file-upload"], "authorized", scan)
        self.show_dashboard(rec)

    def opt_ip_intel(self):
        self.nav.push("ip-intel")
        ip = self.ask_ip()
        ports = (80, 443)
        res = ip_mod.investigate_ip(ip, ports=ports)
        print(terminal.rule())
        print("IP: %s (IPv%d)" % (res["ip"], res["version"]))
        geo = res["geo_estimate"]
        if geo.get("available"):
            print("Country (estimate): %s  Region: %s  City: %s" % (
                geo.get("country"), geo.get("region"), geo.get("city")))
            print("ISP: %s  ASN: %s  Org: %s  Hosting: %s  Proxy: %s" % (
                geo.get("isp"), geo.get("asn"), geo.get("org"),
                geo.get("hosting"), geo.get("proxy")))
        else:
            print("Geolocation: %s (%s)" % (self.t("unknown"), geo.get("error", "")))
        rdap = res["rdap"]
        print("RDAP: %s %s %s" % (rdap.get("name"), rdap.get("handle"), rdap.get("country")))
        print("Reverse DNS: %s" % (res["ptr"] or "-"))
        for k, v in res["network_checks"].items():
            print("  %s: %s" % (k, v))
        print(terminal.grey(res["note"]))
        print(terminal.rule())
        self.pause()

    def opt_phishing(self):
        self.nav.push("phishing")
        url = self.ask_url()
        official = ""
        try:
            official = self.ask("Official domain (optional, Enter to skip)")
        except NavCommand:
            official = ""
        res = rep_mod.reputation_report(url, official_domain=official or None)
        print(terminal.rule())
        print("Verdict: %s" % res["verdict"])
        print("Risk score: %d/100  Phishing: %s  Availability: %s" % (
            res["phishing_risk"], res["phishing_classification"], res["availability"]))
        for r in res["reasons"]:
            print("  - %s" % r)
        print(terminal.rule())
        self.pause()

    def opt_domain_intel(self):
        self.nav.push("domain-intel")
        domain = self.ask_domain()
        res = domain_mod.investigate_domain(domain)
        org = org_mod.organization_report(domain)
        rel = rel_mod.related_domains(domain)
        print(terminal.rule())
        print("Domain: %s" % res["domain"])
        print("Created: %s  Expires: %s  Registrar: %s" % (
            res["registration"]["created"], res["registration"]["expires"],
            res["registration"]["registrar"]))
        print("Registrant org: %s" % res["registration"]["registrant_org"])
        print("Nameservers: %s" % ", ".join(res["nameservers"]))
        print("IPs: %s" % ", ".join(res["dns"]["ips"]))
        print("Hosting: %s" % res["hosting"])
        print("TLS issuer: %s  Days left: %s" % (
            res["tls"]["issuer"], res["tls"]["days_left"]))
        print("CT-logged associated domains: %d" % len(rel["associated_domains"]))
        for d in rel["associated_domains"][:10]:
            print("  - %s" % d)
        print("Organization: %s | Address: %s | Executives: %s | Admins: %s" % (
            org.get("official_name"), org.get("published_address"),
            org.get("executives"), org.get("administrators_count")))
        print(terminal.rule())
        self.pause()

    def opt_exposure(self):
        self.nav.push("exposure")
        url = self.ask_url()
        authorized = self.scope.is_authorized(url) or self.scope.ask_and_authorize(url)
        res = exposure_mod.audit_exposure(url, authorized=authorized)
        osint = osint_mod.osint_domain(url.split("://", 1)[-1].split("/")[0],
                                        authorized=authorized)
        print(terminal.rule())
        print("Public files found: %d  Indexed pages: %d  Public subdomains: %d" % (
            len(res["public_files"]), len(res["indexed_pages"]),
            len(osint["public_subdomains"])))
        for f in res["public_files"]:
            print("  [%s] %s (%d bytes)" % (f["status"], f["url"], f["size"]))
        for f in res["findings"]:
            print("  [%s] %s — %s" % (f["severity"].upper(), f["name"], f["evidence"]))
        print(terminal.grey(res["note"]))
        print(terminal.rule())
        self.pause()

    def opt_paths(self):
        self.nav.push("paths")
        url = self.ask_url()
        self.scope.check_or_ask(url, "path discovery")
        print("Probing %d common paths..." % len(paths_mod.DEFAULT_WORDLIST))
        results = paths_mod.discover_paths(url, delay=0.2)
        for r in results:
            print("  [%s] %s  %s" % (r["category"], r["status"], r["path"]))
        self.pause()

    def opt_auth(self):
        self.nav.push("auth")
        url = self.ask_url()
        self.scope.check_or_ask(url, "authentication audit")
        disc = auth_mod.discover_auth(url)
        print("Login forms found: %d" % len(disc.get("login_forms", [])))
        for f in disc.get("login_forms", []):
            print("  %s [%s] csrf=%s user=%s" % (
                f["action"], f["method"], f["csrf_token"], f["username_fields"]))
        if disc.get("login_forms") and self.confirm(self.t("confirm_state_change")):
            res = auth_mod.audit_auth(url, self.scope)
            for f in res.get("findings", []):
                print("  [%s/%s] %s — %s" % (f["severity"].upper(), f["status"],
                                             f["name"], f["evidence"]))
            print("Login HTTP status: %s  Session rotated: %s" % (
                res.get("login_status"), res.get("session_rotated")))
        self.pause()

    def opt_registration(self):
        self.nav.push("registration")
        url = self.ask_url()
        self.scope.check_or_ask(url, "registration audit")
        res = reg_mod.audit_registration(url, self.scope)
        for f in res.get("findings", []):
            print("  [%s/%s] %s — %s" % (f["severity"].upper(), f["status"],
                                         f["name"], f["evidence"]))
        print(res.get("note", ""))
        self.pause()

    def opt_api(self):
        self.nav.push("api")
        url = self.ask_url()
        html = http_get(url)["body"]
        eps = api_mod.discover_api(url, html)
        for e in eps:
            print("  %s %s  [%s] %s" % (e["method"], e["endpoint"], e["source"], e["status"]))
        if not eps:
            print("No public API endpoints discovered.")
        self.pause()

    def opt_malware(self):
        self.nav.push("malware")
        url = self.ask_url()
        res = malware_mod.detect_malware(url)
        for a in res.get("assets", []):
            print("  %s  sha256=%s…  verdict=%s" % (a["name"], a["sha256"][:12], a["verdict"]))
            for ind in a["indicators"]:
                print("    [%s] %s" % (ind["severity"], ind["pattern"]))
        for f in res.get("findings", []):
            print("  [%s/%s] %s — %s" % (f["severity"].upper(), f["status"],
                                         f["name"], f["evidence"]))
        self.pause()

    def opt_lab(self):
        self.nav.push("lab")
        self.out(self.t("lab_warning"))
        lab_mod.run_lab_simulation(log=lambda m: self.out(m))
        self.pause()

    def opt_health(self):
        self.nav.push("health")
        url = self.ask_url()
        res = health_mod.check_health(url, retries=1)
        print("Status: %s  HTTP: %s  TCP: %sms  TTFB: %sms  Total: %sms" % (
            res["classification"], res["status"], res["tcp_ms"],
            res["ttfb_ms"], res["total_ms"]))
        try:
            db_mod.save_availability(self.db_path, url, res,
                                     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            hist = db_mod.availability_history(self.db_path, url)
            print("History (%d records):" % len(hist))
            for h in hist[:5]:
                print("  %s  %s  HTTP %s  %sms" % (h["checked_at"], h["classification"],
                                                   h["status"], h["total_ms"]))
        except Exception as exc:
            print("History unavailable: %s" % exc)
        self.pause()

    def opt_evidence(self):
        self.nav.push("evidence")
        cases = self.cases.list()
        if not cases:
            self.out(self.t("no_previous"))
            self.pause()
            return
        for i, c in enumerate(cases, 1):
            print("  %d. %s | %s | %s" % (i, c["case_id"], c["target"], c["kind"]))
        print("  S. Record a safety/abuse incident (metadata only)")
        try:
            choice = self.ask(self.t("enter_choice"))
        except NavCommand:
            return
        if choice.strip().upper() == "S":
            self._record_incident()
            return
        try:
            idx = int(choice) - 1
            rec = cases[idx]
        except Exception:
            self.out(self.t("invalid_choice"))
            return
        files = self.cases.export_evidence(rec["case_id"], "conan-evidence")
        self.out(self.t("export_done") + ": " + ", ".join(files or []))
        self.pause()

    def _record_incident(self):
        url = self.ask(self.t("enter_url"))
        print("Categories: %s" % ", ".join(child_mod.CATEGORIES))
        category = self.ask("Category").strip().lower()
        notes = self.ask("Notes (optional)")
        try:
            rec = child_mod.analyze_reported_url(url, category, notes)
        except ValueError as exc:
            print(str(exc))
            return
        print("Incident: %s  Severity: %s" % (rec["incident_id"],
                                               rec["assessment"]["severity"]))
        print(rec["assessment"]["guidance"])
        print(self.t("report_channels") + ":")
        for ch in rec["channels"]:
            print("  - %s: %s" % (ch["name"], ch["url"]))
        print(self.t("report_note"))
        self.pause()

    def opt_previous(self):
        self.nav.push("previous")
        cases = self.cases.list()
        sessions = self.sessions.list()
        if not cases and not sessions:
            self.out(self.t("no_previous"))
            self.pause()
            return
        for c in cases:
            print("  %s | %s | %s | score %s" % (c["case_id"], c["created_at"],
                                                 c["target"], c.get("score")))
        print("Compare two cases? Enter: compare <id1> <id2>  (or Enter to go back)")
        try:
            line = self.ask(self.t("enter_choice"))
        except NavCommand:
            return
        parts = line.split()
        if len(parts) == 3 and parts[0].lower() == "compare":
            a = self.cases.get(parts[1])
            b = self.cases.get(parts[2])
            if a and b:
                from ..storage.history import compare_scans
                comp = compare_scans(a["scan"], b["scan"])
                print("Score: %s -> %s (delta %+d)" % (comp["score_before"],
                                                       comp["score_after"],
                                                       comp["score_delta"]))
                print("New findings: %s" % comp["new_findings"])
                print("Fixed findings: %s" % comp["fixed_findings"])
                print("Header changes: %s" % comp["header_changes"])
            else:
                print("Case not found.")
            self.pause()

    def opt_settings(self):
        self.nav.push("settings")
        while True:
            print("  1. %s: %s" % (self.t("language"), self.i18n.lang))
            print("  2. %s: %s" % (self.t("animation"), self.settings.get("animation")))
            print("  3. %s: %s" % (self.t("timeout"), self.settings.get("timeout")))
            print("  4. %s: %s" % (self.t("max_pages"), self.settings.get("max_pages")))
            print("  5. Scope: %d targets" % len(self.scope.targets))
            print("  0. " + self.t("main_menu"))
            try:
                choice = self.ask(self.t("enter_choice"))
            except NavCommand:
                return
            if choice == "0":
                return
            elif choice == "1":
                self.language_screen()
            elif choice == "2":
                self.settings["animation"] = not self.settings.get("animation", True)
                save_settings(self.settings)
            elif choice == "3":
                try:
                    self.settings["timeout"] = int(self.ask(self.t("timeout")))
                    save_settings(self.settings)
                except (ValueError, NavCommand):
                    pass
            elif choice == "4":
                try:
                    self.settings["max_pages"] = int(self.ask(self.t("max_pages")))
                    save_settings(self.settings)
                except (ValueError, NavCommand):
                    pass
            elif choice == "5":
                for t in self.scope.targets:
                    print("  %s (%s)" % (t["host"], t["kind"]))
                self.pause()

    # -- main loop -----------------------------------------------------------
    def run(self):
        self.nav.push("home")
        self.welcome()
        self.language_screen()
        while True:
            self.main_menu()
            try:
                choice = self.ask(self.t("enter_choice"))
            except NavCommand as nav:
                if nav.command == "EXIT":
                    break
                continue
            handlers = {
                "1": self.opt_website_investigation,
                "2": self.opt_vuln_audit,
                "3": self.opt_ip_intel,
                "4": self.opt_phishing,
                "5": self.opt_domain_intel,
                "6": self.opt_exposure,
                "7": self.opt_paths,
                "8": self.opt_auth,
                "9": self.opt_registration,
                "10": self.opt_api,
                "11": self.opt_malware,
                "12": self.opt_lab,
                "13": self.opt_health,
                "14": self.opt_evidence,
                "15": self.opt_previous,
                "16": self.opt_settings,
                "17": None,
            }
            if choice == "17":
                break
            handler = handlers.get(choice)
            if handler is None:
                self.out(self.t("invalid_choice"))
                continue
            try:
                handler()
            except NavCommand as nav:
                if nav.command == "EXIT":
                    break
                # BACK / HOME / CANCEL: return to the main menu, results kept
                self.nav.home()
                continue
            except KeyboardInterrupt:
                self.out(self.t("cancelled"))
                continue
            except ScopeError as exc:
                print(str(exc))
                self.out(self.t("not_authorized"))
                self.pause()
                continue
            except Exception as exc:
                print("Error: %s" % exc)
                self.pause()
                continue
        self.out(self.t("goodbye"))
        return 0
