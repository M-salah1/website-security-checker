#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main menu + smart investigation wizard for CONAN FRAMEWORK v7.0.

Welcome screen (full page: tool, developer, how-to) -> language
selection -> command console (`conan >`): scan <url>, help, menu,
about, lang, version, clear, exit. `scan` runs the mega scan (every
module together + detailed report) after the ethical-terms question.
The classic 20-option menu is still there via `menu` or
`python3 conan.py menu`. Navigation commands BACK / HOME / MENU /
CANCEL / EXIT work at every prompt; BACK preserves completed results
(they live in the case store and the session store, not on the screen).
"""
import ipaddress
import os
import sys
import time
import urllib.parse

from . import terminal
from .animation import Investigation, play_intro
from .authorization import AuthorizationManager, ScopeError
from .configuration import load_settings, save_settings
from .i18n import I18n, ar_display, set_reverse_arabic
from .navigation import (NavCommand, NavigationStack, SessionStore,
                        normalize_nav_command)
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
from ..scanners import mega as mega_mod
from ..scanners import paths as paths_mod
from ..scanners import ports as ports_mod
from ..scanners import phishing as phishing_mod
from ..scanners import registration as reg_mod
from ..scanners import vulnerabilities as vuln_mod
from ..scanners import website as website_mod
from ..scanners._http import get as http_get
from ..intelligence import organization as org_mod
from ..intelligence import osint as osint_mod
from ..intelligence import relationships as rel_mod
from ..intelligence import reputation as rep_mod
from ..defense import hardening
from ..defense import victim_support
from ..laboratory import safe_lab
from ..laboratory import simulator as lab_mod
from ..reporting import telegram as telegram_mod
from ..reporting.animated_report import save_animated_html_report
from ..reporting.html_report import save_html_report
from ..reporting.json_report import save_json_report
from ..scanners import verify as verify_mod
from ..storage import database as db_mod
from ..storage.cases import CaseStore
from ..storage.history import compare_stored


def _valid_url(text):
    text = (text or "").strip()
    try:
        p = urllib.parse.urlparse(text)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        host = p.hostname
        if host == "localhost":
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        # A bare word without a dot is not a site (e.g. "not-a-url").
        return "." in host
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
        # Arabic display fix: honour the saved reverse_arabic setting
        # everywhere (menu, shell, engine reports) via the i18n global.
        set_reverse_arabic(self.settings.get("reverse_arabic", True))
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

    def disp(self, text):
        """Display form of `text` for direct print() lines.

        Applies the Arabic Termux fix (pre-reversed Arabic runs) when it
        is on; a no-op otherwise. Use this for any print() line that can
        contain Arabic — out()/rtl() already do it for their own lines.
        """
        return ar_display(str(text), self.i18n.lang)

    def out(self, text=""):
        self.i18n.out(text)

    def ask(self, prompt):
        """Read one line; navigation inputs raise NavCommand.

        Navigation works everywhere, with a visible button: typing 0 (or
        BACK / رجوع) goes back, HOME goes to the main menu, EXIT quits.
        """
        try:
            line = input(self.i18n.rtl(prompt + " ")).strip()
        except KeyboardInterrupt:
            raise NavCommand("CANCEL")
        except EOFError:
            raise NavCommand("EXIT")
        cmd = normalize_nav_command(line)
        if cmd:
            raise NavCommand(cmd)
        return line

    def ask_url(self):
        while True:
            url = self.ask(self.t("enter_url") + "  (" + self.t("back_option") + ")")
            url = url.strip()
            # Bare domains are accepted too: example.com -> https://example.com
            if url and "://" not in url:
                url = "https://" + url
            if _valid_url(url):
                return url.rstrip("/")
            self.out(self.t("invalid_url"))

    def ask_ip(self):
        while True:
            ip = self.ask(self.t("enter_ip") + "  (" + self.t("back_option") + ")")
            if _valid_ip(ip):
                return ip.strip()
            self.out(self.t("invalid_ip"))

    def ask_domain(self):
        while True:
            d = self.ask(self.t("enter_url") + "  (" + self.t("back_option") + ")")
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
    def _print_welcome(self):
        """The complete welcome page: banner, tool, developer, how-to."""
        print(terminal.rule())
        print(terminal.orange("   ╔══════════════════════════════════════════════╗"))
        print(terminal.orange("   ║                                              ║"))
        print(terminal.orange("   ║    🔍  C O N A N   F R A M E W O R K      ║"))
        print(terminal.orange("   ║    " + self.disp(self.t("app_title")) + "                          ║"))
        print(terminal.orange("   ║    " + self.disp(self.t("app_subtitle")) + "              ║"))
        print(terminal.orange("   ║                                              ║"))
        print(terminal.orange("   ╚══════════════════════════════════════════════╝"))
        print(terminal.green("   🛡  " + self.disp(self.t("shield_line"))))
        print(terminal.rule())
        self.out("   ◆ %s" % self.disp(self.t("about_tool")))
        self.out("   %s" % self.disp(self.t("about_tool_text")))
        print()
        self.out("   ◆ %s" % self.disp(self.t("about_developer")))
        self.out("   Hafed Mehdi Salah Eddine  •  %s" % self.disp(self.t("developer_role")))
        self.out("   GitHub: M-salah1  •  %s" % self.disp(self.t("developer_org")))
        print()
        self.out("   ◆ %s" % self.disp(self.t("how_to_work")))
        self.out("   %s" % self.disp(self.t("how_to_steps")))
        print(terminal.grey("   CONAN FRAMEWORK v%s  •  Copyright © 2026" % __version__))
        print(terminal.rule())

    def welcome(self):
        play_intro(enabled=self.settings.get("animation", True)
                   and not self.no_animation)
        self._print_welcome()
        self.pause()

    def show_splash(self):
        """Same welcome page, shown again by the `about` command."""
        self._print_welcome()
        self.pause()

    def accept_terms(self, url):
        """Ethical-use terms: the user confirms with y, then work begins.

        Returns True on acceptance (and records the authorization for this
        target, so the deep tests run); False on decline, which returns
        to the URL prompt. EXIT navigation is re-raised.
        """
        print(terminal.rule())
        print(terminal.orange("   ⚖  " + self.disp(self.t("terms_title"))))
        self.out("   • %s" % self.disp(self.t("terms_1")))
        self.out("   • %s" % self.disp(self.t("terms_2")))
        self.out("   • %s" % self.disp(self.t("terms_3")))
        self.out("   • %s" % self.disp(self.t("terms_4")))
        print(terminal.rule())
        try:
            ans = self.ask(self.t("terms_accept"))
        except NavCommand as nav:
            if nav.command == "EXIT":
                raise
            return False
        if ans.strip().lower() in ("y", "yes", "نعم", "oui", "o"):
            try:
                self.scope.authorize(url, "authorized")
            except Exception:
                pass
            self.out(self.t("terms_accepted"))
            return True
        self.out(self.t("terms_declined"))
        return False

    def language_screen(self):
        self.out(self.t("choose_language") + ":")
        print("   1. " + self.disp("العربية"))
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
        print(terminal.orange("   " + self.disp(self.t("main_menu"))))
        for i in range(1, 21):
            print("   %s %s" % (terminal.orange("%2d." % i),
                                self.disp(self.t("menu_%d" % i))))
        # Visible back button: on the main menu there is nowhere back to,
        # so 0 exits — exactly like the phone back button on a home screen.
        print("    %s %s" % (terminal.orange("0."),
                             self.disp(self.t("back_exit"))))
        print(terminal.rule())
        print(terminal.green("   🛡  " + self.disp(self.t("shield_line"))))
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

    def _score_text(self, scan):
        """Score line. A failed measurement is INCOMPLETE, never 0%."""
        if scan.get("score") is None:
            cov = (scan.get("coverage") or {}).get("percent")
            extra = ("   %s: %s%%" % (self.t("coverage"), cov)) \
                if cov is not None else ""
            return "%s: %s   %s: %s   %s: %s%%   %s: %s s%s" % (
                self.t("score"), self.t("incomplete"),
                self.t("grade"), self.t("incomplete"),
                self.t("confidence"), scan.get("confidence") or 0,
                self.t("duration"), scan.get("duration_s"), extra)
        return "%s: %s%%   %s: %s   %s: %s%%   %s: %s s" % (
            self.t("score"), scan.get("score"), self.t("grade"),
            scan.get("grade"), self.t("confidence"), scan.get("confidence"),
            self.t("duration"), scan.get("duration_s"))

    def show_dashboard(self, rec):
        scan = rec["scan"]
        print(terminal.rule())
        print(terminal.orange("🔍 %s — %s" % (rec["case_id"], scan.get("target"))))
        self.out(self._score_text(scan))
        dist = scan.get("severity_distribution") or {}
        self.out("%s: %s" % (self.t("findings"),
                             ", ".join("%s=%d" % (k, v) for k, v in dist.items() if v)))
        for f in (scan.get("findings") or [])[:8]:
            print("  [%s/%s] %s" % (f["severity"].upper(), f["status"],
                                    self.disp(f["name"])))
        print(terminal.rule())
        self.out("0. %s    1. %s    2. JSON    3. HTML    4. %s    5. %s    6. %s    7. %s" % (
            self.t("back"), self.t("findings"), self.t("animated_report"),
            self.t("telegram"), self.t("full_port_scan"), self.t("verify")))
        try:
            choice = self.ask(self.t("enter_choice"))
        except NavCommand:
            return
        if choice == "1":
            for f in (scan.get("findings") or []):
                print("  [%s/%s] %s" % (f["severity"].upper(), f["status"],
                                        self.disp(f["name"])))
                print("      %s" % self.disp(f.get("evidence", "")[:180]))
                print("      Fix: %s" % self.disp(f.get("remediation", "")[:180]))
            self.pause()
        elif choice == "2":
            save_json_report(scan, "conan-report.json")
            self.out(self.t("export_done") + ": conan-report.json")
        elif choice == "3":
            save_html_report(scan, "conan-report.html")
            self.out(self.t("export_done") + ": conan-report.html")
        elif choice == "4":
            save_animated_html_report(scan, "conan-report-animated.html")
            self.out(self.t("export_done") + ": conan-report-animated.html")
        elif choice == "5":
            self.opt_send_telegram(rec)
        elif choice == "6":
            self.opt_full_port_scan(rec)
        elif choice == "7":
            self.opt_verify(rec)

    def opt_verify(self, rec):
        """Verification Mode: compare an owner-provided value against
        what the scan found — yes/no + location, never the value."""
        scan = rec["scan"]
        if not (scan.get("scope") or {}).get("authorized"):
            self.out(self.t("verify_need_auth"))
            return
        self.out(self.t("verify_intro"))
        secret = self._ask_hidden(self.t("verify_value"))
        if not secret:
            return
        self.out(self.t("verify_checking"))
        result = verify_mod.verify_secret(scan, secret)
        secret = ""  # wipe the local reference immediately
        if result.get("cookie_match"):
            self.out(self.t("verify_cookie_match"))
        if result.get("found"):
            self.out(self.t("verify_found"))
            for loc in result["found"][:10]:
                print("   %s" % loc["where"])
        else:
            self.out(self.t("verify_not_found"))
        self.out("%s: %d" % (self.t("verify_checked"),
                             result.get("checked", 0)))
        self.pause()

    def opt_full_port_scan(self, rec):
        """Full scan of all 65535 ports on the target IP.

        Authorized targets only; asks for confirmation first because
        it takes minutes and is noisy. Shows a progress percentage.
        """
        scan = rec["scan"]
        url = scan.get("target") or ""
        if not (scan.get("scope") or {}).get("authorized"):
            self.out(self.t("ports_need_auth"))
            return
        host = url.split("/")[2] if "://" in url else url
        self.out(self.t("full_port_scan_warn"))
        try:
            confirm = self.ask(self.t("confirm_yes"))
        except NavCommand:
            return
        if (confirm or "").strip().lower() not in ("y", "yes", "نعم"):
            return
        total = 65535
        done = [0]
        tty = terminal.is_tty()

        def progress():
            done[0] += 1
            if tty and done[0] % 500 == 0:
                sys.stdout.write("\r\x1b[K%s %d%%" % (
                    self.t("scanning_ports"),
                    int(100 * done[0] / total)))
                sys.stdout.flush()

        open_ports = ports_mod.scan_all_ports(host, progress=progress)
        if tty:
            sys.stdout.write("\r\x1b[K")
            sys.stdout.flush()
        entries = ports_mod.probe_entry_points(host, open_ports, url)
        scan.setdefault("ports", {})["full_scan"] = {
            "open_ports": open_ports, "open_count": len(open_ports),
            "entry_points": entries,
            "doors_serving_site": [e["port"] for e in entries
                                   if e.get("serves_site")]}
        self.out("%s: %d" % (self.t("open_ports"), len(open_ports)))
        for p in open_ports[:20]:
            banner = (" — %s" % p["banner"][:80]) if p.get("banner") else ""
            print("   [%d] %s%s" % (p["port"], p.get("service", "?"), banner))
        doors = [e["port"] for e in entries if e.get("serves_site")]
        self.out("%s: %s" % (self.t("entry_points"),
                             ", ".join(str(d) for d in doors)
                             if doors else self.t("none")))
        self.pause()

    def opt_send_telegram(self, rec):
        """Optional Telegram delivery of the full report.

        Asks for the user's own chat ID and bot token. The token is
        typed hidden, sent only to Telegram's official API, and never
        stored, saved or printed anywhere.
        """
        scan = rec["scan"]
        self.out(self.t("telegram_intro"))
        try:
            chat_id = self.ask(self.t("telegram_chat_id"))
        except NavCommand:
            return
        if not (chat_id or "").strip():
            return
        token = self._ask_token()
        if not token:
            return
        self.out(self.t("telegram_sending"))
        text = telegram_mod.build_telegram_report(scan, self.i18n.lang)
        sent, error = telegram_mod.send_telegram(token, chat_id, text)
        if error:
            self.out("%s: %s" % (self.t("telegram_failed"), error))
        else:
            self.out("%s (%d)" % (self.t("telegram_sent"), sent))

    def _ask_token(self):
        """Read the bot token hidden (getpass); never echo or store it."""
        return self._ask_hidden(self.t("telegram_token"))

    def _ask_hidden(self, prompt):
        """Read a secret value hidden (getpass); never echo or store it."""
        import getpass
        try:
            value = getpass.getpass(prompt + " ")
            return (value or "").strip()
        except (EOFError, KeyboardInterrupt):
            return ""
        except Exception:
            try:
                return self.ask(prompt).strip()
            except NavCommand:
                return ""

    # -- menu options ------------------------------------------------------
    def opt_mega_scan(self, url=None):
        """The big scan: one URL, every module together, one detailed report."""
        self.nav.push("mega-scan")
        if url is None:
            url = self.ask_url()
        inv = self._anim(total=len(mega_mod.DEEP_TESTS))
        inv.start()
        try:
            scan = mega_mod.mega_scan(
                url, scope=self.scope, settings=self.settings,
                progress=lambda name: inv.phase(name))
        finally:
            inv.done()
        rec = self.finish_case("mega-scan", url, mega_mod.DEEP_TESTS,
                               "authorized" if self.scope.is_authorized(url) else "passive",
                               scan)
        self.print_mega_report(rec)
        self.show_dashboard(rec)

    def print_mega_report(self, rec):
        """Detailed report: identity, history, admin, country, servers,
        paths, deep tests, findings and fixes — public data only."""
        scan = rec["scan"]
        hist = scan.get("history") or {}
        servers = scan.get("servers") or {}
        print(terminal.rule())
        print(terminal.orange("🔍 %s" % self.disp(self.t("detailed_report"))))
        self.out("%s: %s" % (self.disp(self.t("target")), scan.get("target")))
        self.out(self._score_text(scan))
        if scan.get("resumed_from"):
            self.out("   %s: %s" % (self.disp(self.t("resumed")),
                                   ", ".join(scan["resumed_from"])))
        # 1. Identity & country
        print(terminal.rule())
        self.out("1. %s" % self.disp(self.t("identity")))
        self.out("   %s: %s" % (self.disp(self.t("domain")), hist.get("domain")))
        self.out("   %s: %s" % (self.disp(self.t("country")),
                               hist.get("country") or "UNKNOWN"))
        if hist.get("city") or hist.get("region"):
            self.out("   %s: %s" % (self.disp(self.t("city")),
                                   ", ".join(x for x in (hist.get("city"), hist.get("region")) if x)))
        self.out("   %s: %s" % (self.disp(self.t("hosted_by")),
                               hist.get("hosting_org") or "UNKNOWN"))
        # 2. Domain history
        print(terminal.rule())
        self.out("2. %s" % self.disp(self.t("domain_history")))
        self.out("   %s: %s" % (self.disp(self.t("created")), hist.get("created") or "UNKNOWN"))
        self.out("   %s: %s" % (self.disp(self.t("expires")), hist.get("expires") or "UNKNOWN"))
        self.out("   %s: %s" % (self.disp(self.t("registrar")), hist.get("registrar") or "UNKNOWN"))
        self.out("   %s: %s" % (self.disp(self.t("registrant_org")),
                               hist.get("registrant_org") or "UNKNOWN"))
        self.out("   %s: %s" % (self.disp(self.t("earliest_certificate")),
                               hist.get("earliest_certificate") or "UNKNOWN"))
        self.out("   %s: %s (%s: %d)" % (self.disp(self.t("previous_names")),
                                        hist.get("previous_names") or "UNKNOWN",
                                        self.disp(self.t("ct_certificates")),
                                        hist.get("ct_certificates") or 0))
        self.out("   %s" % self.disp(self.t("history_note")))
        # 3. Admin contact (published only)
        print(terminal.rule())
        self.out("3. %s" % self.disp(self.t("admin_contact")))
        self.out("   %s" % self.disp(hist.get("admin_contact") or "UNKNOWN"))
        self.out("   %s: %s" % (self.disp(self.t("source")),
                               self.disp(hist.get("admin_contact_source") or "")))
        contacts = scan.get("contacts") or {}
        for email in (contacts.get("emails") or [])[:3]:
            print("   ✉ %s" % email)
        for line in (contacts.get("contact_lines") or [])[:3]:
            self.out("   %s" % self.disp(line))
        # 4. Servers
        print(terminal.rule())
        self.out("4. %s" % self.disp(self.t("servers")))
        self.out("   %s: %s" % (self.disp(self.t("server_header")),
                               servers.get("server_header") or "UNKNOWN"))
        self.out("   IP: %s" % ", ".join(servers.get("ips") or ["UNKNOWN"]))
        self.out("   NS: %s" % ", ".join(servers.get("nameservers") or ["UNKNOWN"]))
        self.out("   MX: %s" % ", ".join(servers.get("mx") or ["UNKNOWN"]))
        self.out("   %s: %s" % (self.disp(self.t("tls_issuer")),
                               servers.get("tls_issuer") or "UNKNOWN"))
        methods = scan.get("methods") or {}
        self.out("   %s: %s" % (self.disp(self.t("http_methods")),
                               ", ".join(methods.get("methods") or ["UNKNOWN"])))
        redirs = scan.get("redirects") or {}
        chain = redirs.get("chain") or []
        self.out("   %s: %s" % (self.disp(self.t("redirect_chain")),
                               (" -> ".join("%d %s" % (c, u) for c, u in chain)
                                if chain else self.disp(self.t("none")))))
        # 5. Paths
        print(terminal.rule())
        self.out("5. %s" % self.disp(self.t("paths")))
        deep = scan.get("deep_paths") or []
        if isinstance(deep, list):
            public = [d for d in deep if d.get("category") == "PUBLIC"]
            auth = [d for d in deep if d.get("category") == "AUTHENTICATION REQUIRED"]
            self.out("   %s: %d  |  %s: %d  |  %s: %d" % (
                self.disp(self.t("public")), len(public),
                self.disp(self.t("auth_required")), len(auth),
                self.disp(self.t("probed")), len(deep)))
            for d in public[:10]:
                print("     [200] %s" % d["path"])
        else:
            self.out("   %s" % self.disp(self.t("deep_paths_note")))
        disc = scan.get("discovery") or {}
        self.out("   %s: %s" % (self.disp(self.t("discovered_pages")),
                               len(disc.get("pages", []) or [])))
        # 6. Cookies (names + flags only — values are never shown)
        print(terminal.rule())
        self.out("6. %s" % self.disp(self.t("cookies")))
        cookies = scan.get("cookies") or {}
        for c in (cookies.get("cookies") or [])[:10]:
            self.out("   %s  [Secure=%s HttpOnly=%s SameSite=%s]" % (
                c.get("name", "?"), bool(c.get("secure")),
                bool(c.get("httponly")), c.get("samesite") or "-"))
        self.out("   %s" % self.disp(self.t("cookies_note")))
        # 7. API & client-side reverse engineering (public JS only)
        print(terminal.rule())
        self.out("7. %s" % self.disp(self.t("js_api")))
        js = scan.get("js_api") or {}
        self.out("   %s: %s" % (self.disp(self.t("scripts_scanned")),
                               js.get("scripts_scanned", 0)))
        self.out("   GraphQL: %s" % ("yes" if js.get("graphql") else "no"))
        for ep in (js.get("endpoints") or [])[:10]:
            print("   → %s" % ep)
        for ws in (js.get("websockets") or [])[:3]:
            print("   ⇌ %s" % ws)
        # 8. Real IP & origin
        print(terminal.rule())
        self.out("8. %s" % self.disp(self.t("real_ip")))
        origin = scan.get("origin") or {}
        self.out("   IP: %s" % ", ".join(origin.get("ips") or ["UNKNOWN"]))
        self.out("   %s: %s" % (self.disp(self.t("cdn_detected")),
                               "yes" if origin.get("cdn_detected") else "no"))
        if origin.get("cdn_signals"):
            self.out("   %s" % ", ".join(origin["cdn_signals"]))
        direct = origin.get("direct_ip") or {}
        if direct:
            self.out("   %s: %s (%s)" % (self.disp(self.t("direct_ip_check")),
                                        direct.get("ip"),
                                        direct.get("verdict")))
        self.out("   %s: %s" % (self.disp(self.t("origin_ip")),
                               self.disp(origin.get("origin") or "UNKNOWN")))
        # 9. Permissions & certificates
        print(terminal.rule())
        self.out("9. %s" % self.disp(self.t("permissions_section")))
        perms = scan.get("permissions") or {}
        self.out("   Permissions-Policy: %s" % (
            (perms.get("permissions_policy") or "UNKNOWN")[:120]))
        self.out("   CORS: %s" % (perms.get("cors") or "UNKNOWN"))
        self.out("   CSP: %s" % ("yes" if perms.get("csp") else "no"))
        self.out("   %s: %s (%s: %s)" % (self.disp(self.t("tls_issuer")),
                                        perms.get("tls_issuer") or "UNKNOWN",
                                        self.disp(self.t("tls_days_left")),
                                        perms.get("tls_days_left")))
        self.out("   %s: %s" % (self.disp(self.t("ct_certificates")),
                               perms.get("ct_certificates", 0)))
        # 10. Ports & Sunlight/Echo adaptive probe
        print(terminal.rule())
        self.out("10. %s" % self.disp(self.t("ports_section")))
        ports = scan.get("ports") or {}
        if ports.get("note"):
            self.out("   %s" % self.disp(ports["note"]))
        else:
            self.out("   %s: %s" % (self.disp(self.t("open_ports")),
                                   ports.get("open_count", 0)))
            for p in (ports.get("open_ports") or [])[:15]:
                banner = (" — %s" % p["banner"][:80]) if p.get("banner") else ""
                print("   [%d] %s%s" % (p["port"], p.get("service", "?"), banner))
            doors = ports.get("doors_serving_site") or []
            self.out("   %s: %s" % (self.disp(self.t("entry_points")),
                                   ", ".join(str(d) for d in doors)
                                   if doors else self.disp(self.t("none"))))
        # 11. What Conan learned (Site Brain)
        print(terminal.rule())
        self.out("11. %s" % self.disp(self.t("learned_section")))
        profile = scan.get("learned_profile") or {}
        for rule in (profile.get("rules") or [])[:8]:
            self.out("   • %s" % self.disp(rule))
        changes = scan.get("learned_changes") or []
        if changes:
            self.out("   %s:" % self.disp(self.t("learned_changes")))
            for ch in changes[:10]:
                mark = {"added": "+", "removed": "-", "changed": "~"}.get(
                    ch.get("kind"), "?")
                self.out("   %s %s" % (mark, self.disp(ch.get("detail", ""))))
        else:
            self.out("   %s" % self.disp(self.t("no_changes")))
        # 12. Conan AI Brain — the detective's reasoning
        print(terminal.rule())
        self.out("12. %s" % self.disp(self.t("ai_brain")))
        brain = scan.get("ai_brain") or {}
        if brain.get("verdict"):
            self.out("   %s" % self.disp(brain["verdict"]))
        if brain.get("first_fix"):
            self.out("   %s" % self.disp(brain["first_fix"]))
        for note in (brain.get("new_since_last") or [])[:3]:
            self.out("   ! %s" % self.disp(note))
        if brain.get("chains"):
            self.out("   %s:" % self.disp(self.t("attack_chains")))
            for chain in brain["chains"][:3]:
                self.out("   [%s] %s" % (chain["severity"].upper(),
                                         self.disp(chain["title"])))
                self.out("      %s" % self.disp(chain["story"]))
                if chain.get("evidence"):
                    self.out("      %s: %s" % (self.disp(self.t("evidence")),
                                               ", ".join(chain["evidence"])))
                self.out("      %s: %s" % (self.disp(self.t("how_to_stop")),
                                           self.disp(chain["stop"])))
        if brain.get("priorities"):
            self.out("   %s:" % self.disp(self.t("priorities")))
            for p in brain["priorities"][:5]:
                self.out("   [%s] %s" % (p["severity"].upper(),
                                         self.disp(p["name"])))
        if brain.get("next_tests"):
            self.out("   %s:" % self.disp(self.t("next_tests")))
            for test in brain["next_tests"][:4]:
                self.out("   → %s" % self.disp(test))
        # 13. Deep tests + findings
        print(terminal.rule())
        self.out("13. %s" % self.disp(self.t("deep_tests")))
        if scan.get("phase_timeouts"):
            self.out("   %s: %s" % (self.disp(self.t("phase_timeout")),
                                   ", ".join(scan["phase_timeouts"])))
        status = scan.get("module_status") or {}
        if status:
            self.out("   %s:" % self.disp(self.t("module_status")))
            for name in (scan.get("deep_tests") or []):
                run = status.get(name)
                if not run:
                    continue
                line = "   • %s: %s (%ss" % (
                    name, run.get("status"), run.get("duration_s"))
                if run.get("retries"):
                    line += ", %d %s" % (run["retries"], "retries")
                if run.get("error"):
                    line += " — %s" % run["error"][:80]
                self.out(line + ")")
        self.out("   %s" % ", ".join(scan.get("deep_tests") or []))
        findings = scan.get("findings") or []
        dist = scan.get("severity_distribution") or {}
        self.out("%s: %s" % (self.disp(self.t("findings")),
                            ", ".join("%s=%d" % (k, v) for k, v in dist.items() if v)))
        for f in findings[:10]:
            print("  [%s/%s] %s" % (f["severity"].upper(), f["status"],
                                    self.disp(f["name"])))
        for fix in (scan.get("recommendations") or [])[:5]:
            self.out("   • %s" % self.disp(fix))
        print(terminal.rule())

    def opt_website_investigation(self):
        self.nav.push("website")
        url = self.ask_url()
        if not self.accept_terms(url):
            return
        # Passive modules run without authorization; only the active parts
        # (paths discovery, file inspection) need it — website.py handles
        # that by skipping them when unauthorized.
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
        scan = {"tool": "CONAN FRAMEWORK v7.0", "target": url,
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
        # Optional question — BACK / 0 here cancels the whole option and
        # returns to the main menu (previously it was swallowed and the
        # scan started anyway).
        official = self.ask("Official domain (optional, Enter to skip)")
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
            print("  [%s] %s — %s" % (f["severity"].upper(), self.disp(f["name"]), self.disp(f["evidence"])))
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
                                             self.disp(f["name"]), self.disp(f["evidence"])))
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
                                         self.disp(f["name"]), self.disp(f["evidence"])))
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
                                         self.disp(f["name"]), self.disp(f["evidence"])))
        self.pause()

    def opt_lab(self):
        self.nav.push("lab")
        self.out(self.t("lab_warning"))
        lab_mod.run_lab_simulation(log=lambda m: self.out(m))
        self.pause()

    def opt_safe_lab(self):
        """Safe lab: a deliberately vulnerable demo site on 127.0.0.1 only.

        Ethical training without touching any real site — the scanners run
        against localhost, find real (demo) weaknesses, and each finding
        comes with its fix. The lab is stopped and cleaned up on exit.
        """
        self.nav.push("safe-lab")
        self.out(self.t("safe_lab") + " — 127.0.0.1 only, demo site, no real data.")
        server, url = safe_lab.start_lab()
        try:
            print("%s %s" % (self.t("lab_started"), url))
            self.out(self.t("training_scan") + "...")
            res = safe_lab.run_lab_training(url)
            for f in res["findings"]:
                print("  [%s/%s] %s" % (f["severity"].upper(), f["status"], self.disp(f["name"])))
                print("      %s" % f.get("training_note", "")[:200])
            if not res["findings"]:
                self.out("No findings — the lab may not have started correctly.")
            print(terminal.grey(res["note"]))
            self.pause()
        finally:
            safe_lab.stop_lab(server)
            self.out(self.t("lab_stopped"))

    def opt_victim_protection(self):
        """Victim protection: safety plan, evidence checklist, channels.

        No URL is ever fetched and no content is downloaded — this is
        guidance and safe metadata recording only.
        """
        self.nav.push("victim")
        while True:
            print("  1. %s" % self.disp(self.t("record_incident")))
            print("  2. %s" % self.disp(self.t("safety_plan")))
            print("  3. %s" % self.disp(self.t("evidence_checklist")))
            print("  4. %s" % self.disp(self.t("channels")))
            print("  0. %s" % self.disp(self.t("back")))
            try:
                choice = self.ask(self.t("enter_choice"))
            except NavCommand:
                return
            if choice == "1":
                self._record_incident()
            elif choice == "2":
                for step in victim_support.safety_plan(self.i18n.lang):
                    self.out("  - " + step)
                self.pause()
            elif choice == "3":
                for step in victim_support.evidence_checklist(self.i18n.lang):
                    self.out("  - " + step)
                self.pause()
            elif choice == "4":
                for ch in victim_support.report_channels():
                    print("  - %s: %s" % (ch["name"], ch["url"]))
                self.pause()

    def opt_defense(self):
        """Defense center: hardening, incident plan, takedown template.

        Defensive only. Nothing here attacks anyone: the "deterrence" is
        hardening your own server, blocking abuse at your own firewall,
        and reporting through official channels with preserved evidence.
        """
        self.nav.push("defense")
        while True:
            print("  1. %s (Apache)" % self.disp(self.t("hardening")))
            print("  2. %s (Nginx)" % self.disp(self.t("hardening")))
            print("  3. %s" % self.disp(self.t("incident_plan")))
            print("  4. %s" % self.disp(self.t("takedown_template")))
            print("  5. %s" % self.disp(self.t("animated_report")))
            print("  0. %s" % self.disp(self.t("back")))
            try:
                choice = self.ask(self.t("enter_choice"))
            except NavCommand:
                return
            if choice == "1":
                print(hardening.apache_snippet())
                self.pause()
            elif choice == "2":
                print(hardening.nginx_snippet())
                self.pause()
            elif choice == "3":
                for title, step in hardening.incident_response_plan():
                    print("  %s — %s" % (title, step))
                print("  Rate limits (your own server):")
                for g in hardening.rate_limit_guidance():
                    print("    - " + g)
                self.pause()
            elif choice == "4":
                url = self.ask_url()
                kind = self.ask("Kind (threats / harassment / illegal content)")
                print(hardening.takedown_request_template(url, kind or "abusive content"))
                self.pause()
            elif choice == "5":
                if not self.last_result:
                    self.out(self.t("no_scan_yet"))
                else:
                    save_animated_html_report(self.last_result, "conan-report-animated.html")
                    self.out(self.t("export_done") + ": conan-report-animated.html")
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
            print("  1. %s: %s" % (self.disp(self.t("language")), self.i18n.lang))
            print("  2. %s: %s" % (self.disp(self.t("animation")), self.settings.get("animation")))
            print("  3. %s: %s" % (self.disp(self.t("timeout")), self.settings.get("timeout")))
            print("  4. %s: %s" % (self.disp(self.t("max_pages")), self.settings.get("max_pages")))
            print("  5. Scope: %d targets" % len(self.scope.targets))
            print("  6. %s: %s" % (self.disp(self.t("reverse_arabic")),
                                  self.settings.get("reverse_arabic", True)))
            print("  0. " + self.disp(self.t("main_menu")))
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
            elif choice == "6":
                # Toggle the Termux Arabic fix live: on = write Arabic
                # pre-reversed so the terminal shows it readable.
                self.settings["reverse_arabic"] = not self.settings.get("reverse_arabic", True)
                save_settings(self.settings)
                set_reverse_arabic(self.settings["reverse_arabic"])

    # -- main loop -----------------------------------------------------------
    def run(self, start_menu=False):
        self.nav.push("home")
        self.welcome()
        self.language_screen()
        if start_menu:
            return self.classic_menu_loop()
        return self.console_loop()

    def console_loop(self):
        """The command console — the tool's front door.

        Commands: scan <url>, <url>, help, menu, about, lang, version,
        clear, exit. Type `help` for the full work guide.
        """
        self.out(self.t("console_welcome"))
        while True:
            # Raw input here: the console's own words (menu, back, exit)
            # must reach the console, not the navigation layer.
            try:
                line = input("conan > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            cmd, _, rest = line.partition(" ")
            cmd = cmd.lower()
            rest = rest.strip()
            if cmd in ("exit", "quit", "0"):
                break
            if cmd == "help":
                self.print_help()
                continue
            if cmd == "menu":
                self.classic_menu_loop(from_console=True)
                continue
            if cmd == "about":
                self.show_splash()
                continue
            if cmd == "version":
                self.out("CONAN FRAMEWORK v%s" % __version__)
                continue
            if cmd == "lang":
                self.language_screen()
                continue
            if cmd == "clear":
                print("\033[2J\033[H", end="")
                continue
            if cmd == "scan":
                try:
                    url = rest or self.ask_url()
                except NavCommand:
                    continue
                if not self._scan_command(url):
                    break
                continue
            if self._looks_like_url(line):
                if not self._scan_command(line):
                    break
                continue
            self.out(self.t("unknown_command"))
        self.out(self.t("goodbye"))
        return 0

    def print_help(self):
        """The work guide: every command + how to work with the tool."""
        print(terminal.rule())
        print(terminal.orange("   " + self.disp(self.t("help_title"))))
        self.out("   scan <url>   —  %s" % self.disp(self.t("help_scan")))
        self.out("   <url>        —  %s" % self.disp(self.t("help_bare_url")))
        self.out("   menu         —  %s" % self.disp(self.t("help_menu")))
        self.out("   about        —  %s" % self.disp(self.t("help_about")))
        self.out("   lang         —  %s" % self.disp(self.t("help_lang")))
        self.out("   version      —  %s" % self.disp(self.t("help_version")))
        self.out("   clear        —  %s" % self.disp(self.t("help_clear")))
        self.out("   exit         —  %s" % self.disp(self.t("help_exit")))
        print(terminal.rule())
        self.out("   %s" % self.disp(self.t("how_to_work")))
        self.out("   %s" % self.disp(self.t("how_to_steps")))
        self.out("   %s" % self.disp(self.t("help_tip")))
        print(terminal.rule())

    @staticmethod
    def _looks_like_url(line):
        text = line.strip()
        if "://" in text:
            return _valid_url(text)
        return _valid_url("https://" + text)

    def _scan_command(self, url):
        """Terms (y) then the mega scan. False = user asked to exit."""
        try:
            if not self.accept_terms(url):
                return True
            self.opt_mega_scan(url)
        except NavCommand as nav:
            if nav.command == "EXIT":
                return False
            self.nav.home()
        except KeyboardInterrupt:
            self.out(self.t("cancelled"))
        except ScopeError as exc:
            print(str(exc))
            self.out(self.t("not_authorized"))
            self.pause()
        except Exception as exc:
            print("Error: %s" % exc)
            self.pause()
        return True

    def classic_menu_loop(self, from_console=False):
        while True:
            self.main_menu()
            try:
                choice = self.ask(self.t("enter_choice"))
            except NavCommand as nav:
                # On the main menu, BACK (0) is the same as EXIT: there is
                # nowhere further back to go.
                if nav.command in ("EXIT", "BACK"):
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
                "17": self.opt_safe_lab,
                "18": self.opt_victim_protection,
                "19": self.opt_defense,
                "20": None,
            }
            if choice == "20":
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
        # From the console, exiting the classic menu returns to the
        # console prompt; otherwise the goodbye ends the app.
        if not from_console:
            self.out(self.t("goodbye"))
        return 0
