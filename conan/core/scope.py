#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scope and authorization manager.

Active tests (SQLi / XSS / CSRF / auth / registration / session) only run
against targets the user explicitly authorized: owned domains, authorized
testing domains, staging environments, localhost / private test environments.

The scope file stores ONLY the target list and limits. Test credentials are
never stored in plain text — if the user supplies them, they are kept in
memory for the session only, and never written to logs or reports.

Rules enforced here:
- no password guessing, credential stuffing, account takeover, auth bypass,
  destructive testing or unauthorized account creation — ever;
- state-changing operations (login, registration) require explicit
  confirmation right before they run;
- rate limits, maximum scan duration, maximum crawl depth, excluded paths.
"""
import getpass
import json
import os
import urllib.parse

SCOPE_FILE = "conan-scope.json"


class ScopeError(Exception):
    pass


class ScopeManager:
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.getcwd()
        self.path = os.path.join(self.base_dir, SCOPE_FILE)
        self.targets = []          # [{"url":..., "kind":"owned|authorized|staging|local", "added":...}]
        self.excluded_paths = ["/logout", "/delete", "/admin/delete"]
        self.rate_limit = 0.5      # seconds between requests
        self.max_duration = 300    # seconds
        self.max_depth = 2
        self.max_pages = 50
        self.load()

    # -- persistence ------------------------------------------------------
    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.targets = data.get("targets", [])
                self.excluded_paths = data.get("excluded_paths", self.excluded_paths)
                self.rate_limit = float(data.get("rate_limit", self.rate_limit))
                self.max_duration = int(data.get("max_duration", self.max_duration))
                self.max_depth = int(data.get("max_depth", self.max_depth))
                self.max_pages = int(data.get("max_pages", self.max_pages))
        except Exception:
            pass

    def save(self):
        data = {
            "targets": self.targets,
            "excluded_paths": self.excluded_paths,
            "rate_limit": self.rate_limit,
            "max_duration": self.max_duration,
            "max_depth": self.max_depth,
            "max_pages": self.max_pages,
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    # -- authorization ----------------------------------------------------
    @staticmethod
    def _host(url):
        try:
            return (urllib.parse.urlparse(url).hostname or "").lower()
        except Exception:
            return ""

    @staticmethod
    def _is_local(host):
        return host in ("localhost", "127.0.0.1", "::1") or host.startswith("192.168.") \
            or host.startswith("10.") or host.startswith("172.16.") \
            or host.endswith(".local") or host.endswith(".test")

    def authorize(self, url, kind="owned"):
        """Explicitly authorize a target. kind: owned|authorized|staging|local."""
        host = self._host(url)
        if not host:
            raise ScopeError("Invalid URL: %s" % url)
        if kind not in ("owned", "authorized", "staging", "local"):
            raise ScopeError("Unknown scope kind: %s" % kind)
        if kind == "local" and not self._is_local(host):
            raise ScopeError("local scope requires localhost or a private address")
        entry = {"url": url, "host": host, "kind": kind}
        if not any(t.get("host") == host for t in self.targets):
            self.targets.append(entry)
            self.save()
        return entry

    def is_authorized(self, url):
        host = self._host(url)
        if self._is_local(host):
            return True  # localhost / private test environments are in-scope by design
        return any(t.get("host") == host for t in self.targets)

    def require_authorized(self, url, what="active test"):
        if not self.is_authorized(url):
            raise ScopeError(
                "Not authorized: %s\n"
                "This %s needs explicit authorization. Run:\n"
                "  conan > scope add <url> owned\n"
                "Use it only for your own sites or sites you have written "
                "authorization to test." % (url, what))

    def is_excluded(self, url):
        path = urllib.parse.urlparse(url).path or "/"
        return any(path.startswith(p) for p in self.excluded_paths)

    def confirm(self, action, default=False):
        """Explicit confirmation before any state-changing operation."""
        try:
            ans = input("Confirm: %s ? [y/N] " % action).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans in ("y", "yes")

    # -- test credentials (memory only, never persisted) ------------------
    @staticmethod
    def prompt_credentials():
        """Ask for test credentials interactively; password is hidden and
        never printed, logged or saved."""
        user = input("Test username/email: ").strip()
        pw = getpass.getpass("Test password (hidden, not stored): ")
        if not user or not pw:
            raise ScopeError("Test credentials are required for this audit.")
        return {"username": user, "password": pw}
