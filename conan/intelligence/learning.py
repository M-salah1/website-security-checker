#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Site Brain — the tool learns a site from its own public behaviour.

Every scan builds a baseline profile ("rules and fundamentals") from
observed public facts only: server header, TLS issuer, IPs, open
ports, discovered pages, API endpoints, cookies, security headers,
HTTP methods, redirect behaviour, findings. The profile is saved
locally (conan-profiles.json) keyed by domain. On the next scan the
new profile is compared with the previous one — what appeared, what
disappeared, what changed. Those changes are the site's faults and
regressions, reported in plain language.

This is observation, not control: the tool never changes the site,
never logs in, and never sees private data. Live user counts, peak
users and private analytics live inside the site's own systems
(Google Analytics, server logs) and cannot be observed from outside —
any tool that claims to show them for a site it does not manage is
inventing numbers.
"""
import json
import os
import time

PROFILE_FILE = "conan-profiles.json"

_LIST_FIELDS = [
    ("ips", "IP addresses"),
    ("open_ports", "open ports"),
    ("pages", "pages"),
    ("endpoints", "API endpoints"),
    ("cookies", "cookies"),
    ("headers_present", "security headers"),
    ("methods", "HTTP methods"),
    ("findings", "findings"),
]
_SCALAR_FIELDS = [
    ("server", "server"),
    ("tls_issuer", "TLS issuer"),
]


def build_profile(scan):
    """Build the learnable profile of a site from one scan dict."""
    hist = scan.get("history") or {}
    servers = scan.get("servers") or {}
    ports = scan.get("ports") or {}
    js = scan.get("js_api") or {}
    disc = scan.get("discovery") or {}
    headers = scan.get("headers") or {}
    cookies = scan.get("cookies") or {}
    methods = scan.get("methods") or {}
    redirects = scan.get("redirects") or {}
    tls = scan.get("tls") or {}

    rules = []
    server = servers.get("server_header")
    if server:
        rules.append("server: %s" % server)
    if tls.get("issuer"):
        rules.append("TLS issued by %s" % tls["issuer"])
    chain = redirects.get("chain") or []
    if chain:
        rules.append("redirects: %s" % " -> ".join(
            "%d" % c for c, _ in chain))
    raw_pages = disc.get("pages") or []
    pages = sorted(p.get("url", "") if isinstance(p, dict) else str(p)
                   for p in raw_pages)[:50]
    if pages:
        rules.append("public pages discovered: %d" % len(pages))
    endpoints = js.get("endpoints") or []
    if endpoints:
        rules.append("API endpoints in public JS: %d" % len(endpoints))
    open_ports = ports.get("open_ports") or []
    if open_ports:
        rules.append("open ports: %s" % ", ".join(
            str(p["port"]) for p in open_ports))
    cookie_list = cookies.get("cookies") or []
    if cookie_list:
        rules.append("cookies set: %s" % ", ".join(
            c.get("name", "?") for c in cookie_list))
    if methods.get("methods"):
        rules.append("HTTP methods allowed: %s" % ", ".join(
            methods["methods"]))
    if scan.get("score") is not None:
        rules.append("security score: %s%% (%s)" % (
            scan.get("score"), scan.get("grade")))

    return {
        "domain": hist.get("domain") or (scan.get("target") or ""),
        "target": scan.get("target"),
        "score": scan.get("score"),
        "grade": scan.get("grade"),
        "server": server,
        "tls_issuer": tls.get("issuer"),
        "ips": sorted(servers.get("ips") or []),
        "open_ports": sorted(p["port"] for p in open_ports),
        "pages": pages,
        "endpoints": sorted(endpoints)[:40],
        "cookies": sorted(c.get("name", "?") for c in cookie_list),
        "headers_present": sorted(
            c.get("name", "?") for c in (headers.get("checks") or [])
            if c.get("present")),
        "methods": sorted(methods.get("methods") or []),
        "findings": sorted(f.get("name", "?")
                           for f in (scan.get("findings") or [])),
        "rules": rules,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def compare_profiles(old, new):
    """Diff two profiles. Returns a list of plain-language changes."""
    changes = []
    for field, label in _SCALAR_FIELDS:
        if (old.get(field) or None) != (new.get(field) or None):
            changes.append({
                "field": field, "kind": "changed",
                "detail": "%s: %s -> %s" % (
                    label, old.get(field) or "UNKNOWN",
                    new.get(field) or "UNKNOWN")})
    for field, label in _LIST_FIELDS:
        before = set(old.get(field) or [])
        after = set(new.get(field) or [])
        for item in sorted(after - before):
            changes.append({"field": field, "kind": "added",
                            "detail": "%s: + %s" % (label, item)})
        for item in sorted(before - after):
            changes.append({"field": field, "kind": "removed",
                            "detail": "%s: - %s" % (label, item)})
    if (old.get("score") is not None and new.get("score") is not None
            and old["score"] != new["score"]):
        changes.append({"field": "score", "kind": "changed",
                        "detail": "score: %s%% -> %s%%" % (
                            old["score"], new["score"])})
    return changes


def _load_all(base_dir=None):
    path = os.path.join(base_dir or os.getcwd(), PROFILE_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_all(profiles, base_dir=None):
    path = os.path.join(base_dir or os.getcwd(), PROFILE_FILE)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profiles, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def learn(scan, base_dir=None):
    """Build the profile for this scan, compare with the previous one
    for the same domain, save it, and return (profile, changes)."""
    profile = build_profile(scan)
    domain = profile.get("domain") or profile.get("target") or "unknown"
    all_profiles = _load_all(base_dir)
    previous = all_profiles.get(domain)
    changes = compare_profiles(previous, profile) if previous else []
    all_profiles[domain] = profile
    _save_all(all_profiles, base_dir)
    return profile, changes
