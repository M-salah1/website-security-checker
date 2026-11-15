#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MEGA SCAN — one URL in, everything together, one detailed report.

Runs every Conan module in a single investigation: the universal website
audit (DNS, TLS, headers, cookies, health, discovery, forms, API,
exposure, phishing, vulnerability indicators, core score), the deep
identity profile (domain history, admin contact, country, servers),
bounded path discovery, HTTP methods and the redirect chain.

Authorization: passive modules always run. The deep path probe and the
active vulnerability indicators run only on the user's own site or a
site with written authorization — the mega scan asks once at the start
and continues passively if the user declines. Nothing here exploits,
logs in, brute-forces or modifies the target.
"""
import time

from ..core import engine
from ..core.scope import ScopeError
from ..intelligence import history as history_mod
from . import paths as paths_mod
from . import website as website_mod
from ._http import request as http_request

DEEP_TESTS = [
    "health", "dns", "dnssec", "tls", "headers", "cookies", "forms",
    "api", "discovery", "exposure", "phishing", "vulnerabilities",
    "core-audit", "domain-history", "certificate-history", "admin-contact",
    "country-servers", "deep-paths", "http-methods", "redirect-chain",
]


def mega_scan(url, scope=None, settings=None, timeout=15, progress=None):
    """Run the full mega scan. Returns the detailed scan dict."""
    url = engine.normalize_url(url)
    host = url.split("/")[2]
    settings = settings or {}
    max_pages = int(settings.get("max_pages", 20))
    t0 = time.time()

    def tick(name):
        if progress:
            try:
                progress(name)
            except Exception:
                pass

    # One authorization question for the whole deep run.
    authorized = False
    if scope is not None:
        try:
            authorized = bool(scope.is_authorized(url))
            if not authorized:
                authorized = bool(scope.check_or_ask(url, "mega scan"))
        except ScopeError:
            authorized = False
        except Exception:
            authorized = False

    scan = website_mod.investigate_website(
        url, scope=scope, max_pages=max_pages, timeout=timeout, progress=tick)
    scan["kind"] = "mega-scan"
    scan["tool"] = "CONAN FRAMEWORK v5.4"
    scan["deep_tests"] = list(DEEP_TESTS)
    scan["scope"] = {"kind": "authorized" if authorized else "passive",
                     "authorized": authorized}

    # Deep identity: domain history, admin contact, country, servers.
    tick("domain-history")
    try:
        scan["history"] = history_mod.domain_history(host, url, timeout=timeout)
    except Exception as exc:
        scan["history"] = {"domain": host, "error": str(exc)}

    # Deep paths (bounded probe) — authorized targets only.
    tick("deep-paths")
    if authorized:
        try:
            scan["deep_paths"] = paths_mod.discover_paths(
                url, None, timeout, 0.15, 60)
        except Exception as exc:
            scan["deep_paths"] = {"error": str(exc)}
    else:
        scan["deep_paths"] = []
        scan["deep_paths_note"] = (
            "Deep path probing needs authorization (your own site or written "
            "permission). Passive discovery results are in the report above.")

    # HTTP methods (read-only OPTIONS) + redirect chain.
    tick("http-methods")
    try:
        scan["methods"] = history_mod.http_methods(url, timeout=timeout)
    except Exception as exc:
        scan["methods"] = {"error": str(exc)}
    tick("redirect-chain")
    try:
        r = http_request(url, method="GET", timeout=timeout, max_bytes=0)
        scan["redirects"] = {"chain": r.get("chain") or [],
                             "final_url": r.get("final_url") or url,
                             "status": r.get("status")}
    except Exception as exc:
        scan["redirects"] = {"chain": [], "final_url": url, "error": str(exc)}

    # Servers summary, built only from observed public data.
    hist = scan.get("history") or {}
    headers = scan.get("headers") or {}
    scan["servers"] = {
        "server_header": hist.get("server_header"),
        "ips": hist.get("ips") or (scan.get("dns") or {}).get("ips") or [],
        "nameservers": hist.get("nameservers") or [],
        "mx": hist.get("mx") or [],
        "tls_issuer": hist.get("tls_issuer"),
        "hosting_org": hist.get("hosting_org"),
        "asn": hist.get("asn"),
        "country": hist.get("country"),
    }
    scan["duration_s"] = round(time.time() - t0, 1)
    scan["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return scan
