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
from ..intelligence import contacts as contacts_mod
from ..intelligence import history as history_mod
from . import js_api as js_api_mod
from . import origin_ip as origin_mod
from . import paths as paths_mod
from . import website as website_mod
from ._http import get as http_get
from ._http import request as http_request

DEEP_TESTS = [
    "health", "dns", "dnssec", "tls", "headers", "cookies", "forms",
    "api", "discovery", "exposure", "phishing", "vulnerabilities",
    "core-audit", "domain-history", "certificate-history", "admin-contact",
    "country-servers", "deep-paths", "http-methods", "redirect-chain",
    "js-api-reverse", "real-ip", "published-contacts", "permissions",
    "certificates",
]


def _permissions_section(scan, timeout):
    """Permissions & certificates, from observed headers + TLS only."""
    out = {"permissions_policy": None, "cors": None, "csp": None,
           "tls_issuer": None, "tls_days_left": None, "tls_version": None,
           "ct_certificates": 0}
    try:
        headers = scan.get("headers") or {}
        for check in headers.get("checks") or []:
            name = (check.get("name") or "").lower()
            if "permissions-policy" in name:
                out["permissions_policy"] = check.get("value") or ""
            if "content-security-policy" in name:
                out["csp"] = check.get("value") or ""
        r = http_get(scan.get("target", ""), timeout=timeout)
        lower = {str(k).lower(): v for k, v in dict(r["headers"]).items()}
        out["cors"] = lower.get("access-control-allow-origin")
        if out["permissions_policy"] is None:
            out["permissions_policy"] = lower.get("permissions-policy", "")
        if out["csp"] is None:
            out["csp"] = lower.get("content-security-policy", "")
    except Exception:
        pass
    tls = scan.get("tls") or {}
    out["tls_issuer"] = tls.get("issuer")
    out["tls_days_left"] = tls.get("days_left")
    out["tls_version"] = tls.get("version")
    hist = scan.get("history") or {}
    out["ct_certificates"] = hist.get("ct_certificates") or 0
    return out


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
    scan["tool"] = "CONAN FRAMEWORK v5.6"
    scan["deep_tests"] = list(DEEP_TESTS)
    scan["scope"] = {"kind": "authorized" if authorized else "passive",
                     "authorized": authorized}

    # Homepage HTML once, reused by the deep-recon modules.
    try:
        html = http_get(url, timeout=timeout)["body"]
    except Exception:
        html = ""
    discovery_pages = (scan.get("discovery") or {}).get("pages") or []

    # Deep identity: domain history, admin contact, country, servers.
    tick("domain-history")
    try:
        scan["history"] = history_mod.domain_history(host, url, timeout=timeout)
    except Exception as exc:
        scan["history"] = {"domain": host, "error": str(exc)}

    # Published contacts from the site's own public pages.
    tick("published-contacts")
    try:
        scan["contacts"] = contacts_mod.discover_contacts(
            url, html, discovery_pages, timeout=timeout)
    except Exception as exc:
        scan["contacts"] = {"emails": [], "contact_lines": [], "error": str(exc)}

    # Client-side reverse engineering: API endpoints from public JS.
    tick("js-api-reverse")
    try:
        scan["js_api"] = js_api_mod.analyze_js(url, html, timeout=timeout)
    except Exception as exc:
        scan["js_api"] = {"endpoints": [], "error": str(exc)}

    # Real-IP investigation: resolved IPs, CDN signals, direct-IP check.
    tick("real-ip")
    try:
        scan["origin"] = origin_mod.investigate_origin(host, url, timeout=timeout)
    except Exception as exc:
        scan["origin"] = {"host": host, "ips": [], "error": str(exc)}

    # Permissions & certificates from observed headers + TLS.
    tick("permissions")
    try:
        scan["permissions"] = _permissions_section(scan, timeout)
    except Exception as exc:
        scan["permissions"] = {"error": str(exc)}

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
