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
from ..core.timeout import call_with_timeout
from ..intelligence import contacts as contacts_mod
from ..intelligence import history as history_mod
from ..intelligence import learning as learning_mod
from . import js_api as js_api_mod
from . import origin_ip as origin_mod
from . import paths as paths_mod
from . import ports as ports_mod
from . import website as website_mod
from ._http import get as http_get
from ._http import request as http_request

DEEP_TESTS = [
    "health", "dns", "dnssec", "tls", "headers", "cookies", "forms",
    "api", "discovery", "exposure", "phishing", "vulnerabilities",
    "core-audit", "domain-history", "certificate-history", "admin-contact",
    "country-servers", "deep-paths", "http-methods", "redirect-chain",
    "js-api-reverse", "real-ip", "published-contacts", "permissions",
    "certificates", "ports", "adaptive-probe", "learning",
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

    # Every phase runs with a hard deadline. A slow or hung phase
    # (a blackholed host, a dead WHOIS server, a crawler loop) is
    # recorded as timed out and the scan moves on — the investigation
    # can never freeze at 70% (or any %) again.
    timeouts = []

    def safe(name, fn, seconds, fallback):
        """Run one phase with a deadline; return fallback on timeout/error."""
        tick(name)
        try:
            out = call_with_timeout(fn, seconds)
        except Exception as exc:
            return fallback(str(exc))
        if isinstance(out, dict) and out.get("timed_out"):
            timeouts.append(name)
            return fallback(out.get("error", ""))
        return out

    def _core_fallback(err):
        return {"target": url, "score": 0, "grade": "?",
                "confidence": 0, "findings": [], "error": err}

    scan = safe("core-audit",
                lambda: website_mod.investigate_website(
                    url, scope=scope, max_pages=max_pages,
                    timeout=timeout, progress=tick),
                150, _core_fallback)
    scan["kind"] = "mega-scan"
    scan["tool"] = "CONAN FRAMEWORK v5.8"
    scan["deep_tests"] = list(DEEP_TESTS)
    scan["scope"] = {"kind": "authorized" if authorized else "passive",
                     "authorized": authorized}

    # Homepage HTML once, reused by the deep-recon modules.
    try:
        html = call_with_timeout(
            lambda: http_get(url, timeout=timeout)["body"], 20)
        if isinstance(html, dict) and html.get("timed_out"):
            timeouts.append("homepage")
            html = ""
    except Exception:
        html = ""
    discovery_pages = (scan.get("discovery") or {}).get("pages") or []

    # Deep identity: domain history, admin contact, country, servers.
    scan["history"] = safe(
        "domain-history",
        lambda: history_mod.domain_history(host, url, timeout=timeout),
        40, lambda e: {"domain": host, "error": e})

    # Published contacts from the site's own public pages.
    scan["contacts"] = safe(
        "published-contacts",
        lambda: contacts_mod.discover_contacts(
            url, html, discovery_pages, timeout=timeout),
        40, lambda e: {"emails": [], "contact_lines": [], "error": e})

    # Client-side reverse engineering: API endpoints from public JS.
    scan["js_api"] = safe(
        "js-api-reverse",
        lambda: js_api_mod.analyze_js(url, html, timeout=timeout),
        40, lambda e: {"endpoints": [], "error": e})

    # Real-IP investigation: resolved IPs, CDN signals, direct-IP check.
    scan["origin"] = safe(
        "real-ip",
        lambda: origin_mod.investigate_origin(host, url, timeout=timeout),
        40, lambda e: {"host": host, "ips": [], "error": e})

    # Permissions & certificates from observed headers + TLS.
    scan["permissions"] = safe(
        "permissions",
        lambda: _permissions_section(scan, timeout),
        25, lambda e: {"error": e})

    # Ports + Sunlight/Echo adaptive probe — authorized targets only.
    if authorized:
        scan["ports"] = safe(
            "ports",
            lambda: ports_mod.adaptive_probe(host, url, timeout=0.4),
            90, lambda e: {"error": e})
    else:
        tick("ports")
        scan["ports"] = {"note": "Port scanning needs authorization "
                                 "(your own site or written permission)."}

    # Deep paths (bounded probe) — authorized targets only.
    if authorized:
        scan["deep_paths"] = safe(
            "deep-paths",
            lambda: paths_mod.discover_paths(url, None, timeout, 0.15, 60),
            90, lambda e: {"error": e})
    else:
        tick("deep-paths")
        scan["deep_paths"] = []
        scan["deep_paths_note"] = (
            "Deep path probing needs authorization (your own site or written "
            "permission). Passive discovery results are in the report above.")

    # HTTP methods (read-only OPTIONS) + redirect chain.
    scan["methods"] = safe(
        "http-methods",
        lambda: history_mod.http_methods(url, timeout=timeout),
        25, lambda e: {"error": e})

    def _redirect_chain():
        r = http_request(url, method="GET", timeout=timeout, max_bytes=0)
        return {"chain": r.get("chain") or [],
                "final_url": r.get("final_url") or url,
                "status": r.get("status")}

    scan["redirects"] = safe(
        "redirect-chain", _redirect_chain,
        25, lambda e: {"chain": [], "final_url": url, "error": e})

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
    scan["phase_timeouts"] = timeouts

    # Site Brain: learn this site's rules and fundamentals from the
    # scan, and report what changed since the previous scan.
    tick("learning")
    try:
        profile, changes = learning_mod.learn(scan)
        scan["learned_profile"] = profile
        scan["learned_changes"] = changes
    except Exception as exc:
        scan["learned_profile"] = {"error": str(exc)}
        scan["learned_changes"] = []
    return scan
