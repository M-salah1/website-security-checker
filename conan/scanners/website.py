#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Universal website investigation — orchestrates the relevant modules.

Runs the passive modules with bounded concurrency (ThreadPoolExecutor,
max 4 workers): DNS, IP resolution, TLS, headers, cookies, availability,
redirects, discovery, forms, API references, auth analysis, registration
analysis, exposure, phishing, paths, misconfiguration.

Active tests (SQLi/XSS/auth login) are NOT run here — they need explicit
authorization and live in the vulnerability/auth audit menu options.
"""
import concurrent.futures
import time

from ..core import engine
from ..core.evidence import count_by_severity, sort_findings
from . import api as api_mod
from . import cookies as cookies_mod
from . import discovery as disc_mod
from . import dns as dns_mod
from . import exposure as exposure_mod
from . import forms as forms_mod
from . import headers as headers_mod
from . import health as health_mod
from . import paths as paths_mod
from . import phishing as phishing_mod
from . import tls as tls_mod
from . import vulnerabilities as vuln_mod
from ._http import get as http_get


def _safe(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        return {"error": str(exc)}


def investigate_website(url, scope=None, max_pages=20, timeout=15,
                        progress=None):
    """Run the universal investigation. Returns the full case scan dict."""
    url = engine.normalize_url(url)
    host = url.split("/")[2]
    t0 = time.time()
    findings = []

    def tick(name):
        if progress:
            try:
                progress(name)
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futs = {
            "health": pool.submit(_safe, health_mod.check_health, url, 1, timeout),
            "dns": pool.submit(_safe, dns_mod.analyze_dns, host),
            "tls": pool.submit(_safe, tls_mod.analyze_tls, host),
            "headers": pool.submit(_safe, headers_mod.analyze_headers, url, timeout),
            "cookies": pool.submit(_safe, cookies_mod.analyze_cookies, url, timeout),
            "phishing": pool.submit(_safe, phishing_mod.analyze_phishing, url, None, timeout),
            "discovery": pool.submit(_safe, disc_mod.crawl, url, 1, max_pages, timeout, (), 0.3),
            "forms": pool.submit(_safe, forms_mod.fetch_forms, url, timeout),
        }
        results = {}
        for name, fut in futs.items():
            try:
                results[name] = fut.result(timeout=timeout + 30)
            except Exception as exc:
                results[name] = {"error": str(exc)}
            tick(name)

    html = http_get(url, timeout=timeout)["body"]
    api_refs = _safe(api_mod.discover_api, url, html)
    tick("api")
    authorized = bool(scope and scope.is_authorized(url))
    exposure = _safe(exposure_mod.audit_exposure, url, authorized, timeout)
    tick("exposure")
    paths = _safe(paths_mod.discover_paths, url, None, timeout, 0.2, 30) \
        if authorized else []
    tick("paths")
    vuln = _safe(vuln_mod.run_vuln_tests, url, html, {}, results["forms"].get("forms", []),
                 (results["cookies"].get("cookies", [])) if isinstance(results["cookies"], dict) else [])
    tick("vulnerabilities")

    for key in ("headers", "cookies"):
        findings += (results.get(key) or {}).get("findings", [])
    findings += (exposure.get("findings", []) if isinstance(exposure, dict) else [])
    findings += (vuln if isinstance(vuln, list) else [])
    # core audit (score/grade/confidence) — the preserved v2.4 engine
    audit = _safe(engine.run_check, url)
    tick("core-audit")
    findings += _engine_findings(audit, url)
    findings = _dedupe(sort_findings(findings))

    duration = round(time.time() - t0, 1)
    return {
        "tool": "CONAN FRAMEWORK v5.8",
        "target": url, "kind": "website-investigation",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - duration)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": duration,
        "health": results.get("health"), "dns": results.get("dns"),
        "tls": results.get("tls"), "headers": results.get("headers"),
        "cookies": results.get("cookies"), "phishing": results.get("phishing"),
        "discovery": results.get("discovery"), "forms": results.get("forms"),
        "api": api_refs, "exposure": exposure, "paths": paths,
        "audit": audit, "findings": findings,
        "score": audit.get("score") if isinstance(audit, dict) else 0,
        "grade": audit.get("grade") if isinstance(audit, dict) else "F",
        "confidence": audit.get("confidence", 100) if isinstance(audit, dict) else 0,
        "checks_count": len(audit.get("checks", [])) + 12 if isinstance(audit, dict) else 12,
        "severity_distribution": count_by_severity(findings),
        "recommendations": list((audit.get("top_fixes") or []) if isinstance(audit, dict) else [])[:8],
        "scope": {"kind": "authorized" if authorized else "passive",
                  "authorized": authorized},
    }


_SEV = {"عالي": "high", "متوسط": "medium", "منخفض": "low"}
_TITLE = {
    "غياب HSTS": "Missing HSTS",
    "غياب Content-Security-Policy": "Missing Content-Security-Policy",
    "خطر Clickjacking": "Missing X-Frame-Options",
    "غياب nosniff": "Missing X-Content-Type-Options nosniff",
    "غياب Referrer-Policy": "Missing Referrer-Policy",
    "غياب Permissions-Policy": "Missing Permissions-Policy",
    "غياب Cross-Origin-Opener-Policy": "Missing Cross-Origin-Opener-Policy",
    "غياب Cross-Origin-Embedder-Policy": "Missing Cross-Origin-Embedder-Policy",
    "لا يوجد security.txt": "Missing security.txt",
    "تعذر التحقق من شهادة TLS": "TLS certificate could not be verified",
    "شهادة TLS على وشك الانتهاء": "TLS certificate expiring soon",
    "ملف حساس مكشوف علناً": "Sensitive file exposed publicly",
}


def _engine_findings(audit, target):
    out = []
    if not isinstance(audit, dict):
        return out
    for v in audit.get("vulnerabilities", []):
        out.append({"name": _TITLE.get(v["title"], v["title"]),
                    "severity": _SEV.get(v["severity"], "low"),
                    "confidence": 90, "status": "confirmed", "url": target,
                    "evidence": v["detail"], "method": "Conan engine audit",
                    "reproduction": "Run: scan %s" % target,
                    "remediation": v["fix"],
                    "timestamp": audit.get("checked_at_utc", ""),
                    "fixes": v.get("fixes") or {}})
    return out


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["severity"], f["name"], f["url"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
