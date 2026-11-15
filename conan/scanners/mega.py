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
from ..intelligence import ai_brain as ai_brain_mod
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
    "certificates", "ports", "adaptive-probe", "learning", "ai-brain",
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


PHASE_DEADLINES = {
    "core-audit": 120, "domain-history": 40, "published-contacts": 40,
    "js-api-reverse": 40, "real-ip": 40, "permissions": 25,
    "ports": 90, "deep-paths": 90, "http-methods": 25, "redirect-chain": 25,
    "learning": 10, "ai-brain": 10,
}

# Sub-phases that belong to a parent phase: when the parent finishes,
# these are ticked too, so a complete run reaches 29/29 real phases.
SUB_TICKS = {
    "domain-history": ["certificate-history", "admin-contact",
                       "country-servers"],
    "permissions": ["certificates"],
    "ports": ["adaptive-probe"],
}

# Core modules the score depends on. Coverage is the share of these
# that completed with real results.
CORE_MODULES = ["health", "dns", "tls", "headers", "cookies", "forms",
                "api", "discovery", "exposure", "core-audit"]

PARTIAL_PREFIX = "conan-partial-"
PARTIAL_MAX_AGE_S = 3600  # resume only a scan from the last hour


def _partial_path(url):
    import os
    import re
    host = url.split("/")[2] if "://" in url else url
    safe_name = re.sub(r"[^a-z0-9.-]", "_", host.lower())
    return os.path.join(os.getcwd(), "%s%s.json" % (PARTIAL_PREFIX, safe_name))


def _save_partial(url, scan, completed):
    """Incremental write: an interrupted scan keeps what it finished."""
    import json
    try:
        with open(_partial_path(url), "w", encoding="utf-8") as f:
            json.dump({"target": url, "saved_at": time.time(),
                       "completed": sorted(completed), "scan": scan},
                      f, ensure_ascii=False)
    except Exception:
        pass


def _load_partial(url):
    """A fresh partial scan for the same target, or None."""
    import json
    import os
    try:
        path = _partial_path(url)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("target") != url:
            return None
        if time.time() - float(data.get("saved_at") or 0) > PARTIAL_MAX_AGE_S:
            return None
        return data
    except Exception:
        return None


def _run_parallel(jobs, global_seconds):
    """Run (name, fn) jobs concurrently; collect what finishes inside
    the global deadline. Jobs still running after the deadline are
    abandoned (daemon threads) — never waited on. Returns
    {name: ("ok", value) | ("timeout", None)}."""
    import concurrent.futures

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs) or 1)
    try:
        futs = {pool.submit(fn): name for name, fn in jobs}
        done, _ = concurrent.futures.wait(
            futs, timeout=global_seconds,
            return_when=concurrent.futures.ALL_COMPLETED)
        out = {}
        for fut, name in futs.items():
            if fut in done:
                try:
                    out[name] = ("ok", fut.result())
                except Exception as exc:
                    out[name] = ("ok", exc)
            else:
                out[name] = ("timeout", None)
        return out
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def mega_scan(url, scope=None, settings=None, timeout=15, progress=None,
              resume=True):
    """Run the full mega scan. Returns the detailed scan dict.

    CONAN 2.0 engine:
    - independent phases run in parallel, under one global budget
      (default 300s) — total time is the slowest phase, never the sum
      of every phase's deadline;
    - every phase has a status (completed / timeout / error), a
      duration and a retry count, stored in scan["module_status"]
      and in the SQLite module_runs table;
    - a fast-failing phase is retried once with backoff;
    - partial results are saved after every phase, and a fresh
      partial scan for the same target is resumed, not restarted;
    - the score is INCOMPLETE (never 0%) when the core audit failed
      or coverage is below half.
    """
    url = engine.normalize_url(url)
    host = url.split("/")[2]
    settings = settings or {}
    max_pages = int(settings.get("max_pages", 20))
    budget = int(settings.get("scan_budget_s", 300))
    deadlines = dict(PHASE_DEADLINES)
    deadlines.update(settings.get("phase_deadlines") or {})
    t0 = time.time()

    import threading
    status_lock = threading.Lock()
    module_status = {}
    timeouts = []
    completed = set()
    resumed = []

    def tick(name):
        if progress:
            try:
                progress(name)
            except Exception:
                pass

    def record(name, status, duration, retries, error):
        with status_lock:
            old = module_status.get(name) or {}
            # A phase abandoned by the global budget stays "timeout"
            # even if its daemon thread finishes later — its result
            # was not used in this scan.
            if old.get("status") == "timeout" and status == "completed":
                return
            module_status[name] = {
                "status": status, "duration_s": round(duration, 1),
                "retries": retries, "error": (error or "")[:300]}

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

    # Resume a fresh partial scan for the same target, if one exists.
    scan = {}
    if resume:
        partial = _load_partial(url)
        if partial and isinstance(partial.get("scan"), dict):
            scan = partial["scan"]
            completed = set(partial.get("completed") or [])
            resumed = sorted(completed)
            for name in completed:
                module_status[name] = {"status": "completed",
                                       "duration_s": 0, "retries": 0,
                                       "error": "", "resumed": True}
                tick(name)
                for sub in SUB_TICKS.get(name, []):
                    tick(sub)

    def _core_fallback(err):
        return {"target": url, "score": None, "grade": "INCOMPLETE",
                "confidence": 0, "findings": [], "error": err}

    def safe(name, fn, seconds, fallback, retries=1):
        """Run one phase with a deadline; retry once if it fails FAST.

        A timeout is never retried (it would only double the wait).
        Returns the phase result; records its status, duration and
        retry count; ticks the phase and its sub-phases.
        """
        if name in completed:
            return scan.get(_KEY_FOR.get(name, name))
        tick(name)
        attempts = 0
        started = time.time()
        key = _KEY_FOR.get(name)

        def _store(result):
            # Store the phase result in the scan BEFORE the partial
            # save, so a resumed run never sees a phase marked
            # completed with its result missing.
            if key and key != "core":
                scan[key] = result

        while True:
            attempts += 1
            try:
                out = call_with_timeout(fn, seconds)
            except Exception as exc:
                record(name, "error", time.time() - started, attempts - 1,
                       str(exc))
                for sub in SUB_TICKS.get(name, []):
                    tick(sub)
                completed.add(name)
                _store(fallback(str(exc)))
                _save_partial(url, scan, completed)
                return fallback(str(exc))
            if isinstance(out, dict) and out.get("timed_out"):
                timeouts.append(name)
                record(name, "timeout", time.time() - started, attempts - 1,
                       out.get("error", ""))
                _store(fallback(out.get("error", "")))
                _save_partial(url, scan, completed)
                return fallback(out.get("error", ""))
            err = out.get("error") if isinstance(out, dict) else None
            if err and attempts <= retries and \
                    time.time() - started < 10:
                # Fast failure (refused connection, DNS error, ...) —
                # retry once with backoff before giving up.
                time.sleep(2 * attempts)
                continue
            status = "error" if err else "completed"
            record(name, status, time.time() - started, attempts - 1, err)
            for sub in SUB_TICKS.get(name, []):
                tick(sub)
            completed.add(name)
            _store(out)
            _save_partial(url, scan, completed)
            return out

    # --- Core audit (the base scan everything else builds on). ---
    prev_scan = scan
    if "core-audit" not in completed:
        scan = safe("core-audit",
                    lambda: website_mod.investigate_website(
                        url, scope=scope, max_pages=max_pages,
                        timeout=timeout, progress=tick),
                    deadlines["core-audit"], _core_fallback)
        scan["kind"] = "mega-scan"
        scan["tool"] = "CONAN FRAMEWORK v7.0"
        scan["deep_tests"] = list(DEEP_TESTS)
        scan["scope"] = {"kind": "authorized" if authorized else "passive",
                         "authorized": authorized}
        # Keep results of phases completed in the resumed partial run:
        # the new core scan replaces the dict, it must not erase them.
        for name in completed:
            key = _KEY_FOR.get(name)
            if key and key != "core" and key in prev_scan:
                scan[key] = prev_scan[key]
        _save_partial(url, scan, completed)
    else:
        scan.setdefault("kind", "mega-scan")
        scan.setdefault("deep_tests", list(DEEP_TESTS))

    def budget_left():
        return budget - (time.time() - t0)

    # --- Homepage HTML once, reused by the deep-recon modules. ---
    html = ""
    need_html = any(n not in completed for n in
                    ("published-contacts", "js-api-reverse"))
    if need_html and budget_left() > 5:
        try:
            html = call_with_timeout(
                lambda: http_get(url, timeout=timeout)["body"], 20)
            if isinstance(html, dict) and html.get("timed_out"):
                timeouts.append("homepage")
                html = ""
        except Exception:
            html = ""
    discovery_pages = (scan.get("discovery") or {}).get("pages") or []

    # --- Parallel batch 1: independent intelligence modules. ---
    batch1 = [
        ("domain-history",
         lambda: history_mod.domain_history(host, url, timeout=timeout),
         lambda e: {"domain": host, "error": e}, "history"),
        ("published-contacts",
         lambda: contacts_mod.discover_contacts(
             url, html, discovery_pages, timeout=timeout),
         lambda e: {"emails": [], "contact_lines": [], "error": e},
         "contacts"),
        ("js-api-reverse",
         lambda: js_api_mod.analyze_js(url, html, timeout=timeout),
         lambda e: {"endpoints": [], "error": e}, "js_api"),
        ("real-ip",
         lambda: origin_mod.investigate_origin(host, url, timeout=timeout),
         lambda e: {"host": host, "ips": [], "error": e}, "origin"),
        ("permissions",
         lambda: _permissions_section(scan, timeout),
         lambda e: {"error": e}, "permissions"),
        ("http-methods",
         lambda: history_mod.http_methods(url, timeout=timeout),
         lambda e: {"error": e}, "methods"),
        ("redirect-chain",
         lambda: _redirect_chain(url, timeout),
         lambda e: {"chain": [], "final_url": url, "error": e},
         "redirects"),
    ]
    key_of = {n: k for n, _f, _b, k in batch1}
    fb_of = {n: b for n, _f, b, _k in batch1}
    jobs = [(n, (lambda fn, fb, nm=n: lambda: safe(nm, fn, deadlines[nm], fb))(
        fn, fb)) for n, fn, fb, _k in batch1 if n not in completed]
    if jobs and budget_left() > 5:
        results = _run_parallel(jobs, min(budget_left(), 90))
        for name, (state, value) in results.items():
            if state == "timeout":
                timeouts.append(name)
                record(name, "timeout", deadlines[name], 0,
                       "global budget reached")
                tick(name)
                scan[key_of[name]] = fb_of[name]("global budget reached")
            else:
                scan[key_of[name]] = value
    for name, fn, fb, key in batch1:
        if name not in module_status:
            # Not run in the batch (no budget left, or skipped): run
            # it now if any budget remains, else mark it timed out.
            if budget_left() <= 5:
                timeouts.append(name)
                record(name, "timeout", 0, 0, "global budget reached")
                tick(name)
                scan[key] = fb("global budget reached")
            else:
                scan[key] = safe(name, fn, deadlines[name], fb)
        elif key not in scan:
            scan[key] = fb(module_status[name].get("error", ""))

    # --- Parallel batch 2: authorized active probes. ---
    # Resolve the host once to an IP: the port probe connects to the
    # IP directly, so no per-port DNS lookup can stall it.
    ips = (scan.get("origin") or {}).get("ips") or \
        (scan.get("dns") or {}).get("ips") or []
    target_ip = ips[0] if ips else None
    batch2 = []
    if authorized:
        batch2.append(("ports",
                       lambda: ports_mod.adaptive_probe(
                           host, url, timeout=0.4, ip=target_ip),
                       lambda e: {"error": e}, "ports"))
        batch2.append(("deep-paths",
                       lambda: paths_mod.discover_paths(
                           url, None, min(timeout, 8), 0.15, 60),
                       lambda e: {"error": e}, "deep_paths"))
    jobs2 = [(n, (lambda fn, fb, nm=n: lambda: safe(nm, fn, deadlines[nm], fb))(
        fn, fb)) for n, fn, fb, _k in batch2 if n not in completed]
    key2 = {n: k for n, _f, _b, k in batch2}
    fb2 = {n: b for n, _f, b, _k in batch2}
    if jobs2 and budget_left() > 5:
        results2 = _run_parallel(jobs2, min(budget_left(), 100))
        for name, (state, value) in results2.items():
            if state == "timeout":
                timeouts.append(name)
                record(name, "timeout", deadlines[name], 0,
                       "global budget reached")
                tick(name)
                scan[key2[name]] = fb2[name]("global budget reached")
            else:
                scan[key2[name]] = value
    for name, fn, fb, key in batch2:
        if name not in module_status:
            if budget_left() <= 5:
                timeouts.append(name)
                record(name, "timeout", 0, 0, "global budget reached")
                tick(name)
                scan[key] = fb("global budget reached")
            else:
                scan[key] = safe(name, fn, deadlines[name], fb)
        elif key not in scan:
            scan[key] = fb(module_status[name].get("error", ""))
    if not authorized:
        for name, key in (("ports", "ports"), ("deep-paths", "deep_paths")):
            tick(name)
            record(name, "not_tested", 0, 0,
                   "needs authorization (own site or written permission)")
            for sub in SUB_TICKS.get(name, []):
                tick(sub)
        scan["ports"] = {"note": "Port scanning needs authorization "
                                 "(your own site or written permission)."}
        scan["deep_paths"] = []
        scan["deep_paths_note"] = (
            "Deep path probing needs authorization (your own site or written "
            "permission). Passive discovery results are in the report above.")

    # Servers summary, built only from observed public data.
    hist = scan.get("history") or {}
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
    scan["module_status"] = module_status
    if resumed:
        scan["resumed_from"] = resumed

    # --- Accuracy: coverage and the INCOMPLETE score. ---
    covered = []
    missing = []
    for mod in CORE_MODULES:
        if mod == "core-audit":
            ok = scan.get("score") is not None
        else:
            part = scan.get(mod)
            ok = isinstance(part, dict) and not part.get("error") \
                and part is not None
        (covered if ok else missing).append(mod)
    coverage_pct = int(100 * len(covered) / len(CORE_MODULES))
    scan["coverage"] = {"completed": len(covered), "total": len(CORE_MODULES),
                        "percent": coverage_pct, "missing": missing}
    if scan.get("score") is None or coverage_pct < 50:
        # Never present a failed measurement as 0%: with half the
        # evidence missing, the honest result is INCOMPLETE.
        scan["score"] = None
        scan["grade"] = "INCOMPLETE"
        scan["confidence"] = 0
    _save_partial(url, scan, completed)

    # Site Brain: learn this site's rules and fundamentals from the
    # scan, and report what changed since the previous scan.
    tick("learning")
    try:
        profile, changes = learning_mod.learn(scan)
        scan["learned_profile"] = profile
        scan["learned_changes"] = changes
        record("learning", "completed", 0, 0, "")
    except Exception as exc:
        scan["learned_profile"] = {"error": str(exc)}
        scan["learned_changes"] = []
        record("learning", "error", 0, 0, str(exc))

    # AI Brain: reason over the whole scan like an ethical hacker —
    # attack chains, priorities, verdict, next tests.
    tick("ai-brain")
    try:
        lang = (settings.get("language") or "ar") if settings else "ar"
        scan["ai_brain"] = ai_brain_mod.analyze(scan, lang)
        record("ai-brain", "completed", 0, 0, "")
    except Exception as exc:
        scan["ai_brain"] = {"error": str(exc)}
        record("ai-brain", "error", 0, 0, str(exc))
    scan["module_status"] = module_status

    # A complete scan removes its partial file; an interrupted one
    # keeps it, so the next run resumes instead of restarting.
    try:
        import os
        _save_partial(url, scan, completed)
        parents = ["core-audit", "domain-history", "published-contacts",
                   "js-api-reverse", "real-ip", "permissions", "ports",
                   "deep-paths", "http-methods", "redirect-chain",
                   "learning", "ai-brain"]
        if all(n in module_status for n in parents):
            os.remove(_partial_path(url))
    except Exception:
        pass
    return scan


_KEY_FOR = {
    "core-audit": "core", "domain-history": "history",
    "published-contacts": "contacts", "js-api-reverse": "js_api",
    "real-ip": "origin", "permissions": "permissions",
    "ports": "ports", "deep-paths": "deep_paths",
    "http-methods": "methods", "redirect-chain": "redirects",
}


def _redirect_chain(url, timeout):
    r = http_request(url, method="GET", timeout=timeout, max_bytes=0)
    out = {"chain": r.get("chain") or [],
           "final_url": r.get("final_url") or url,
           "status": r.get("status")}
    if r.get("error") or r.get("status") is None:
        # A chain that never got a response is an error, not a
        # completed measurement.
        out["error"] = r.get("error") or "no response"
    return out
