#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hidden paths & file discovery — safe, bounded, authorized only.

Uses a configurable wordlist of common public paths on authorized domains.
Every path is categorized by its real HTTP status:

PUBLIC / AUTHENTICATION REQUIRED / FORBIDDEN / NOT FOUND / REDIRECT /
SERVER ERROR / TIMEOUT.

Requests run in parallel (bounded workers = built-in rate limiting).
The old sequential loop made total time the sum of every request timeout
(60 slow paths x 15s = 15 minutes) — that is what froze scans.

No access-restriction bypass, no protected user data.
"""
import concurrent.futures
import time

from ._http import request

DEFAULT_WORDLIST = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/admin", "/login", "/register", "/signup", "/dashboard", "/api",
    "/api/docs", "/swagger.json", "/openapi.json", "/.git/HEAD", "/.env",
    "/wp-admin", "/wp-login.php", "/wp-config.php", "/config.php",
    "/backup.zip", "/db.sql", "/.env.bak", "/sitemap_index.xml",
    "/about", "/contact", "/privacy", "/terms", "/feed", "/rss.xml",
    "/static", "/assets", "/uploads", "/images", "/css", "/js",
    "/health", "/status", "/metrics", "/.well-known/robots.txt",
]

CATEGORIES = {
    200: "PUBLIC", 301: "REDIRECT", 302: "REDIRECT", 307: "REDIRECT",
    308: "REDIRECT", 401: "AUTHENTICATION REQUIRED", 403: "FORBIDDEN",
    404: "NOT FOUND", 429: "REDIRECT", 500: "SERVER ERROR", 502: "SERVER ERROR",
    503: "SERVER ERROR",
}


def categorize(status, error=None):
    if status is None:
        return "TIMEOUT" if error and "timed out" in str(error).lower() else "NOT FOUND"
    return CATEGORIES.get(status, "NOT FOUND" if status == 404 else "OTHER-%s" % status)


def _probe_one(base, path, timeout):
    url = base + path
    r = request(url, method="GET", timeout=timeout, max_bytes=5000)
    return {"path": path, "url": url, "status": r["status"],
            "category": categorize(r["status"], r["error"]),
            "content_type": (r["headers"].get("Content-Type", "") or "")[:60],
            "ms": r["elapsed_ms"], "error": r["error"]}


def discover_paths(base_url, wordlist=None, timeout=8, delay=0.2, max_paths=60,
                   on_result=None):
    """Probe a bounded path list, in parallel. Returns one entry per path.

    `delay` is kept for API compatibility; the rate limit is the worker
    count (8 concurrent requests), not a sleep between requests.
    """
    base = base_url.rstrip("/")
    paths = (wordlist or DEFAULT_WORDLIST)[:max_paths]
    results = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    try:
        futs = {pool.submit(_probe_one, base, p, timeout): p for p in paths}
        for fut in concurrent.futures.as_completed(futs):
            try:
                entry = fut.result(timeout=timeout + 5)
            except Exception as exc:
                entry = {"path": futs[fut], "url": base + futs[fut],
                         "status": None, "category": "TIMEOUT",
                         "content_type": "", "ms": 0, "error": str(exc)}
            results.append(entry)
            if on_result:
                try:
                    on_result(entry)
                except Exception:
                    pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    # Keep the wordlist order in the result.
    order = {p: i for i, p in enumerate(paths)}
    return sorted(results, key=lambda e: order.get(e["path"], 999))
