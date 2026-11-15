#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hidden paths & file discovery — safe, bounded, authorized only.

Uses a configurable wordlist of common public paths on authorized domains.
Every path is categorized by its real HTTP status:

PUBLIC / AUTHENTICATION REQUIRED / FORBIDDEN / NOT FOUND / REDIRECT /
SERVER ERROR / TIMEOUT.

No access-restriction bypass, no protected user data.
"""
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


def discover_paths(base_url, wordlist=None, timeout=8, delay=0.2, max_paths=60,
                   on_result=None):
    """Probe a bounded path list. Returns one entry per path."""
    base = base_url.rstrip("/")
    results = []
    for path in (wordlist or DEFAULT_WORDLIST)[:max_paths]:
        url = base + path
        r = request(url, method="GET", timeout=timeout, max_bytes=5000)
        entry = {"path": path, "url": url, "status": r["status"],
                 "category": categorize(r["status"], r["error"]),
                 "content_type": (r["headers"].get("Content-Type", "") or "")[:60],
                 "ms": r["elapsed_ms"], "error": r["error"]}
        results.append(entry)
        if on_result:
            try:
                on_result(entry)
            except Exception:
                pass
        if delay:
            time.sleep(delay)
    return results
