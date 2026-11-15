#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Website discovery engine — real crawler (same-origin, bounded).

Discovers public internal links, pages, robots.txt, sitemap.xml, JavaScript
resources, API endpoint references, forms and redirects. Never attempts to
bypass authentication or access controls. Every path is classified by its
real HTTP status.
"""
import re
import time
import urllib.parse

from ..core import engine
from ._http import get, request

_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
_SCRIPT_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)

STATUS_CLASS = {
    200: "accessible", 301: "redirect", 302: "redirect", 307: "redirect",
    308: "redirect", 401: "auth-required", 403: "forbidden", 404: "not-found",
    429: "rate-limited", 500: "server-error", 503: "unavailable",
}


def classify_status(status, error=None):
    if status is None:
        return "timeout" if error and "timed out" in str(error).lower() else "no-response"
    return STATUS_CLASS.get(status, "other-%s" % status)


def _same_origin(base, url):
    b, u = urllib.parse.urlparse(base), urllib.parse.urlparse(url)
    return (u.netloc or b.netloc) == b.netloc and u.scheme in ("http", "https", "")


def crawl(start_url, max_depth=2, max_pages=50, timeout=15, excluded=(),
          delay=0.5, on_page=None):
    """Breadth-first crawl. Returns a site map + discovered assets."""
    start_url = engine.normalize_url(start_url)
    seen = {}
    queue = [(start_url, 0, "seed")]
    pages, scripts, api_refs = [], [], []
    t_end = time.time() + 600  # hard safety bound: 10 minutes
    while queue and len(pages) < max_pages and time.time() < t_end:
        url, depth, source = queue.pop(0)
        if url in seen:
            continue
        if any(url.rstrip("/").endswith(p) for p in (excluded or ())):
            continue
        seen[url] = True
        r = get(url, timeout=timeout)
        entry = {"url": url, "status": r["status"],
                 "classification": classify_status(r["status"], r["error"]),
                 "content_type": (r["headers"].get("Content-Type", "") or "")[:80],
                 "response_ms": r["elapsed_ms"], "source": source,
                 "final_url": r["final_url"]}
        pages.append(entry)
        if on_page:
            try:
                on_page(entry)
            except Exception:
                pass
        if r["status"] == 200 and "text/html" in entry["content_type"]:
            for link in _LINK_RE.findall(r["body"]):
                absu = urllib.parse.urljoin(url, link.split("#")[0])
                if _same_origin(start_url, absu) and absu not in seen \
                        and depth < max_depth:
                    queue.append((absu, depth + 1, "link:%s" % url))
            for src in _SCRIPT_RE.findall(r["body"]):
                absu = urllib.parse.urljoin(url, src)
                if absu not in scripts:
                    scripts.append(absu)
        if delay:
            time.sleep(delay)
    # robots.txt / sitemap.xml
    parsed = urllib.parse.urlparse(start_url)
    base = "%s://%s" % (parsed.scheme, parsed.netloc)
    robots = engine.analyze_robots(
        engine.fetch_small(base, "/robots.txt")[2] or "")
    sitemap = engine.analyze_sitemap(
        engine.fetch_small(base, "/sitemap.xml")[2] or "")
    # API references from crawled pages
    from .api import discover_api
    first_html = ""
    try:
        first_html = get(start_url, timeout=timeout)["body"]
    except Exception:
        pass
    api_refs = discover_api(start_url, first_html, scripts[:5])
    return {"start_url": start_url, "pages": pages, "scripts": scripts,
            "api_refs": api_refs, "robots": robots, "sitemap": sitemap,
            "pages_crawled": len(pages)}
