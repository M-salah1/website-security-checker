#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Client-side reverse engineering — public code only.

Reads the JavaScript the site itself sends to every visitor (script
tags on its public pages) and extracts API endpoints, GraphQL and
WebSocket URLs. This is reading code the site publishes — no login,
no bypass, no credentials, no private data. Only endpoint URL strings
are collected; secret values, tokens and passwords are never collected
or shown (endpoint patterns simply never match them).
"""
import re
from urllib.parse import urljoin, urlparse

from ._http import get as http_get

_ENDPOINT_RE = re.compile(r"""["'`](/(?:api|graphql|v\d|rest)[A-Za-z0-9_\-/.?=&%#]*)["'`]""")
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|__NEXT_DATA__)\s*\(\s*["'`]([^"'`]{3,200})["'`]""")
_ABS_RE = re.compile(
    r"""["'`](https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{6,200})["'`]""")
_WS_RE = re.compile(r"""["'`](wss?://[^"'`]{4,200})["'`]""")
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src=["'`]([^"'`#]{3,300})["'`]""", re.I)


def extract_from_js(text):
    """Parse one JS file's text. Pure function — endpoint strings only."""
    endpoints, websockets, absolute = set(), set(), set()
    for m in _ENDPOINT_RE.findall(text or ""):
        if " " not in m:
            endpoints.add(m[:160])
    for m in _FETCH_RE.findall(text or ""):
        if m.startswith("/"):
            endpoints.add(m[:160])
        elif m.startswith("http"):
            absolute.add(m[:200])
    for m in _ABS_RE.findall(text or ""):
        if "/api/" in m or "/graphql" in m or "/rest/" in m:
            absolute.add(m[:200])
    for m in _WS_RE.findall(text or ""):
        websockets.add(m[:200])
    return {
        "endpoints": sorted(endpoints)[:40],
        "absolute_urls": sorted(absolute)[:20],
        "websockets": sorted(websockets)[:10],
        "graphql": ("/graphql" in (text or "").lower()),
    }


def analyze_js(base_url, html, timeout=12, max_scripts=5, max_bytes=200000):
    """Fetch the site's public scripts and extract their endpoints.

    Never raises. Bounded: at most max_scripts files, max_bytes each.
    """
    out = {"scripts_scanned": 0, "scripts": [], "endpoints": [],
           "absolute_urls": [], "websockets": [], "graphql": False}
    try:
        srcs = []
        for src in _SCRIPT_SRC_RE.findall(html or ""):
            full = urljoin(base_url, src)
            if full not in srcs:
                srcs.append(full)
        endpoints, absolute, websockets = set(), set(), set()
        graphql = False
        for src in srcs[:max_scripts]:
            try:
                r = http_get(src, timeout=timeout, max_bytes=max_bytes)
            except Exception:
                continue
            if r["status"] != 200 or not r["body"]:
                continue
            parsed = extract_from_js(r["body"])
            out["scripts_scanned"] += 1
            out["scripts"].append(urlparse(src).path[-60:])
            endpoints.update(parsed["endpoints"])
            absolute.update(parsed["absolute_urls"])
            websockets.update(parsed["websockets"])
            graphql = graphql or parsed["graphql"]
        out["endpoints"] = sorted(endpoints)[:40]
        out["absolute_urls"] = sorted(absolute)[:20]
        out["websockets"] = sorted(websockets)[:10]
        out["graphql"] = graphql
    except Exception as exc:
        out["error"] = str(exc)
    return out
