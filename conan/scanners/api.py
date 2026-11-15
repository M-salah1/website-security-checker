#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API discovery — only publicly referenced endpoints.

Sources: HTML, public JavaScript, and OpenAPI documents when intentionally
exposed (swagger.json / openapi.json). No route brute-forcing, no destructive
endpoint invocation.
"""
import json
import re
import urllib.parse

from ._http import get

_URL_RE = re.compile(r"['\"`](/api/[A-Za-z0-9_\-/{}.?=&%]+)['\"`]")
_FETCH_RE = re.compile(r"(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest)\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I)
_OPENAPI_PATHS = ["/swagger.json", "/openapi.json", "/api/openapi.json",
                  "/api/docs", "/docs/openapi.json"]


def _abs(base, path):
    return urllib.parse.urljoin(base, path)


def discover_api(base_url, html="", scripts=None, timeout=10):
    endpoints = {}

    def add(url, source, method="GET", auth=None):
        key = url
        if key not in endpoints:
            endpoints[key] = {"endpoint": url, "method": method, "source": source,
                              "auth": auth, "status": None, "content_type": ""}

    text = html or ""
    for m in _URL_RE.finditer(text):
        add(_abs(base_url, m.group(1)), "html")
    for m in _FETCH_RE.finditer(text):
        add(_abs(base_url, m.group(1)), "javascript")
    for script_url in (scripts or []):
        try:
            r = get(script_url, timeout=timeout, max_bytes=120000)
            if r["status"] == 200:
                for m in _URL_RE.finditer(r["body"]):
                    add(_abs(base_url, m.group(1)), "javascript:%s" % script_url)
                for m in _FETCH_RE.finditer(r["body"]):
                    add(_abs(base_url, m.group(1)), "javascript:%s" % script_url)
        except Exception:
            pass
    # OpenAPI documents only when intentionally exposed
    parsed = urllib.parse.urlparse(base_url)
    origin = "%s://%s" % (parsed.scheme, parsed.netloc)
    for path in _OPENAPI_PATHS:
        try:
            r = get(origin + path, timeout=timeout, max_bytes=120000)
            if r["status"] == 200 and "json" in (r["headers"].get("Content-Type", "") or ""):
                try:
                    doc = json.loads(r["body"])
                    for pth, ops in (doc.get("paths") or {}).items():
                        for method in ops:
                            if method.lower() in ("get", "post", "put", "delete", "patch"):
                                add(_abs(base_url, pth), "openapi:%s" % path,
                                    method=method.upper())
                except Exception:
                    pass
        except Exception:
            pass
    # Probe each discovered endpoint with a safe GET to record its status
    for ep in endpoints.values():
        try:
            r = get(ep["endpoint"], timeout=timeout, max_bytes=20000)
            ep["status"] = r["status"]
            ep["content_type"] = (r["headers"].get("Content-Type", "") or "")[:60]
            if r["status"] in (401, 403):
                ep["auth"] = "required (observed %s)" % r["status"]
        except Exception:
            pass
    return sorted(endpoints.values(), key=lambda e: e["endpoint"])
