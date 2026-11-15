#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Published contact discovery — public pages only.

Reads the site's own public pages (home, /about, /contact, /team and
pages found by discovery) and extracts what the site itself publishes:
mailto: addresses and contact-labelled lines. A personal admin name is
reported only if the site itself publishes it on these pages. Nothing
is probed, guessed, enumerated or taken from private sources.
"""
import re

from ..scanners._http import get as http_get

_MAILTO_RE = re.compile(
    r"mailto:([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})", re.I)
_KEYWORD_RE = re.compile(
    r"\b(admin|contact|support|webmaster|تواصل|إدارة|دعم)\b", re.I)
_PAGES = ("/about", "/contact", "/team", "/about-us", "/contact-us")


def extract_contacts(html):
    """Parse one page's HTML. Pure function — published data only."""
    emails = sorted(set(_MAILTO_RE.findall(html or "")))[:10]
    text = re.sub(r"<[^>]+>", "\n", html or "")
    lines = []
    for line in text.splitlines():
        line = " ".join(line.split())
        if len(line) >= 4 and len(line) <= 140 and _KEYWORD_RE.search(line):
            if line not in lines:
                lines.append(line)
    return {"emails": emails, "contact_lines": lines[:5]}


def discover_contacts(base_url, html, discovery_pages, timeout=10):
    """Check the home page + public about/contact pages. Never raises."""
    out = {"emails": [], "contact_lines": [], "pages_checked": []}
    emails, lines = set(), []
    try:
        parsed = extract_contacts(html)
        emails.update(parsed["emails"])
        lines.extend(parsed["contact_lines"])
        out["pages_checked"].append("/")
    except Exception:
        pass
    candidates = list(_PAGES)
    for page in (discovery_pages or []):
        path = (page.get("url") or page.get("path") or "")
        for want in _PAGES:
            if want in path and path not in candidates:
                candidates.append(path)
    for path in candidates[:6]:
        url = base_url.rstrip("/") + path if path.startswith("/") else path
        try:
            r = http_get(url, timeout=timeout, max_bytes=100000)
        except Exception:
            continue
        if r["status"] != 200 or not r["body"]:
            continue
        parsed = extract_contacts(r["body"])
        emails.update(parsed["emails"])
        for line in parsed["contact_lines"]:
            if line not in lines:
                lines.append(line)
        out["pages_checked"].append(path)
    out["emails"] = sorted(emails)[:10]
    out["contact_lines"] = lines[:5]
    return out
