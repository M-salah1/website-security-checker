#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Form extraction — login / registration / search / upload forms."""
import re
import urllib.parse

from ._http import get

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.I)
_TEXTAREA_RE = re.compile(r"<textarea\b([^>]*)>", re.I)
_SELECT_RE = re.compile(r"<select\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r"(\w[\w-]*)\s*=\s*[\"']([^\"']*)[\"']")


def _attrs(tag):
    return {k.lower(): v for k, v in _ATTR_RE.findall(tag or "")}


def extract_forms(html, base_url):
    """Parse forms from HTML. No requests are made here."""
    forms = []
    for m in _FORM_RE.finditer(html or ""):
        fat = _attrs(m.group(1))
        body = m.group(2)
        action = urllib.parse.urljoin(base_url, fat.get("action", "") or base_url)
        inputs = []
        for im in _INPUT_RE.finditer(body):
            ia = _attrs(im.group(1))
            inputs.append({"type": (ia.get("type") or "text").lower(),
                           "name": ia.get("name", ""), "value": ia.get("value", "")[:40],
                           "accept": ia.get("accept", "")})
        for tm in _TEXTAREA_RE.finditer(body):
            ta = _attrs(tm.group(1))
            inputs.append({"type": "textarea", "name": ta.get("name", ""),
                           "value": "", "accept": ""})
        for sm in _SELECT_RE.finditer(body):
            sa = _attrs(sm.group(1))
            inputs.append({"type": "select", "name": sa.get("name", ""),
                           "value": "", "accept": ""})
        kinds = set()
        names = " ".join(i["name"].lower() for i in inputs)
        types = [i["type"] for i in inputs]
        if "password" in types:
            kinds.add("login" if any(w in names for w in ("login", "user", "email")) else "password")
        if "file" in types:
            kinds.add("upload")
        if any(w in names for w in ("register", "signup", "sign-up", "confirm")) \
                or "register" in action.lower() or "signup" in action.lower():
            kinds.add("registration")
        if not kinds:
            kinds.add("other")
        csrf = any("csrf" in i["name"].lower() or "token" in i["name"].lower()
                   and i["type"] == "hidden" for i in inputs)
        forms.append({"action": action,
                      "method": (fat.get("method") or "GET").upper(),
                      "enctype": fat.get("enctype", ""),
                      "inputs": inputs, "kinds": sorted(kinds),
                      "csrf_token": csrf})
    return forms


def fetch_forms(url, timeout=15):
    r = get(url, timeout=timeout)
    if r["status"] is None:
        return {"url": url, "status": None, "forms": [], "error": r["error"]}
    return {"url": url, "status": r["status"], "forms": extract_forms(r["body"], url),
            "error": None}


def find_login_forms(forms):
    return [f for f in forms if "login" in f["kinds"] or "password" in f["kinds"]]


def find_registration_forms(forms):
    return [f for f in forms if "registration" in f["kinds"]]
