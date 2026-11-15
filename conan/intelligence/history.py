#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Domain history & deep identity — public records only, never invented.

What this module can honestly report:
- Registration: creation / expiry / registrar / registrant org from
  public WHOIS (redacted by most registrars today — shown as UNKNOWN).
- Certificate history: earliest and latest certificate dates and all
  publicly logged hostnames from the Certificate Transparency log
  (crt.sh, free public API).
- Admin contact: ONLY what the site itself publishes — security.txt
  Contact lines and a publicly disclosed WHOIS org. Personal admin
  names are not probed and not guessed.
- Country / servers: IP geolocation estimate, hosting org/ASN, server
  header, nameservers, MX records, HTTP methods (OPTIONS, read-only).

What it CANNOT report from free public sources (shown as UNKNOWN with
the reason, never invented):
- Previous domain names and the date a name changed: that is WHOIS
  history, a paid commercial service. The closest free facts are the
  domain creation date and the earliest CT certificate date.
"""
import json
import urllib.parse
import urllib.request

from ..scanners._http import get as http_get, request as http_request
from ..scanners import dns as dns_mod
from ..scanners.domain_intelligence import investigate_domain
from ..scanners.ip_intelligence import geo_lookup

UNKNOWN = "UNKNOWN"


def _fetch_json(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": "Conan-Framework/5.2"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(300000).decode(errors="ignore"))


def parse_ct_history(entries):
    """Parse crt.sh entries into dates + hostnames. Pure function."""
    hostnames = set()
    dates = []
    for entry in entries or []:
        for name in (entry.get("name_value") or "").split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*"):
                hostnames.add(name)
        for key in ("not_before", "entry_timestamp"):
            value = entry.get(key)
            if value:
                dates.append(str(value)[:10])
    dates = sorted(d for d in dates if d)
    return {
        "available": bool(entries),
        "certificates": len(entries or []),
        "hostnames": sorted(hostnames)[:50],
        "earliest_certificate": dates[0] if dates else None,
        "latest_certificate": dates[-1] if dates else None,
    }


def ct_history(domain, timeout=12):
    """Certificate history from the public CT log (crt.sh). Never raises."""
    out = {"source": "crt.sh (Certificate Transparency)",
           "available": False, "certificates": 0, "hostnames": [],
           "earliest_certificate": None, "latest_certificate": None}
    try:
        entries = _fetch_json("https://crt.sh/?q=%%25.%s&output=json" % domain, timeout)
        out.update(parse_ct_history(entries))
    except Exception as exc:
        out["error"] = str(exc)
    return out


def parse_security_txt(text):
    """Parse security.txt content. Pure function — contacts are public data."""
    contacts, expires, encryption = [], None, None
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "contact" and value:
            contacts.append(value)
        elif key == "expires":
            expires = value
        elif key == "encryption":
            encryption = value
    return {"contacts": contacts, "expires": expires, "encryption": encryption}


def fetch_security_contacts(base_url, timeout=10):
    """Fetch the site's own published security.txt contacts. Never raises."""
    out = {"available": False, "contacts": [], "expires": None}
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = http_get(base_url.rstrip("/") + path, timeout=timeout)
        except Exception:
            continue
        if r["status"] == 200 and "contact:" in r["body"].lower():
            parsed = parse_security_txt(r["body"])
            out.update(parsed)
            out["available"] = True
            out["url"] = base_url.rstrip("/") + path
            break
    return out


def http_methods(base_url, timeout=10):
    """Allowed HTTP methods via a read-only OPTIONS request. Never raises."""
    out = {"available": False, "methods": [], "risky": []}
    try:
        r = http_request(base_url, method="OPTIONS", timeout=timeout, max_bytes=0)
        allow = (r["headers"].get("Allow") or "") if hasattr(r["headers"], "get") else ""
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        out["methods"] = methods
        out["risky"] = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT")]
        out["available"] = bool(methods) or r["status"] is not None
        out["status"] = r["status"]
    except Exception as exc:
        out["error"] = str(exc)
    return out


def domain_history(domain, base_url, timeout=12):
    """Full deep-identity profile for one domain. Never raises."""
    domain = (domain or "").strip().lower().lstrip("www.")
    profile = {
        "domain": domain,
        "created": None, "expires": None, "registrar": None,
        "registrant_org": UNKNOWN,
        "admin_contact": UNKNOWN,
        "admin_contact_source": None,
        "previous_names": UNKNOWN,
        "previous_names_note": (
            "Previous domain names and rename dates are WHOIS history, a paid "
            "commercial service — no free public source publishes them. The "
            "closest free facts are the creation date below and the earliest "
            "certificate date from the public CT log."),
        "earliest_certificate": None, "latest_certificate": None,
        "ct_certificates": 0, "ct_hostnames": [],
        "country": UNKNOWN, "region": None, "city": None,
        "hosting_org": UNKNOWN, "asn": None,
        "ips": [], "nameservers": [], "mx": [],
        "server_header": None, "tls_issuer": None,
    }
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        profile["note"] = "Local test target — no public registration history exists."
        return profile
    try:
        info = investigate_domain(domain, timeout=timeout)
        reg = info.get("registration") or {}
        profile["created"] = reg.get("created")
        profile["expires"] = reg.get("expires")
        profile["registrar"] = reg.get("registrar")
        profile["registrant_org"] = reg.get("registrant_org") or UNKNOWN
        profile["nameservers"] = info.get("nameservers") or []
        profile["ips"] = (info.get("dns") or {}).get("ips") or []
        profile["server_header"] = info.get("server_header") or None
        profile["tls_issuer"] = (info.get("tls") or {}).get("issuer")
        hosting = info.get("hosting") or {}
        profile["hosting_org"] = hosting.get("org") or UNKNOWN
        profile["asn"] = hosting.get("asn")
        ct = info.get("certificate_transparency") or {}
        profile["ct_certificates"] = ct.get("certificates", 0)
        profile["ct_hostnames"] = ct.get("domains", []) or []
    except Exception as exc:
        profile["error"] = str(exc)
    # Earliest certificate date needs the dated CT entries.
    try:
        hist = ct_history(domain, timeout=timeout)
        profile["earliest_certificate"] = hist.get("earliest_certificate")
        profile["latest_certificate"] = hist.get("latest_certificate")
        if hist.get("certificates"):
            profile["ct_certificates"] = hist["certificates"]
        if hist.get("hostnames"):
            profile["ct_hostnames"] = hist["hostnames"]
    except Exception:
        pass
    # Country + hosting from the first IP (estimate only).
    if profile["ips"]:
        try:
            geo = geo_lookup(profile["ips"][0], timeout=timeout)
            if geo.get("available"):
                profile["country"] = geo.get("country") or UNKNOWN
                profile["region"] = geo.get("region")
                profile["city"] = geo.get("city")
                profile["hosting_org"] = geo.get("org") or profile["hosting_org"]
                profile["asn"] = geo.get("asn") or profile["asn"]
        except Exception:
            pass
    try:
        dns = dns_mod.analyze_dns(domain)
        profile["mx"] = dns.get("mx") or []
        if not profile["ips"]:
            profile["ips"] = dns.get("ips") or []
    except Exception:
        pass
    # Admin contact: only what the site itself publishes.
    try:
        sec = fetch_security_contacts(base_url, timeout=timeout)
        if sec.get("contacts"):
            profile["admin_contact"] = "; ".join(sec["contacts"][:3])
            profile["admin_contact_source"] = "security.txt (published by the site)"
    except Exception:
        pass
    if profile["admin_contact"] == UNKNOWN and profile["registrant_org"] != UNKNOWN \
            and "redacted" not in str(profile["registrant_org"]).lower():
        profile["admin_contact"] = profile["registrant_org"]
        profile["admin_contact_source"] = "public WHOIS registrant org"
    if profile["admin_contact"] == UNKNOWN:
        profile["admin_contact_source"] = (
            "Not publicly disclosed (WHOIS privacy / GDPR redaction). "
            "Conan does not probe for private admin identities.")
    return profile
