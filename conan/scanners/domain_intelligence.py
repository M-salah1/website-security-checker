#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Domain & ownership intelligence.

- Registration/expiry/registrar/nameservers from public WHOIS (engine).
- DNS provider, hosting org, CDN provider from DNS + headers.
- ASN from ip-api.com for the resolved IP.
- TLS issuer from the certificate.
- Certificate history / associated domains from Certificate Transparency
  (crt.sh public API) — public log data only.
- Organization intelligence: only publicly published facts. When a number
  (administrators, employees, moderators) is unknown, it is UNKNOWN —
  never invented. No probing of private admin panels.
"""
import json
import urllib.request

from ..core import engine
from ._http import get as http_get
from .ip_intelligence import geo_lookup


def _fetch_json(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": "Conan-Framework/4.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(200000).decode(errors="ignore"))


def ct_log_domains(domain, timeout=12, limit=50):
    """Publicly logged certificate names for a domain (crt.sh)."""
    out = {"source": "crt.sh (Certificate Transparency)", "available": False,
           "domains": [], "certificates": 0}
    try:
        data = _fetch_json("https://crt.sh/?q=%%25.%s&output=json" % domain, timeout)
        names = set()
        for entry in data or []:
            for name in (entry.get("name_value") or "").split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    names.add(name)
        out["domains"] = sorted(names)[:limit]
        out["certificates"] = len(data or [])
        out["available"] = True
    except Exception as exc:
        out["error"] = str(exc)
    return out


def investigate_domain(domain, timeout=12):
    """Full deep-identity profile. Never raises.

    The six lookups (WHOIS, DNS, TLS, homepage, geo, CT log) run in
    parallel: sequentially they summed to over a minute on slow
    networks, which is what timed the whole module out.
    """
    import concurrent.futures

    domain = (domain or "").strip().lower().lstrip("www.")

    def _whois():
        return engine.get_whois(domain)

    def _dns():
        return engine.resolve_dns(domain)

    def _tls():
        return engine.check_tls(domain)

    def _home():
        r = http_get("https://%s/" % domain, timeout=timeout)
        lower = {str(k).lower(): v for k, v in dict(r["headers"]).items()}
        tech = engine.detect_tech(lower, r["body"]) \
            if hasattr(engine, "detect_tech") else []
        return {"server": lower.get("server", ""), "tech": tech}

    def _ct():
        return ct_log_domains(domain, timeout=timeout)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=6)
    try:
        futs = {
            "whois": pool.submit(_whois),
            "dns": pool.submit(_dns),
            "tls": pool.submit(_tls),
            "home": pool.submit(_home),
            "ct": pool.submit(_ct),
        }
        out = {}
        for name, fut in futs.items():
            try:
                out[name] = fut.result(timeout=timeout + 5)
            except Exception:
                out[name] = None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    whois = out.get("whois") or {}
    dns = out.get("dns") or {}
    tls = out.get("tls") or {}
    home = out.get("home") or {}
    ct = out.get("ct") or {}
    server = home.get("server", "")
    cdn = home.get("tech") or []
    asn = {}
    if dns.get("ips"):
        try:
            g = geo_lookup(dns["ips"][0], timeout=timeout)
            asn = {"asn": g.get("asn"), "isp": g.get("isp"), "org": g.get("org"),
                   "hosting": g.get("hosting")}
        except Exception:
            asn = {}
    org = {
        "official_name": whois.get("org") or "UNKNOWN",
        "official_website": domain,
        "published_address": "UNKNOWN",
        "business_registration": "UNKNOWN",
        "executives": "UNKNOWN",
        "team_members": "UNKNOWN",
        "administrators_count": "UNKNOWN",
        "contact_details": "UNKNOWN",
        "note": "Organization facts come only from publicly disclosed WHOIS / "
                "registry data. Unknown counts are shown as UNKNOWN, never invented.",
    }
    return {
        "domain": domain,
        "registration": {"created": whois.get("created"), "expires": whois.get("expires"),
                         "registrar": whois.get("registrar"),
                         "registrant_org": whois.get("org") or "UNKNOWN (redacted or not disclosed)"},
        "nameservers": whois.get("nameservers") or [],
        "dns": {"ips": dns.get("ips", []), "reverse": dns.get("reverse", "")},
        "hosting": asn,
        "cdn_or_tech": cdn or [],
        "server_header": server,
        "tls": {"issuer": tls.get("issuer"), "version": tls.get("version"),
                "days_left": tls.get("days_left"), "ok": tls.get("ok")},
        "certificate_transparency": ct,
        "organization": org,
    }
