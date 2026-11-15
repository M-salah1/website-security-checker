#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced IP intelligence — IPv4/IPv6.

Sources (all public, no keys):
- ip-api.com (JSON, free tier): approximate country/region/city, ISP, ASN,
  organization, hosting flag, proxy flag. Geolocation is an ESTIMATE.
- RDAP (rdap.org): public registration / network information.
- Reverse DNS + PTR via the local resolver.
- Authorized network checks: DNS, TCP, TLS, HTTP, configured ports, timing.

Never: DoS, destructive exploitation, unauthorized intrusion. Ownership is
never claimed from geolocation — estimates and verified data are labelled
separately.
"""
import ipaddress
import json
import socket
import urllib.parse
import urllib.request

from ..core import engine
from ._http import get as http_get


def is_valid_ip(text):
    try:
        ipaddress.ip_address((text or "").strip())
        return True
    except Exception:
        return False


def _fetch_json(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "Conan-Framework/4.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read(30000).decode(errors="ignore"))


def geo_lookup(ip, timeout=10):
    """Approximate geolocation + ISP/ASN from ip-api.com (estimate only)."""
    out = {"source": "ip-api.com", "estimate": True}
    try:
        d = _fetch_json("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,query" % ip, timeout)
        if d.get("status") == "success":
            out.update({"country": d.get("country"), "country_code": d.get("countryCode"),
                        "region": d.get("regionName"), "city": d.get("city"),
                        "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as"),
                        "hosting": d.get("hosting"), "proxy": d.get("proxy"),
                        "available": True})
        else:
            out["available"] = False
            out["error"] = d.get("message", "")
    except Exception as exc:
        out["available"] = False
        out["error"] = str(exc)
    return out


def rdap_lookup(ip, timeout=10):
    """Public RDAP registration data (network, country, entities)."""
    out = {"source": "rdap.org", "available": False}
    try:
        d = _fetch_json("https://rdap.org/ip/%s" % ip, timeout)
        out["available"] = True
        out["name"] = d.get("name")
        out["handle"] = d.get("handle")
        out["country"] = d.get("country")
        entities = []
        for e in d.get("entities") or []:
            roles = ", ".join(e.get("roles") or [])
            vcard = e.get("vcardArray") or []
            org = ""
            if len(vcard) > 1:
                for prop in vcard[1]:
                    if prop[0] == "fn":
                        org = prop[3]
            entities.append({"handle": e.get("handle"), "roles": roles, "org": org})
        out["entities"] = entities
    except Exception as exc:
        out["error"] = str(exc)
    return out


def reverse_dns(ip, timeout=8):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def check_port(ip, port, timeout=5):
    """Single authorized TCP connectivity check (no scanning beyond the
    configured ports the user asked for)."""
    import time
    t0 = time.time()
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return {"port": int(port), "open": True,
                    "ms": int((time.time() - t0) * 1000)}
    except Exception as exc:
        return {"port": int(port), "open": False,
                "ms": int((time.time() - t0) * 1000), "error": str(exc)}


def investigate_ip(ip, ports=(80, 443), timeout=10):
    """Full IP intelligence report."""
    ip = (ip or "").strip()
    geo = geo_lookup(ip, timeout=timeout)
    rdap = rdap_lookup(ip, timeout=timeout)
    ptr = reverse_dns(ip)
    checks = {"dns": bool(ptr), "tcp_80": None, "tcp_443": None, "http": None, "tls": None}
    for port in ports:
        try:
            res = check_port(ip, port, timeout=5)
            checks["tcp_%d" % port] = res
        except Exception:
            pass
    http = None
    if checks.get("tcp_80", {}).get("open"):
        http = http_get("http://%s/" % ip, timeout=timeout)
    checks["http"] = {"status": http["status"], "error": http["error"]} if http else None
    tls = None
    if checks.get("tcp_443", {}).get("open"):
        tls = engine.check_tls(ip)
    checks["tls"] = {"ok": tls.get("ok"), "issuer": tls.get("issuer"),
                     "days_left": tls.get("days_left")} if tls else None
    return {
        "ip": ip, "version": 6 if ":" in ip else 4,
        "geo_estimate": geo, "rdap": rdap, "ptr": ptr,
        "network_checks": checks,
        "note": "Geolocation is an approximate estimate from public data, "
                "not verified ownership. Ownership comes only from RDAP/WHOIS records.",
    }
