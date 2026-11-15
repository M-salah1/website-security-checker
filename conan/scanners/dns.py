#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS engine — A/AAAA/CNAME/MX/NS/TXT/SOA + reverse + resolution time."""
import socket
import time

from ..core import engine


def _doh_records(name, rtype):
    d = engine.doh_query(name, rtype)
    if not d:
        return []
    out = []
    for a in d.get("Answer") or []:
        v = (a.get("data") or "").rstrip(".")
        if v and v not in out:
            out.append(v)
    return out


def analyze_dns(hostname):
    t0 = time.time()
    dns = engine.resolve_dns(hostname)
    elapsed_ms = int((time.time() - t0) * 1000)
    domain = engine.registrable_domain(hostname)
    out = {
        "hostname": hostname,
        "domain": domain,
        "resolution_ms": elapsed_ms,
        "ips": dns.get("ips", []),
        "ipv4": [ip for ip in dns.get("ips", []) if "." in ip],
        "ipv6": [ip for ip in dns.get("ips", []) if ":" in ip],
        "reverse": dns.get("reverse", ""),
        "reverse_all": {},
        "a": _doh_records(hostname, "A"),
        "aaaa": _doh_records(hostname, "AAAA"),
        "cname": _doh_records(hostname, "CNAME"),
        "mx": _doh_records(domain, "MX"),
        "ns": _doh_records(domain, "NS"),
        "txt": _doh_records(domain, "TXT"),
        "soa": _doh_records(domain, "SOA"),
        "dnssec": engine.check_dnssec(domain),
        "error": dns.get("error", ""),
    }
    for ip in out["ips"][:5]:
        try:
            out["reverse_all"][ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            out["reverse_all"][ip] = ""
    return out
