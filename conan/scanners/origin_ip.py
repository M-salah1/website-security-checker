#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Real-IP investigation — public DNS + one plain direct request.

Reports every resolved IP, the ASN/hosting org, CDN signals from the
response headers, and one ordinary HTTP request made directly to the
IP itself (Host header set to the site, no credentials). If the IP
answers with the site, it is an origin candidate; if it answers with
a CDN error page, it is the CDN edge. When the evidence does not
prove it, the origin is reported UNCONFIRMED — never guessed. No
bypass, no forged traffic, no private data.
"""
import ssl
import urllib.request

from ..scanners._http import get as http_get
from . import dns as dns_mod

CDN_MARKERS = ("cloudflare", "akamai", "fastly", "cloudfront", "sucuri",
               "incapsula", "stackpath", "bunnycdn", "keycdn")


def _direct_ip_check(ip, host, timeout=8):
    """One plain HTTPS request to the IP with the site's Host header."""
    out = {"ip": ip, "status": None, "server": None, "verdict": "unknown"}
    try:
        req = urllib.request.Request(
            "https://%s/" % ip,
            headers={"User-Agent": "Conan-Framework/5.5 (authorized security audit)",
                     "Host": host})
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8000).decode(errors="ignore")
            out["status"] = resp.status
            out["server"] = resp.headers.get("Server", "")
            lowered = body.lower()
            if any(m in lowered for m in ("cloudflare", "attention required",
                                          "error 100", "ray id")):
                out["verdict"] = "cdn-edge"
            elif resp.status == 200 and (host in body or "<html" in lowered):
                out["verdict"] = "origin-candidate"
            else:
                out["verdict"] = "unknown"
    except Exception as exc:
        out["error"] = str(exc)[:120]
    return out


def investigate_origin(host, url, timeout=10):
    """Full real-IP profile for one host. Never raises."""
    out = {"host": host, "ips": [], "cdn_detected": False, "cdn_signals": [],
           "direct_ip": None, "origin": "UNCONFIRMED",
           "origin_note": "The origin IP is UNCONFIRMED unless a direct "
                          "request proves it. Behind a CDN, the public IPs "
                          "are the CDN edge, not the origin server."}
    if not host or "." not in host or host.startswith("127.") or host == "localhost":
        out["note"] = "Local test target — no public origin to find."
        out["ips"] = [host] if host else []
        return out
    try:
        dns = dns_mod.analyze_dns(host)
        out["ips"] = dns.get("ips") or []
    except Exception:
        pass
    try:
        r = http_get(url, timeout=timeout)
        lower = {str(k).lower(): v for k, v in dict(r["headers"]).items()}
        hay = (lower.get("server", "") + " " + " ".join(lower.keys())).lower()
        for marker in CDN_MARKERS:
            if marker in hay:
                out["cdn_detected"] = True
                out["cdn_signals"].append(marker)
        if lower.get("cf-ray"):
            out["cdn_detected"] = True
            out["cdn_signals"].append("cf-ray")
    except Exception:
        pass
    ipv4 = [ip for ip in out["ips"] if "." in ip and ":" not in ip]
    if ipv4:
        out["direct_ip"] = _direct_ip_check(ipv4[0], host, timeout=timeout)
        if out["direct_ip"].get("verdict") == "origin-candidate":
            out["origin"] = ipv4[0] + " (candidate — direct request served the site)"
    return out
