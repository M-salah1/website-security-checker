#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Website health monitor — availability, timing, retries, classification.

A 403 response is NOT proof the server is offline: it proves the server is
up and refusing that request. Classification rules are explicit and tested.
"""
import socket
import ssl
import time

from ._http import get

CLASSIFICATIONS = ("ONLINE", "DEGRADED", "OFFLINE", "DNS_ERROR",
                   "TLS_ERROR", "HTTP_ERROR", "UNKNOWN")


def _tcp_time(hostname, port=443, timeout=8):
    t0 = time.time()
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return int((time.time() - t0) * 1000), None
    except Exception as exc:
        return None, str(exc)


def check_health(url, retries=2, timeout=15):
    """One bounded health check with retries. Returns metrics + status."""
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    attempts = []
    last = None
    for i in range(max(1, retries + 1)):
        t0 = time.time()
        r = get(url, timeout=timeout)
        total_ms = int((time.time() - t0) * 1000)
        attempts.append({"attempt": i + 1, "status": r["status"],
                         "total_ms": total_ms, "error": r["error"],
                         "redirects": len(r["chain"])})
        last = r
        if r["status"] is not None:
            break
        time.sleep(0.5)
    tcp_ms, tcp_err = _tcp_time(hostname, port)
    status = last["status"]
    if status is None:
        err = (last["error"] or "").lower()
        if "name or service not known" in err or "nodename nor servname" in err \
                or "temporary failure in name resolution" in err or "dns" in err:
            cls = "DNS_ERROR"
        elif "ssl" in err or "certificate" in err or "tls" in err:
            cls = "TLS_ERROR"
        elif tcp_err:
            cls = "OFFLINE"
        else:
            cls = "UNKNOWN"
    elif status == 200:
        cls = "ONLINE"
    elif status in (301, 302, 307, 308):
        cls = "ONLINE"  # redirecting is still up
    elif status in (401, 403):
        cls = "ONLINE"  # server is up and enforcing access control
    elif status == 429:
        cls = "DEGRADED"
    elif status and status >= 500:
        cls = "DEGRADED" if status in (502, 503, 504) else "HTTP_ERROR"
    else:
        cls = "HTTP_ERROR"
    ttfb = attempts[0]["total_ms"] if attempts else None
    times = [a["total_ms"] for a in attempts if a["status"] is not None]
    return {
        "url": url, "classification": cls, "status": status,
        "tcp_ms": tcp_ms, "ttfb_ms": ttfb,
        "total_ms": last and attempts[-1]["total_ms"],
        "avg_ms": int(sum(times) / len(times)) if times else None,
        "redirects": len(last["chain"]) if last else 0,
        "attempts": attempts, "error": last["error"] if last else None,
    }
