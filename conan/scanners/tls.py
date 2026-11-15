#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS engine — wraps the v2.4 engine and adds protocol-version probing."""
import socket
import ssl

from ..core import engine


def probe_protocol(hostname, max_version, timeout=8):
    """Try a handshake limited to one TLS version. Returns True if accepted."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = max_version
        ctx.maximum_version = max_version
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def analyze_tls(hostname, port=443):
    """Certificate details + chain status + supported protocol versions.

    Protocol probing only opens handshakes (no data is sent) and is skipped
    when the network is unavailable — missing data is reported as
    unverifiable, never as a vulnerability.
    """
    base = engine.check_tls(hostname, port)
    out = dict(base)
    out["protocols"] = {}
    out["protocols_unverifiable"] = False
    if base.get("ok"):
        versions = []
        try:
            versions = [(ssl.TLSVersion.TLSv1, "TLSv1.0"),
                        (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
                        (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
                        (ssl.TLSVersion.TLSv1_3, "TLSv1.3")]
        except Exception:
            versions = []
        for ver, name in versions:
            try:
                out["protocols"][name] = probe_protocol(hostname, ver)
            except Exception:
                out["protocols"][name] = None
        if not any(v is True for v in out["protocols"].values()):
            out["protocols_unverifiable"] = True
    return out
