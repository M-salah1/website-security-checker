#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Organization intelligence — publicly disclosed facts only.

Official name, website, published address, business registration,
executives, team members, administrators and contact details are reported
only when publicly disclosed. Unknown numbers are UNKNOWN — never invented.
No probing of private admin panels.
"""
from ..scanners.domain_intelligence import investigate_domain


def organization_report(domain, timeout=12):
    """Organization intelligence derived from public domain data."""
    d = investigate_domain(domain, timeout=timeout)
    org = d.get("organization", {})
    org["domain"] = domain
    org["registrar"] = d.get("registration", {}).get("registrar")
    org["nameservers"] = d.get("nameservers", [])
    org["hosting"] = d.get("hosting", {})
    org["tls_issuer"] = d.get("tls", {}).get("issuer")
    return org
