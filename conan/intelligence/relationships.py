#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relationship intelligence — publicly associated domains and infrastructure.

Sources: Certificate Transparency (shared certificate names), shared
nameservers and shared resolved IPs. Associations are labelled by their
source; they prove shared infrastructure, not shared ownership.
"""
from ..scanners.domain_intelligence import ct_log_domains
from ..scanners import dns as dns_mod


def related_domains(domain, timeout=12):
    """Domains publicly associated with this one via CT logs."""
    ct = ct_log_domains(domain, timeout=timeout)
    return {"domain": domain,
            "associated_domains": ct.get("domains", []),
            "certificates_logged": ct.get("certificates", 0),
            "source": "Certificate Transparency (crt.sh)",
            "note": "Shared certificate names prove shared infrastructure, "
                    "not shared ownership."}


def shared_infrastructure(domain, timeout=10):
    """Nameservers and IPs shared with other names — from public DNS."""
    d = dns_mod.analyze_dns(domain)
    return {"domain": domain,
            "nameservers": d.get("ns", []),
            "ips": d.get("ips", []),
            "reverse": d.get("reverse", ""),
            "note": "Nameservers and IPs are public DNS data."}
