#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN PUBLIC INFORMATION INTELLIGENCE — OSINT aggregator.

Public sources only: Certificate Transparency subdomains, sitemap-indexed
pages, robots.txt, security.txt, public API docs, public DNS records.
No private data, no logins, no scraping of personal information.
"""
from ..scanners.domain_intelligence import ct_log_domains
from ..scanners.exposure import audit_exposure


def osint_domain(domain, authorized=False, timeout=10):
    """Aggregate the public information available about a domain."""
    base = "https://%s" % domain.strip().lower().lstrip("www.")
    ct = ct_log_domains(domain, timeout=timeout)
    exposure = audit_exposure(base, authorized=authorized, timeout=timeout)
    return {
        "domain": domain,
        "public_subdomains": ct.get("domains", []),
        "certificates_logged": ct.get("certificates", 0),
        "indexed_pages": exposure.get("indexed_pages", []),
        "public_files": exposure.get("public_files", []),
        "secret_findings": exposure.get("findings", []),
        "sources": ["Certificate Transparency (crt.sh)", "sitemap.xml",
                    "robots.txt", "security.txt", "public DNS"],
        "note": "Public sources only. Secret values are always [REDACTED].",
    }
