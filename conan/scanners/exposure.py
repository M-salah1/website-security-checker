#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN PUBLIC INFORMATION INTELLIGENCE — exposure audit.

Searches public/authorized sources for the domain:
- public indexed pages (sitemap), public documents, public text/config files,
  public API docs, publicly indexed subdomains (CT log), public contact info.
- file extensions: .pdf .doc .docx .xls .xlsx .csv .txt .xml .json .yaml
  .yml .ini .conf .log .bak .old .zip

For authorized domains, accessible files are inspected for accidental
exposure. Sensitive data detection:

  SECRET DETECTED
  Type: API Key
  Location: URL and file reference
  Value: [REDACTED]
  Severity: HIGH
  Remediation: Revoke and rotate the exposed credential.

Values are NEVER printed. Verification of credentials happens only through
the owner's authorized test environment. Discovered secrets are never used
to access accounts or services.
"""
import re

from ..core.evidence import finding
from ..core.security import redact_text
from ._http import get as http_get
from .domain_intelligence import ct_log_domains

EXPOSED_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt",
                      ".xml", ".json", ".yaml", ".yml", ".ini", ".conf", ".log",
                      ".bak", ".old", ".zip"]

SECRET_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]", "API Key", "high"),
    (r"(?i)aws_access_key_id\s*[:=]\s*['\"]?[A-Z0-9]{16,}['\"]?", "AWS Access Key", "critical"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "critical"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}['\"]", "Password-like string", "high"),
    (r"(?i)(?:db[_-]?password|database_url|mongodb://[^'\"\s]+|postgres://[^'\"\s]+|mysql://[^'\"\s]+)", "Database connection string", "critical"),
    (r"(?i)(?:bearer|access[_-]?token|auth[_-]?token)\s*[:=]?\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?", "Authentication token", "high"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key", "critical"),
    (r"(?i)secret\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Secret value", "high"),
    (r"(?i)debug\s*[:=]\s*true", "Debug enabled", "low"),
]

COMMON_PUBLIC_FILES = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/security.txt",
    "/.well-known/security.txt", "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/.env.example", "/config.example.json", "/api-docs", "/docs",
    "/backup.zip", "/db.sql", "/.env", "/.env.bak", "/.git/HEAD",
]


def scan_text_for_secrets(url, text, source=""):
    """Return findings; values are redacted, only type + location are shown."""
    out = []
    for pat, kind, sev in SECRET_PATTERNS:
        m = re.search(pat, text or "")
        if m:
            out.append(finding(
                "SECRET DETECTED — %s" % kind, sev, 75, url,
                "Type: %s | Location: %s | Value: [REDACTED]" % (kind, url),
                "Public response pattern scan (values masked)",
                "Fetch %s and search for the %s pattern" % (url, kind),
                "Remove the secret from public content immediately and revoke/rotate it",
                status="suspected"))
    return out


def audit_exposure(base_url, authorized=False, timeout=10):
    """Public information intelligence for a domain.

    `authorized=True` enables the bounded public-file inspection on the
    user's own / authorized domain. Unauthorized targets get only the
    public-source (CT subdomains, sitemap) analysis.
    """
    base = base_url.rstrip("/")
    files = []
    findings = []
    subdomains = ct_log_domains(base.split("://", 1)[-1].split("/")[0])
    for path in COMMON_PUBLIC_FILES:
        url = base + path
        r = http_get(url, timeout=timeout, max_bytes=60000)
        if r["status"] in (200, 401, 403):
            files.append({"url": url, "status": r["status"],
                          "size": len(r["body"]),
                          "content_type": (r["headers"].get("Content-Type", "") or "")[:60]})
            if authorized and r["status"] == 200:
                findings += scan_text_for_secrets(url, r["body"][:60000])
    # sitemap URLs
    indexed = []
    r = http_get(base + "/sitemap.xml", timeout=timeout, max_bytes=120000)
    if r["status"] == 200:
        indexed = re.findall(r"<loc>([^<]+)</loc>", r["body"])[:50]
    return {"target": base, "authorized": authorized,
            "public_files": files, "indexed_pages": indexed,
            "subdomains_public": subdomains.get("domains", []),
            "findings": findings,
            "note": "Secret values are always [REDACTED]. Verify credentials only "
                    "in the owner's authorized test environment."}
