#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTML reporting — professional report with risk charts (CSS bars)."""
import html as html_mod

from .json_report import build_json_report

SEV_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
              "low": "#2563eb", "info": "#6b7280"}


def _esc(v):
    return html_mod.escape(str(v if v is not None else ""))


def _bar(label, count, total, color):
    pct = int(100 * count / total) if total else 0
    return ('<div style="margin:4px 0"><span style="display:inline-block;width:90px">%s</span>'
            '<span style="display:inline-block;width:60%%;background:#eee;height:14px">'
            '<span style="display:inline-block;width:%d%%;background:%s;height:14px"></span></span>'
            ' %d (%d%%)</div>') % (_esc(label), pct, color, count, pct)


def build_html_report(scan):
    r = build_json_report(scan)
    lang = scan.get("language", "ar")
    direction = "rtl" if lang == "ar" else "ltr"
    score = r.get("score") or 0
    color = "#16a34a" if score >= 80 else "#ca8a04" if score >= 60 else "#dc2626"
    dist = r.get("severity_distribution") or {}
    total_f = sum(dist.values())
    bars = "".join(_bar(k.title(), v, total_f, SEV_COLORS.get(k, "#666"))
                   for k, v in dist.items() if v)
    rows = ""
    for f in r["vulnerabilities"]:
        rows += ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                 "<td>%s</td><td>%s</td></tr>") % (
            _esc(f.get("severity", "")), _esc(f.get("name", "")),
            _esc(f.get("status", "")), _esc(f.get("confidence", "")),
            _esc(f.get("url", "")), _esc(f.get("evidence", ""))[:160])
    recs = "".join("<li>%s</li>" % _esc(x) for x in r["recommendations"])
    dns = r.get("dns") or {}
    tls = r.get("tls") or {}
    health = r.get("health") or {}
    phishing = r.get("phishing") or {}
    html = """<!DOCTYPE html><html lang="%s" dir="%s"><head><meta charset="utf-8">
<title>CONAN FRAMEWORK v5.2 — %s</title><style>
body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:20px auto;padding:0 16px;color:#111;background:#fff}
h1{font-size:24px} h2{border-bottom:2px solid #f97316;padding-bottom:4px}
.score{font-size:44px;color:%s}
table{border-collapse:collapse;width:100%%;margin:12px 0}
td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:13px;vertical-align:top}
th{background:#111;color:#fff}
footer{color:#666;font-size:13px;margin-top:24px}</style></head><body>
<h1>🔍 CONAN FRAMEWORK v5.2 — Website Security Report</h1>
<p>Target: <b>%s</b><br>Scanned: %s<br>Duration: %s s<br>
Developer: Hafed Mehdi Salah Eddine — Algeria 🇩🇿 — GitHub: M-salah1</p>
<p class="score">%d%% — %s</p>
<p>Confidence (verifiable evidence): %d%% — Checks: %d — Confirmed: %d — Suspected: %d</p>
<h2>Risk distribution</h2>%s
<h2>1. Target information</h2><p>%s</p>
<h2>2. Scope &amp; authorization</h2><p>%s</p>
<h2>3. DNS</h2><p>IPs: %s<br>Nameservers: %s<br>DNSSEC: %s</p>
<h2>4. TLS certificate</h2><p>Issuer: %s<br>Version: %s<br>Days left: %s<br>Chain verified: %s</p>
<h2>5. HTTP headers</h2><p>See findings below; full check list in the JSON report.</p>
<h2>6. Cookies</h2><p>%d cookies analyzed (values masked).</p>
<h2>7. Discovered routes</h2><p>%d pages crawled.</p>
<h2>8. Forms</h2><p>%d forms found.</p>
<h2>9. Authentication audit</h2><p>%s</p>
<h2>10. Registration audit</h2><p>%s</p>
<h2>11. Vulnerability findings</h2>
<table><tr><th>Severity</th><th>Name</th><th>Status</th><th>Confidence</th><th>URL</th><th>Evidence</th></tr>%s</table>
<h2>12. Anti-phishing analysis</h2><p>Risk score: %s/100 — %s</p>
<h2>13. Website availability</h2><p>%s — HTTP %s — %s ms</p>
<h2>14. Recommendations</h2><ol>%s</ol>
<h2>15. Final risk assessment</h2><p>Score %d%% (%s). %d confirmed and %d suspected findings. %s</p>
<footer>CONAN FRAMEWORK v5.2 — passive + authorized-active audit only. No passwords or session values are stored in this report.</footer>
</body></html>""" % (
        lang, direction, _esc(r["target"]), color,
        _esc(r["target"]), _esc(r["scan_timestamp"]), _esc(r["duration_s"]),
        score, _esc(r["grade"]), r.get("confidence") or 0,
        r.get("checks_count") or 0, r["confirmed_findings"], r["suspected_findings"],
        bars, _esc(r["target"]),
        _esc((r.get("scope") or {}).get("kind", "passive")),
        _esc(", ".join(dns.get("ips", []) or [])),
        _esc(", ".join((dns.get("ns") or []))),
        _esc((dns.get("dnssec") or {}).get("enabled")),
        _esc(tls.get("issuer", "")), _esc(tls.get("version", "")),
        _esc(tls.get("days_left")), _esc(tls.get("chain_verified")),
        len((r.get("cookies") or {}).get("cookies", [])),
        len((r.get("discovery") or {}).get("pages", [])),
        len(r.get("forms") or []),
        _esc((r.get("auth_audit") or {}).get("url", "not run")),
        _esc((r.get("registration_audit") or {}).get("url", "not run")),
        rows,
        _esc(phishing.get("risk_score", "-")), _esc(phishing.get("classification", "-")),
        _esc(health.get("classification", "-")), _esc(health.get("status")),
        _esc(health.get("total_ms")),
        recs, score, _esc(r["grade"]), r["confirmed_findings"],
        r["suspected_findings"],
        "Review the confirmed findings first." if r["confirmed_findings"] else "No confirmed findings.")
    return html


def save_html_report(scan, path):
    data = build_html_report(scan)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return data
