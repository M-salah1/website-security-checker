#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Animated HTML report — the same real scan data, presented with motion.

Pure CSS animations (no JavaScript, no external files, works offline):
a rotating radar sweep, a pulsing shield, an animated score ring and
findings rows that fade/slide in one by one. The numbers, findings and
recommendations come from the real scan — the animation is presentation
only, never simulated progress or fake results.
"""
import html as html_mod

from .html_report import build_html_report  # noqa: F401  (kept for callers)
from .json_report import build_json_report

SEV_COLORS = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
              "low": "#2563eb", "info": "#6b7280"}

_CSS = """
body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:20px auto;padding:0 16px;color:#111;background:#0b0b0f;color:#eee}
h1{font-size:24px;color:#f97316} h2{border-bottom:2px solid #f97316;padding-bottom:4px;color:#fff}
a{color:#f97316}
@keyframes sweep{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.12);opacity:.75}}
@keyframes scanline{0%{top:0}100%{top:100%}}
@keyframes fadein{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes ring{from{stroke-dashoffset:283}to{stroke-dashoffset:__OFFSET__}}
.radar{width:120px;height:120px;border-radius:50%;margin:10px 0;position:relative;overflow:hidden;
 background:radial-gradient(circle,#12351f 0%,#0b0b0f 70%);border:2px solid #16a34a}
.radar::before{content:"";position:absolute;inset:0;
 background:conic-gradient(from 0deg,rgba(22,163,74,.9),transparent 90deg);
 animation:sweep 3s linear infinite}
.radar::after{content:"🔍";position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:44px;animation:pulse 2s ease-in-out infinite}
.scanbox{position:relative;overflow:hidden;border:1px solid #333;padding:12px}
.scanbox::after{content:"";position:absolute;left:0;right:0;height:2px;background:#f97316;opacity:.8;animation:scanline 2.5s linear infinite}
table{border-collapse:collapse;width:100%;margin:12px 0}
td,th{border:1px solid #444;padding:6px 8px;text-align:left;font-size:13px;vertical-align:top}
th{background:#f97316;color:#fff}
tbody tr{animation:fadein .5s ease both}
tbody tr:nth-child(1){animation-delay:.1s} tbody tr:nth-child(2){animation-delay:.2s}
tbody tr:nth-child(3){animation-delay:.3s} tbody tr:nth-child(4){animation-delay:.4s}
tbody tr:nth-child(5){animation-delay:.5s} tbody tr:nth-child(6){animation-delay:.6s}
tbody tr:nth-child(7){animation-delay:.7s} tbody tr:nth-child(8){animation-delay:.8s}
.ring{width:140px;height:140px}
.ring circle.bg{fill:none;stroke:#333;stroke-width:12}
.ring circle.fg{fill:none;stroke:__COLOR__;stroke-width:12;stroke-linecap:round;
 stroke-dasharray:283;stroke-dashoffset:283;animation:ring 1.6s ease forwards}
footer{color:#999;font-size:13px;margin-top:24px}
"""


def _esc(v):
    return html_mod.escape(str(v if v is not None else ""))


def build_animated_html_report(scan):
    r = build_json_report(scan)
    lang = scan.get("language", "ar")
    direction = "rtl" if lang == "ar" else "ltr"
    score = r.get("score") or 0
    color = "#16a34a" if score >= 80 else "#ca8a04" if score >= 60 else "#dc2626"
    offset = 283 - int(283 * score / 100)
    css = _CSS.replace("__OFFSET__", str(offset)).replace("__COLOR__", color)
    rows = ""
    for f in r["vulnerabilities"]:
        rows += ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                 "<td>%s</td><td>%s</td></tr>") % (
            _esc(f.get("severity", "")), _esc(f.get("name", "")),
            _esc(f.get("status", "")), _esc(f.get("confidence", "")),
            _esc(f.get("url", "")), _esc(f.get("evidence", ""))[:160])
    recs = "".join("<li>%s</li>" % _esc(x) for x in r["recommendations"])
    dist = r.get("severity_distribution") or {}
    dist_txt = ", ".join("%s=%d" % (k, v) for k, v in dist.items() if v) or "—"
    html = """<!DOCTYPE html><html lang="%s" dir="%s"><head><meta charset="utf-8">
<title>CONAN FRAMEWORK v5.7 — %s</title><style>%s</style></head><body>
<div class="radar"></div>
<h1>🔍 CONAN FRAMEWORK v5.7 — Website Security Report</h1>
<p>Target: <b>%s</b><br>Scanned: %s<br>Duration: %s s<br>
Developer: Hafed Mehdi Salah Eddine — Algeria 🇩🇿 — GitHub: M-salah1</p>
<svg class="ring" viewBox="0 0 100 100"><circle class="bg" cx="50" cy="50" r="45"/>
<circle class="fg" cx="50" cy="50" r="45" transform="rotate(-90 50 50)"/>
<text x="50" y="55" text-anchor="middle" fill="#fff" font-size="20">%d%%</text></svg>
<p>Grade: <b>%s</b> &nbsp; Confidence: %d%% &nbsp; Findings: %s</p>
<div class="scanbox"><h2>Findings</h2>
<table><tr><th>Severity</th><th>Name</th><th>Status</th><th>Confidence</th><th>URL</th><th>Evidence</th></tr>%s</table></div>
<h2>Recommendations</h2><ol>%s</ol>
<footer>CONAN FRAMEWORK v5.7 — Ethical Defender Edition. Passive + authorized-active audit only.
Animated presentation of real results — no simulated findings. No passwords or session values are stored in this report.</footer>
</body></html>""" % (
        lang, direction, _esc(r["target"]), css,
        _esc(r["target"]), _esc(r["scan_timestamp"]), _esc(r["duration_s"]),
        score, _esc(r["grade"]), r.get("confidence") or 0, _esc(dist_txt),
        rows, recs)
    return html


def save_animated_html_report(scan, path):
    data = build_animated_html_report(scan)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return data
