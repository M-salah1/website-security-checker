#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Telegram delivery of the full scan report — optional, user-initiated.

The user provides their own Telegram chat ID and their own bot token
at send time. The token is:
- asked with hidden input (getpass),
- sent only to Telegram's official API (api.telegram.org) as the
  sendMessage endpoint requires,
- NEVER written to any file, NEVER stored in settings or memory,
  NEVER printed and NEVER included in the report itself.

The report contains: the tool name, the developer, a short intro, the
target site, the score/grade, the findings, and the detailed sections.
Long reports are split into chunks (Telegram's 4096-character limit).
"""
import json
import urllib.error
import urllib.request

API_URL = "https://api.telegram.org/bot%s/sendMessage"
LIMIT = 4000

LABELS = {
    "ar": {
        "intro": "فحص دفاعي شامل للمواقع: أمان، ثغرات، هوية النطاق، خوادم ومسارات — بلا استغلال وبلا هجوم.",
        "developer": "المطوّر",
        "target": "الموقع",
        "score": "النتيجة",
        "grade": "التقييم",
        "confidence": "الثقة",
        "findings": "الثغرات والنتائج",
        "identity": "الهوية والموقع",
        "history": "تاريخ النطاق",
        "servers": "الخوادم",
        "paths": "المسارات",
        "api": "الـ API والهندسة العكسية",
        "origin": "الـ IP الحقيقي والأصل",
        "recommendations": "التوصيات",
        "private_report": "تقرير خاص — نتائج فحص كونان",
    },
    "en": {
        "intro": "A complete defensive website audit: security, vulnerabilities, domain identity, servers and paths — no exploitation, no attacks.",
        "developer": "Developer",
        "target": "Target site",
        "score": "Score",
        "grade": "Grade",
        "confidence": "Confidence",
        "findings": "Findings",
        "identity": "Identity & Location",
        "history": "Domain History",
        "servers": "Servers",
        "paths": "Paths",
        "api": "API & Reverse Engineering",
        "origin": "Real IP & Origin",
        "recommendations": "Recommendations",
        "private_report": "Private report — Conan scan results",
    },
    "fr": {
        "intro": "Audit défensif complet de sites web : sécurité, vulnérabilités, identité du domaine, serveurs et chemins — sans exploitation ni attaque.",
        "developer": "Développeur",
        "target": "Site cible",
        "score": "Score",
        "grade": "Note",
        "confidence": "Confiance",
        "findings": "Résultats",
        "identity": "Identité et Localisation",
        "history": "Historique du Domaine",
        "servers": "Serveurs",
        "paths": "Chemins",
        "api": "API et rétro-ingénierie",
        "origin": "IP réelle et origine",
        "recommendations": "Recommandations",
        "private_report": "Rapport privé — résultats de l'analyse Conan",
    },
}


def _short(text, limit=180):
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[:limit - 3] + "..."


def build_telegram_report(scan, lang="ar"):
    """Full detailed report text. Takes only the scan — never a token."""
    lab = LABELS.get(lang, LABELS["en"])
    hist = scan.get("history") or {}
    servers = scan.get("servers") or {}
    origin = scan.get("origin") or {}
    js = scan.get("js_api") or {}
    lines = []
    lines.append("🔍 CONAN FRAMEWORK — %s" % lab["private_report"])
    lines.append("%s: Hafed Mehdi Salah Eddine — GitHub M-salah1 — FOX COMPANY"
                 % lab["developer"])
    lines.append(lab["intro"])
    lines.append("")
    lines.append("🌐 %s: %s" % (lab["target"], scan.get("target")))
    lines.append("📊 %s: %s%%  |  %s: %s  |  %s: %s%%" % (
        lab["score"], scan.get("score"), lab["grade"], scan.get("grade"),
        lab["confidence"], scan.get("confidence")))
    lines.append("")
    lines.append("🚨 %s:" % lab["findings"])
    findings = scan.get("findings") or []
    if not findings:
        lines.append("—")
    for f in findings[:12]:
        lines.append("[%s] %s — %s" % (f["severity"].upper(), f["name"],
                                       _short(f.get("evidence", ""), 120)))
    lines.append("")
    lines.append("🪪 %s: %s | %s | %s" % (
        lab["identity"], hist.get("domain"),
        hist.get("country") or "UNKNOWN", hist.get("hosting_org") or "UNKNOWN"))
    lines.append("📜 %s: %s | %s | %s" % (
        lab["history"], hist.get("created") or "UNKNOWN",
        hist.get("registrar") or "UNKNOWN",
        hist.get("earliest_certificate") or "UNKNOWN"))
    lines.append("🖥 %s: %s | IP: %s" % (
        lab["servers"], servers.get("server_header") or "UNKNOWN",
        ", ".join(servers.get("ips") or ["UNKNOWN"])))
    lines.append("🌍 %s: %s | %s: %s" % (
        lab["origin"], ", ".join(origin.get("ips") or ["UNKNOWN"]),
        "CDN", "yes" if origin.get("cdn_detected") else "no"))
    public_paths = [d["path"] for d in (scan.get("deep_paths") or [])
                    if isinstance(d, dict) and d.get("category") == "PUBLIC"][:10]
    lines.append("🛣 %s: %s" % (lab["paths"], ", ".join(public_paths) or "-"))
    lines.append("🧩 %s: %s" % (
        lab["api"], ", ".join((js.get("endpoints") or [])[:8]) or "-"))
    recs = scan.get("recommendations") or []
    if recs:
        lines.append("")
        lines.append("✅ %s:" % lab["recommendations"])
        for fix in recs[:5]:
            lines.append("• %s" % _short(fix, 160))
    return "\n".join(lines)


def split_message(text, limit=LIMIT):
    """Split into chunks no longer than `limit` characters.

    Splits on newlines first; a single line longer than the limit is
    cut into limit-sized pieces (Telegram rejects >4096-char messages).
    """
    chunks, current = [], ""
    for line in (text or "").split("\n"):
        while len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]
        if len(current) + len(line) + 1 > limit and current:
            chunks.append(current)
            current = ""
        current += line + "\n"
    if current.strip():
        chunks.append(current)
    return chunks or [""]


def _post(url, payload, timeout=15):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode(errors="ignore"))


def send_telegram(token, chat_id, text, timeout=15):
    """Send the report (chunked). Returns (sent_chunks, error_or_None).

    The token is used only inside the Telegram API URL for this call.
    """
    if not token or not str(token).strip() or not chat_id:
        return 0, "missing token or chat id"
    sent = 0
    for chunk in split_message(text):
        try:
            out = _post(API_URL % str(token).strip(),
                        {"chat_id": str(chat_id).strip(), "text": chunk},
                        timeout)
        except Exception as exc:
            return sent, str(exc)
        if not out.get("ok"):
            return sent, str(out.get("description") or "Telegram error")
        sent += 1
    return sent, None
