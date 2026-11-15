#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
المحقق كونان - Conan Detective v2.3
واجهة بأسلوب Metasploit + 3 لغات (English / Français / العربية RTL)
أداة فحص أمان دفاعية سلبية (Passive) لمواقع الويب - Termux
Python standard library فقط، بدون تثبيت مكتبات.
المطور: Hafed Mehdi Salah Eddine — الجزائر

ماذا تفحص؟
  1. DNS والعنوان IP والـ Reverse DNS
  2. WHOIS العام: المسجل، تاريخ الإنشاء والانتهاء، خوادم الأسماء،
     وبيانات المالك الظاهرة علناً فقط (إذا نشرها المسجل)
  3. HTTPS وشهادة TLS: الصلاحية، الجهة المصدرة، الإصدار
  4. رؤوس الأمان: HSTS, CSP, X-Frame-Options, nosniff, Referrer, Permissions
  5. الكوكيز: Secure + HttpOnly + SameSite
  6. كشف إصدار الخادم والتقنية الظاهرة في الرؤوس و meta generator
  7. ملفات عامة: robots.txt / sitemap.xml / security.txt
  8. محتوى مختلط http داخل صفحة https

ماذا لا تفعل؟
  لا تحاول استغلال أي ثغرة، لا ترسل حمولات SQLi / XSS،
  لا تجرب كلمات مرور، لا تبحث عن لوحات تحكم بالقوة،
  ولا تسجل الدخول أو تتجاوز أي حماية.
  الثغرات هنا تعني: إعدادات ناقصة ظاهرة علناً + توصية إصلاح،
  وليست إثبات استغلال.

الاستعمال - استعملها فقط على موقعك الخاص أو موقع عندك إذن كتابي لفحصه:
    python3 conan.py                        # وحدة تحكم بأسلوب Metasploit: conan >
    python3 conan.py --lang en             # English
    python3 conan.py --lang fr             # Français
    python3 conan.py --lang ar             # العربية (من اليمين لليسار)
    python3 conan.py https://example.com
    python3 conan.py https://example.com --lang en --json
    python3 conan.py https://example.com -o تقرير.json
    python3 conan.py --about               # عن الأداة فقط
    python3 conan.py --developer            # عن المطور فقط
أوامر وحدة التحكم: help | scan <url> | set target <url> | run | about |
    developer | lang <en|fr|ar> | banner | clear | exit
"""

import argparse
import datetime
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


VERSION = "2.3"
TOOL_NAME = "المحقق كونان - Conan Detective"
DEVELOPER_NAME = "Hafed Mehdi Salah Eddine"
DEVELOPER_COUNTRY = "الجزائر 🇩🇿"
DEVELOPER_GITHUB = "M-salah1"
SYSTEM_TAGLINE = "نظام فحص قوي — دقيق، سريع، ويعمل بقوة"

# ---------- اللغات: English / Français / العربية (RTL) ----------
LANG = "ar"  # اللغة الحالية، تتغير بأمر lang أو --lang
RLM = "\u200f"  # Right-to-Left Mark: يجعل السطر العربي يبدأ من اليمين
LRI = "\u2066"  # Left-to-Right Isolate, PDI = \u2069 لإغلاقه

STR = {
    "tagline": {
        "en": "Powerful website security audit system — precise, fast, strong",
        "fr": "Système puissant d'audit de sécurité web — précis, rapide, fort",
        "ar": "نظام فحص قوي — دقيق، سريع، ويعمل بقوة",
    },
    "subtitle": {
        "en": "Powerful website security audit system",
        "fr": "Système puissant d'audit de sécurité web",
        "ar": "نظام فحص أمان قوي لمواقع الويب",
    },
    "version": {"en": "Version", "fr": "Version", "ar": "الإصدار"},
    "developer": {"en": "Developer", "fr": "Développeur", "ar": "المطور"},
    "works_strong": {"en": "works strong", "fr": "travaille fort", "ar": "يعمل بقوة"},
    "checks_line": {
        "en": "12 passive checks  •  0 exploits  •  3 languages",
        "fr": "12 vérifications passives  •  0 exploit  •  3 langues",
        "ar": "12 فحصاً سلبياً  •  0 استغلال  •  3 لغات",
    },
    "type_help": {
        "en": "Type 'help' to see commands.",
        "fr": "Tapez 'help' pour voir les commandes.",
        "ar": "اكتب 'help' لعرض الأوامر.",
    },
    "choose_lang": {
        "en": "Choose language",
        "fr": "Choisissez la langue",
        "ar": "اختر اللغة",
    },
    "lang_set": {
        "en": "Language set to English.",
        "fr": "Langue définie sur Français.",
        "ar": "تم تعيين اللغة على العربية.",
    },
    "lang_bad": {
        "en": "Unknown language. Use: en, fr, ar.",
        "fr": "Langue inconnue. Utilisez : en, fr, ar.",
        "ar": "لغة غير معروفة. استعمل: en أو fr أو ar.",
    },
    "help_title": {
        "en": "Commands",
        "fr": "Commandes",
        "ar": "الأوامر",
    },
    "enter_url": {
        "en": "Enter website URL (e.g. https://example.com): ",
        "fr": "Entrez l'URL du site (ex. https://example.com) : ",
        "ar": "ادخل رابط الموقع (مثال: https://example.com): ",
    },
    "scanning": {"en": "Scanning... ", "fr": "Analyse en cours... ", "ar": "جارٍ الفحص... 🔎"},
    "no_url": {"en": "No URL entered.", "fr": "Aucune URL saisie.", "ar": "لم تدخل رابطاً."},
    "no_target": {
        "en": "No target set. Use: scan <url>  or  set target <url>  then run",
        "fr": "Aucune cible. Utilisez : scan <url>  ou  set target <url>  puis run",
        "ar": "لا يوجد هدف. استعمل: scan <url>  أو  set target <url>  ثم run",
    },
    "target_set": {"en": "Target set to: ", "fr": "Cible définie : ", "ar": "تم تعيين الهدف: "},
    "save_q": {
        "en": "Save report as JSON? (y/N): ",
        "fr": "Enregistrer le rapport en JSON ? (o/N) : ",
        "ar": "هل تريد حفظ التقرير JSON؟ (y/N): ",
    },
    "saved": {"en": "Saved to: ", "fr": "Enregistré dans : ", "ar": "تم الحفظ في: "},
    "goodbye": {"en": "Goodbye", "fr": "Au revoir", "ar": "مع السلامة 👋"},
    "unknown_cmd": {
        "en": "Unknown command. Type 'help'.",
        "fr": "Commande inconnue. Tapez 'help'.",
        "ar": "أمر غير معروف، اكتب 'help'.",
    },
    "about_tool_title": {"en": "About the tool", "fr": "À propos de l'outil", "ar": "عن الأداة"},
    "about_dev_title": {"en": "About the developer", "fr": "À propos du développeur", "ar": "عن المطور"},
    "country": {"en": "Country", "fr": "Pays", "ar": "البلد"},
    "project": {"en": "Project", "fr": "Projet", "ar": "المشروع"},
    "report_title": {
        "en": "Website security audit report",
        "fr": "Rapport d'audit de sécurité du site",
        "ar": "تقرير فحص أمان الموقع",
    },
    "owner_section": {
        "en": "Owner & domain info (public WHOIS)",
        "fr": "Infos propriétaire & domaine (WHOIS public)",
        "ar": "معلومات المالك والنطاق (WHOIS عام)",
    },
    "dns_section": {"en": "DNS & network", "fr": "DNS & réseau", "ar": "DNS والشبكة"},
    "checks_section": {"en": "Check results", "fr": "Résultats des vérifications", "ar": "نتائج الفحص"},
    "notes_section": {"en": "Notes", "fr": "Remarques", "ar": "ملاحظات"},
    "vulns_section": {
        "en": "Weaknesses / vulnerabilities",
        "fr": "Faiblesses / vulnérabilités",
        "ar": "الثغرات / نقاط الضعف",
    },
    "no_vulns": {
        "en": "No visible weakness in this passive audit. Excellent!",
        "fr": "Aucune faiblesse visible dans cet audit passif. Excellent !",
        "ar": "لا توجد نقاط ضعف ظاهرة في هذا الفحص السلبي. ممتاز!",
    },
    "summary": {"en": "Summary", "fr": "Résumé", "ar": "الملخص"},
    "score": {"en": "Security score", "fr": "Score de sécurité", "ar": "نسبة الأمان"},
    "grade": {"en": "Grade", "fr": "Note", "ar": "التقييم"},
    "top_fixes": {"en": "Top 3 fixes:", "fr": "Top 3 correctifs :", "ar": "أول 3 إصلاحات:"},
    "warning": {
        "en": "Note: passive audit of visible settings only, not a full security guarantee.",
        "fr": "Note : audit passif des réglages visibles seulement, pas une garantie complète.",
        "ar": "تنبيه: هذا فحص سلبي للإعدادات الظاهرة فقط، وليس ضماناً كاملاً للأمان.",
    },
    "details": {"en": "Details:", "fr": "Détails :", "ar": "التفاصيل:"},
    "fix": {"en": "Fix:", "fr": "Correctif :", "ar": "الإصلاح:"},
    "domain": {"en": "Domain", "fr": "Domaine", "ar": "النطاق"},
    "registrar": {"en": "Registrar", "fr": "Bureau d'enregistrement", "ar": "المسجل"},
    "created": {"en": "Created", "fr": "Créé le", "ar": "تاريخ الإنشاء"},
    "expires": {"en": "Expires", "fr": "Expire le", "ar": "تاريخ الانتهاء"},
    "org": {"en": "Registered organisation", "fr": "Organisation enregistrée", "ar": "المنظمة المسجلة"},
    "nameservers": {"en": "Name servers", "fr": "Serveurs de noms", "ar": "خوادم الأسماء"},
    "hidden": {"en": "hidden / not disclosed", "fr": "masqué / non divulgué", "ar": "محجوبة للخصوصية أو غير معلنة"},
    "final_url": {"en": "Final URL", "fr": "URL finale", "ar": "الوجهة النهائية"},
    "date": {"en": "Date (UTC)", "fr": "Date (UTC)", "ar": "التاريخ (UTC)"},
    "dnssec_section": {"en": "DNSSEC", "fr": "DNSSEC", "ar": "DNSSEC"},
    "tech_section": {"en": "Technologies detected (passive)", "fr": "Technologies détectées (passif)", "ar": "التقنيات المكتشفة (سلبياً)"},
    "robots_section": {"en": "robots.txt & sitemap.xml analysis", "fr": "Analyse robots.txt & sitemap.xml", "ar": "تحليل robots.txt و sitemap.xml"},
    "cookies_section": {"en": "Cookies (values masked)", "fr": "Cookies (valeurs masquées)", "ar": "الكوكيز (القيم مخفية)"},
    "comparison_section": {"en": "Comparison with previous scan", "fr": "Comparaison avec le scan précédent", "ar": "مقارنة مع الفحص السابق"},
    "prev_score": {"en": "Previous score", "fr": "Score précédent", "ar": "النتيجة السابقة"},
    "score_change": {"en": "Change", "fr": "Évolution", "ar": "التغيّر"},
    "new_vulns": {"en": "New weaknesses", "fr": "Nouvelles faiblesses", "ar": "ثغرات جديدة"},
    "fixed_vulns": {"en": "Fixed weaknesses", "fr": "Faiblesses corrigées", "ar": "ثغرات تم إصلاحها"},
    "no_previous": {"en": "No previous scan for this domain — this is the baseline.", "fr": "Aucun scan précédent pour ce domaine — c'est la référence.", "ar": "لا يوجد فحص سابق لهذا النطاق — هذا هو الأساس للمقارنة."},
    "save_fmt": {"en": "Save report? (json/html/both/no): ", "fr": "Enregistrer le rapport ? (json/html/both/no) : ", "ar": "حفظ التقرير؟ (json/html/both/no): "},
    "cipher": {"en": "Cipher", "fr": "Chiffrement", "ar": "التشفير"},
    "sans": {"en": "SANs", "fr": "SAN", "ar": "النطاقات في الشهادة"},
}

SEV_TR = {
    "عالي": {"en": "HIGH", "fr": "ÉLEVÉ", "ar": "عالي"},
    "متوسط": {"en": "MEDIUM", "fr": "MOYEN", "ar": "متوسط"},
    "منخفض": {"en": "LOW", "fr": "FAIBLE", "ar": "منخفض"},
}

CHECK_TR = {
    "HTTPS مفعل": {"en": "HTTPS enabled", "fr": "HTTPS activé"},
    "شهادة TLS صالحة": {"en": "Valid TLS certificate", "fr": "Certificat TLS valide"},
    "Strict-Transport-Security (HSTS)": {"en": "Strict-Transport-Security (HSTS)", "fr": "Strict-Transport-Security (HSTS)"},
    "Content-Security-Policy": {"en": "Content-Security-Policy", "fr": "Content-Security-Policy"},
    "حماية من التضمين في إطارات (X-Frame-Options)": {"en": "Frame embedding protection (X-Frame-Options)", "fr": "Protection contre l'intégration (X-Frame-Options)"},
    "X-Content-Type-Options: nosniff": {"en": "X-Content-Type-Options: nosniff", "fr": "X-Content-Type-Options: nosniff"},
    "Referrer-Policy": {"en": "Referrer-Policy", "fr": "Referrer-Policy"},
    "Permissions-Policy": {"en": "Permissions-Policy", "fr": "Permissions-Policy"},
    "ملفات تعريف الارتباط آمنة (Secure + HttpOnly)": {"en": "Secure cookies (Secure + HttpOnly)", "fr": "Cookies sécurisés (Secure + HttpOnly)"},
    "ملفات تعريف الارتباط آمنة": {"en": "Secure cookies", "fr": "Cookies sécurisés"},
    "HSTS": {"en": "HSTS", "fr": "HSTS"},
    "بدون محتوى مختلط": {"en": "No mixed content", "fr": "Aucun contenu mixte"},
    "Cross-Origin-Opener-Policy": {"en": "Cross-Origin-Opener-Policy", "fr": "Cross-Origin-Opener-Policy"},
    "Cross-Origin-Embedder-Policy": {"en": "Cross-Origin-Embedder-Policy", "fr": "Cross-Origin-Embedder-Policy"},
}

VULN_TR = {
    "تعذر حل DNS": ("DNS resolution failed", "Échec de résolution DNS", "تحقق من إعدادات DNS والنطاق", "Check DNS settings and the domain", "Vérifiez les réglages DNS et le domaine"),
    "شهادة TLS تنتهي قريباً": ("TLS certificate expiring soon", "Certificat TLS expirant bientôt", "جدد الشهادة قبل الانتهاء", "Renew the certificate before expiry", "Renouvelez le certificat avant expiration"),
    "شهادة TLS منتهية": ("TLS certificate expired", "Certificat TLS expiré", "جدد الشهادة فوراً", "Renew the certificate immediately", "Renouvelez le certificat immédiatement"),
    "تعذر التحقق من شهادة TLS": ("Could not verify TLS certificate", "Impossible de vérifier le certificat TLS", "تحقق من تثبيت الشهادة وسلسلتها", "Check the certificate installation and chain", "Vérifiez l'installation du certificat et sa chaîne"),
    "الموقع يعمل بدون HTTPS": ("Site running without HTTPS", "Site sans HTTPS", "فعّل HTTPS وأعد توجيه http إلى https", "Enable HTTPS and redirect http to https", "Activez HTTPS et redirigez http vers https"),
    "تعذر الوصول للموقع": ("Could not reach the site", "Impossible d'atteindre le site", "تحقق أن الموقع يعمل والرابط صحيح", "Check that the site is up and the URL is correct", "Vérifiez que le site fonctionne et que l'URL est correcte"),
    "غياب HSTS": ("Missing HSTS", "HSTS manquant", "أضف Strict-Transport-Security: max-age=31536000; includeSubDomains", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains", "Ajoutez Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "غياب Content-Security-Policy": ("Missing Content-Security-Policy", "Content-Security-Policy manquant", "أضف CSP مناسباً لموقعك، ابدأ بـ default-src 'self'", "Add a suitable CSP, start with default-src 'self'", "Ajoutez une CSP adaptée, commencez par default-src 'self'"),
    "CSP ضعيف": ("Weak CSP", "CSP faible", "أزل unsafe-inline/eval واستعمل nonce أو hash", "Remove unsafe-inline/eval, use nonce or hash", "Retirez unsafe-inline/eval, utilisez nonce ou hash"),
    "خطر Clickjacking": ("Clickjacking risk", "Risque de clickjacking", "أضف X-Frame-Options: DENY أو SAMEORIGIN", "Add X-Frame-Options: DENY or SAMEORIGIN", "Ajoutez X-Frame-Options: DENY ou SAMEORIGIN"),
    "غياب nosniff": ("Missing nosniff", "nosniff manquant", "أضف X-Content-Type-Options: nosniff", "Add X-Content-Type-Options: nosniff", "Ajoutez X-Content-Type-Options: nosniff"),
    "غياب Referrer-Policy": ("Missing Referrer-Policy", "Referrer-Policy manquant", "أضف Referrer-Policy مناسباً", "Add a suitable Referrer-Policy", "Ajoutez un Referrer-Policy adapté"),
    "غياب Permissions-Policy": ("Missing Permissions-Policy", "Permissions-Policy manquant", "أضف Permissions-Policy مناسباً", "Add a suitable Permissions-Policy", "Ajoutez un Permissions-Policy adapté"),
    "الخادم يكشف إصداره": ("Server discloses its version", "Le serveur révèle sa version", "أخفِ رقم الإصدار من رأس Server", "Hide the version number from the Server header", "Masquez le numéro de version de l'en-tête Server"),
    "كشف التقنية X-Powered-By": ("Technology disclosed (X-Powered-By)", "Technologie révélée (X-Powered-By)", "أزل رأس X-Powered-By", "Remove the X-Powered-By header", "Retirez l'en-tête X-Powered-By"),
    "كوكيز بدون حماية كاملة": ("Cookies without full protection", "Cookies sans protection complète", "أضف Secure و HttpOnly و SameSite=Lax للكوكيز", "Add Secure, HttpOnly and SameSite=Lax to cookies", "Ajoutez Secure, HttpOnly et SameSite=Lax aux cookies"),
    "كوكيز بدون SameSite": ("Cookies without SameSite", "Cookies sans SameSite", "أضف SameSite=Lax أو Strict", "Add SameSite=Lax or Strict", "Ajoutez SameSite=Lax ou Strict"),
    "محتوى مختلط Mixed Content": ("Mixed content", "Contenu mixte", "حوّل كل الموارد إلى https أو روابط نسبية", "Move all resources to https or relative URLs", "Passez toutes les ressources en https ou en URL relatives"),
    "لا يوجد security.txt": ("No security.txt", "Pas de security.txt", "أضف /.well-known/security.txt مع بريد للتواصل الأمني", "Add /.well-known/security.txt with a security contact email", "Ajoutez /.well-known/security.txt avec un e-mail de contact sécurité"),
    "DNSSEC غير مفعّل": ("DNSSEC not enabled", "DNSSEC non activé", "فعّل DNSSEC عند مسجل النطاق", "Enable DNSSEC at your domain registrar", "Activez DNSSEC chez votre bureau d'enregistrement"),
    "HSTS max-age قصير": ("HSTS max-age too short", "HSTS max-age trop court", "ارفع max-age إلى 31536000 على الأقل", "Raise max-age to at least 31536000", "Augmentez max-age à au moins 31536000"),
    "CSP يسمح بـ wildcard": ("CSP allows wildcard sources", "La CSP autorise les sources wildcard", "قيّد script-src بنطاقات محددة بدل *", "Restrict script-src to specific domains instead of *", "Restreignez script-src à des domaines précis au lieu de *"),
    "إصدار TLS قديم وغير آمن": ("Old insecure TLS version", "Ancienne version TLS non sécurisée", "فعّل TLS 1.2 كحد أدنى ويفضل 1.3 فقط", "Enable TLS 1.2 minimum, preferably TLS 1.3 only", "Activez TLS 1.2 minimum, de préférence TLS 1.3 uniquement"),
    "تشفير TLS ضعيف": ("Weak TLS cipher", "Chiffrement TLS faible", "عطّل الشفرات الضعيفة (RC4/3DES/DES) في الخادم", "Disable weak ciphers (RC4/3DES/DES) on the server", "Désactivez les chiffrements faibles (RC4/3DES/DES) sur le serveur"),
    "غياب Cross-Origin-Opener-Policy": ("Missing Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy manquant", "أضف Cross-Origin-Opener-Policy: same-origin", "Add Cross-Origin-Opener-Policy: same-origin", "Ajoutez Cross-Origin-Opener-Policy: same-origin"),
    "غياب Cross-Origin-Embedder-Policy": ("Missing Cross-Origin-Embedder-Policy", "Cross-Origin-Embedder-Policy manquant", "أضف Cross-Origin-Embedder-Policy: require-corp", "Add Cross-Origin-Embedder-Policy: require-corp", "Ajoutez Cross-Origin-Embedder-Policy: require-corp"),
    "robots.txt يكشف مسارات حساسة": ("robots.txt exposes sensitive paths", "robots.txt expose des chemins sensibles", "أزل المسارات الحساسة من robots.txt", "Remove sensitive paths from robots.txt", "Retirez les chemins sensibles de robots.txt"),
}


def t(key):
    """ترجمة مفتاح واجهة حسب اللغة الحالية (افتراضياً العربية)."""
    return STR.get(key, {}).get(LANG, STR.get(key, {}).get("ar", key))


def set_lang(code):
    global LANG
    code = (code or "").strip().lower()
    if code in ("en", "english"):
        LANG = "en"
    elif code in ("fr", "francais", "français"):
        LANG = "fr"
    elif code in ("ar", "arabic", "العربية", "عربي"):
        LANG = "ar"
    else:
        return False
    return True


def out(line=""):
    """طباعة سطر: في العربية يبدأ بعلامة RTL حتى يظهر من اليمين لليسار."""
    if LANG == "ar" and line:
        print(RLM + line)
    else:
        print(line)


def ar_align(line, width=56):
    """في العربية: محاذاة لليمين لمحاكاة اتجاه RTL في الطرفية."""
    if LANG == "ar":
        return line.rjust(width)
    return line


# ألوان ANSI (تعمل في Termux). تُلغى تلقائياً مع --json.
_USE_COLOR = sys.stdout.isatty()


def _c(code):
    return "\033[%sm" % code if _USE_COLOR else ""


C_BOLD = lambda s: _c("1") + s + _c("0")  # noqa: E731
C_CYAN = lambda s: _c("96") + s + _c("0")  # noqa: E731
C_GREEN = lambda s: _c("92") + s + _c("0")  # noqa: E731
C_YELLOW = lambda s: _c("93") + s + _c("0")  # noqa: E731
C_RED = lambda s: _c("91") + s + _c("0")  # noqa: E731


def show_banner():
    # بانر بأسلوب Metasploit: إطار + عدد الفحوصات + المطور
    print(C_CYAN("=" * 60))
    print(C_BOLD("   ____ ___  _   _    _    _   _"))
    print(C_BOLD("  / ___/ _ \\| \\ | |  / \\  | \\ | |"))
    print(C_BOLD(" | |  | | | |  \\| | / _ \\ |  \\| |   DETECTIVE"))
    print(C_BOLD(" | |__| |_| | |\\  |/ ___ \\| |\\  |   المحقق كونان"))
    print(C_BOLD("  \\____\\___/|_| \\_/_/   \\_\\_| \\_|"))
    print(C_CYAN("   Conan Framework v" + VERSION + "  •  " + t("subtitle")))
    print("   " + t("checks_line"))
    print(C_CYAN("=" * 60))
    out("   " + t("developer") + ": " + DEVELOPER_NAME + "  •  " + DEVELOPER_COUNTRY)
    out("   GitHub: " + DEVELOPER_GITHUB + "  •  " + t("works_strong") + " 💪")
    print(C_CYAN("-" * 60))
    out("   " + t("type_help"))


ABOUT_TOOL = {
    "en": [
        "Defensive passive security audit system, running in Termux",
        "with Python only — no external library.",
        "",
        "What it does:",
        "  1. Checks DNS, IP and Reverse DNS",
        "  2. Fetches public WHOIS: registrar, dates, name servers",
        "     and publicly disclosed owner data only",
        "  3. Checks HTTPS, TLS certificate, security headers, cookies",
        "  4. Detects server version, visible tech and public files",
        "  5. Gives a summary, a score out of 100, a grade, and a list",
        "     of weaknesses (missing settings) ranked by severity,",
        "     each with a fix.",
        "",
        "What it does NOT do:",
        "  No exploitation, no payloads, no password guessing,",
        "  no login and no bypassing any protection.",
        "",
        "Golden rule: use it only on your own site",
        "or on a site you have written permission to audit.",
    ],
    "fr": [
        "Système d'audit de sécurité défensif et passif, sous Termux",
        "avec Python seulement — aucune bibliothèque externe.",
        "",
        "Ce qu'il fait :",
        "  1. Vérifie DNS, IP et Reverse DNS",
        "  2. Récupère le WHOIS public : bureau, dates, serveurs de noms",
        "     et données du propriétaire divulguées publiquement seulement",
        "  3. Vérifie HTTPS, certificat TLS, en-têtes de sécurité, cookies",
        "  4. Détecte la version du serveur, la tech visible et les fichiers publics",
        "  5. Donne un résumé, un score sur 100, une note, et une liste",
        "     de faiblesses (réglages manquants) classées par gravité,",
        "     chacune avec un correctif.",
        "",
        "Ce qu'il ne fait PAS :",
        "  Aucun exploit, aucune charge utile, aucune devinette de mot de passe,",
        "  aucune connexion et aucun contournement de protection.",
        "",
        "Règle d'or : utilisez-le uniquement sur votre propre site",
        "ou sur un site avec une autorisation écrite d'audit.",
    ],
    "ar": [
        "نظام فحص أمان دفاعي سلبي (Passive) يعمل في Termux",
        "ببايثون فقط، بدون أي مكتبة خارجية.",
        "",
        "ماذا يفعل؟",
        "  1. يفحص DNS و IP و Reverse DNS",
        "  2. يجلب WHOIS العام: المسجل وتواريخ النطاق وخوادم الأسماء",
        "     وبيانات المالك الظاهرة علناً فقط",
        "  3. يفحص HTTPS وشهادة TLS والرؤوس الأمنية والكوكيز",
        "  4. يكشف إصدار الخادم والتقنية الظاهرة والملفات العامة",
        "  5. يعطيك ملخصاً ونسبة من 100 وتقييماً، وقائمة ثغرات",
        "     (إعدادات ناقصة) مرتبة حسب الخطورة مع إصلاح لكل واحدة",
        "",
        "ماذا لا يفعل؟",
        "  لا يستغل أي ثغرة، لا يرسل حمولات، لا يجرب كلمات مرور،",
        "  ولا يسجل الدخول أو يتجاوز أي حماية.",
        "",
        "القاعدة الذهبية: استعمله فقط على موقعك الخاص",
        "أو موقع عندك إذن كتابي لفحصه.",
    ],
}

ABOUT_DEV = {
    "en": [
        "Name: " + DEVELOPER_NAME,
        "Country: Algeria 🇩🇿",
        "GitHub: " + DEVELOPER_GITHUB,
        "Project: " + TOOL_NAME + " v" + VERSION,
        "",
        "A developer from Algeria, works strong 💪",
        "He builds practical tools that really work in Termux,",
        "with clean code, no complexity and no false promises:",
        "what works is said to work, what does not is said honestly.",
    ],
    "fr": [
        "Nom : " + DEVELOPER_NAME,
        "Pays : Algérie 🇩🇿",
        "GitHub : " + DEVELOPER_GITHUB,
        "Projet : " + TOOL_NAME + " v" + VERSION,
        "",
        "Un développeur d'Algérie, travaille fort 💪",
        "Il construit des outils pratiques qui fonctionnent vraiment sous Termux,",
        "avec un code propre, sans complexité et sans fausses promesses :",
        "ce qui fonctionne est dit fonctionner, sinon c'est dit honnêtement.",
    ],
    "ar": [
        "الاسم: " + DEVELOPER_NAME,
        "البلد: الجزائر 🇩🇿",
        "GitHub: " + DEVELOPER_GITHUB,
        "المشروع: " + TOOL_NAME + " v" + VERSION,
        "",
        "مطور من الجزائر، يعمل بقوة 💪",
        "يبني أدوات عملية تشتغل فعلاً في Termux،",
        "بكود نظيف، وبدون تعقيد، وبدون وعود وهمية:",
        "ما يشتغل يقال إنه يشتغل، وما لا يشتغل يقال بصراحة.",
    ],
}


def show_about_tool():
    print("\n" + "=" * 60)
    out("📖 " + t("about_tool_title") + " — " + TOOL_NAME + " v" + VERSION)
    print("=" * 60)
    for line in ABOUT_TOOL.get(LANG, ABOUT_TOOL["ar"]):
        out(line)
    print("=" * 60)


def show_about_developer():
    print("\n" + "=" * 60)
    out("👨‍💻 " + t("about_dev_title"))
    print("=" * 60)
    for line in ABOUT_DEV.get(LANG, ABOUT_DEV["ar"]):
        out(line)
    print("=" * 60)


def choose_language():
    """اختيار اللغة عند البدء: 1 English / 2 Français / 3 العربية (افتراضي)."""
    print("\n" + "=" * 60)
    print("  Choose language  •  Choisissez la langue  •  اختر اللغة")
    print("  [1] English")
    print("  [2] Français")
    print("  [3] العربية  (RTL — من اليمين لليسار)")
    print("=" * 60)
    try:
        choice = input("  [1/2/3] (default 3): ").strip()
    except (EOFError, KeyboardInterrupt):
        return
    if choice == "1":
        set_lang("en")
    elif choice == "2":
        set_lang("fr")
    else:
        set_lang("ar")


def show_help():
    print("\n" + "=" * 60)
    out("📖 " + t("help_title") + " — conan >")
    print("=" * 60)
    cmds = {
        "en": [
            "  scan <url>        Scan a website (e.g. scan https://example.com)",
            "  set target <url>  Set the target, then type: run",
            "  run               Scan the current target",
            "  about             About the tool",
            "  developer         About the developer",
            "  lang <en|fr|ar>   Switch language",
            "  history           List previous scans",
            "  export <json|html>  Export the last report",
            "  whois <domain>    Public WHOIS for a domain",
            "  dns <domain>      DNS + DNSSEC for a domain",
            "  banner            Show the banner again",
            "  clear             Clear the screen",
            "  help              Show this help",
            "  exit / quit       Exit the console",
        ],
        "fr": [
            "  scan <url>        Analyser un site (ex. scan https://example.com)",
            "  set target <url>  Définir la cible, puis tapez : run",
            "  run               Analyser la cible actuelle",
            "  about             À propos de l'outil",
            "  developer         À propos du développeur",
            "  lang <en|fr|ar>   Changer de langue",
            "  history           Lister les scans précédents",
            "  export <json|html>  Exporter le dernier rapport",
            "  whois <domaine>   WHOIS public d'un domaine",
            "  dns <domaine>     DNS + DNSSEC d'un domaine",
            "  banner            Réafficher la bannière",
            "  clear             Effacer l'écran",
            "  help              Afficher cette aide",
            "  exit / quit       Quitter la console",
        ],
        "ar": [
            "  scan <url>        فحص موقع (مثال: scan https://example.com)",
            "  set target <url>  تعيين الهدف، ثم اكتب: run",
            "  run               فحص الهدف الحالي",
            "  about             عن الأداة",
            "  developer         عن المطور",
            "  lang <en|fr|ar>   تغيير اللغة",
            "  history           عرض الفحوصات السابقة",
            "  export <json|html>  تصدير آخر تقرير",
            "  whois <domain>    WHOIS عام لنطاق",
            "  dns <domain>      DNS و DNSSEC لنطاق",
            "  banner            عرض البانر من جديد",
            "  clear             مسح الشاشة",
            "  help              عرض هذه المساعدة",
            "  exit / quit       الخروج من وحدة التحكم",
        ],
    }
    for line in cmds.get(LANG, cmds["ar"]):
        out(line)
    print("=" * 60)


LAST_REPORT = None


def _do_scan(raw):
    global LAST_REPORT
    if not raw:
        out(t("no_url"))
        return
    out(t("scanning"))
    report = run_check(raw)
    LAST_REPORT = report
    print_report(report)
    try:
        save = input(t("save_fmt")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        save = ""
    if save in ("json", "both"):
        fname = "conan-report.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        out(t("saved") + fname)
    if save in ("html", "both"):
        fname = "conan-report.html"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(generate_html_report(report))
        out(t("saved") + fname)


def msf_console():
    """وحدة تحكم بأسلوب Metasploit: موجه conan > وأوامر نصية."""
    target = ""
    show_banner()
    while True:
        try:
            line = input("\n" + C_RED("conan") + " > ").strip()
        except (EOFError, KeyboardInterrupt):
            out("\n" + t("goodbye"))
            return 0
        if not line:
            continue
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("exit", "quit", "q"):
            out(t("goodbye") + " — " + TOOL_NAME)
            return 0
        if cmd in ("help", "?", "h"):
            show_help()
        elif cmd == "banner":
            show_banner()
        elif cmd == "clear":
            print("\033[2J\033[H", end="")
            show_banner()
        elif cmd in ("version", "ver"):
            out(TOOL_NAME + " v" + VERSION)
        elif cmd == "about":
            show_about_tool()
        elif cmd in ("developer", "author", "dev"):
            show_about_developer()
        elif cmd in ("lang", "language"):
            if set_lang(arg):
                out(t("lang_set"))
                show_banner()
            else:
                out(t("lang_bad"))
        elif cmd in ("scan", "check"):
            _do_scan(arg)
        elif cmd == "set":
            sub = arg.split(None, 1)
            if len(sub) == 2 and sub[0].lower() in ("target", "url"):
                target = sub[1].strip()
                out(t("target_set") + target)
            else:
                out(t("unknown_cmd"))
        elif cmd == "run":
            if not target:
                out(t("no_target"))
            else:
                _do_scan(target)
        elif cmd == "history":
            hist = load_history()
            if not hist:
                out(t("no_previous"))
            for e in hist[-10:]:
                out(" - %s | %s | %d%% %s | %s" % (e.get("checked_at_utc", ""), e.get("domain", ""), e.get("score", 0), e.get("grade", ""), e.get("target", "")))
        elif cmd == "export":
            if LAST_REPORT is None:
                out(t("no_target"))
            else:
                fmt = (arg or "json").lower()
                if fmt in ("json", "both"):
                    with open("conan-report.json", "w", encoding="utf-8") as f:
                        json.dump(LAST_REPORT, f, ensure_ascii=False, indent=2)
                    out(t("saved") + "conan-report.json")
                if fmt in ("html", "both"):
                    with open("conan-report.html", "w", encoding="utf-8") as f:
                        f.write(generate_html_report(LAST_REPORT))
                    out(t("saved") + "conan-report.html")
        elif cmd == "whois":
            if not arg:
                out(t("no_url"))
            else:
                w = get_whois(registrable_domain(arg))
                out(t("domain") + ": " + w["domain"])
                out(t("registrar") + ": " + (w["registrar"] or t("hidden")))
                out(t("created") + ": " + (w["created"] or "-"))
                out(t("expires") + ": " + (w["expires"] or "-"))
                out(t("nameservers") + ": " + (", ".join(w["nameservers"]) if w["nameservers"] else "-"))
        elif cmd == "dns":
            if not arg:
                out(t("no_url"))
            else:
                host = urllib.parse.urlparse(normalize_url(arg)).hostname or arg
                d = resolve_dns(host)
                ds = check_dnssec(registrable_domain(host))
                out("IP: " + (", ".join(d["ips"]) if d["ips"] else "-"))
                out("DNSSEC: " + ("enabled" if ds.get("enabled") else ("disabled" if ds.get("enabled") is False else "unknown")))
        else:
            out(t("unknown_cmd"))


def interactive_menu():
    """توافق قديم: الواجهة التفاعلية الآن هي وحدة تحكم Metasploit."""
    return msf_console()


# ---------- أدوات مساعدة ----------

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    return raw


def registrable_domain(hostname):
    parts = (hostname or "").lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname or ""


def whois_query(server, query, timeout=10):
    """استعلام WHOIS خام عبر المنفذ 43، يرجع النص أو None."""
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 20000:
                    break
        return data.decode(errors="ignore")
    except Exception:
        return None


def parse_whois_field(text, names):
    if not text:
        return ""
    for name in names:
        m = re.search(r"(?im)^\s*" + re.escape(name) + r"\s*:\s*(.+?)\s*$", text)
        if m:
            v = m.group(1).strip()
            if v and v.lower() not in ("redacted for privacy", "not disclosed"):
                return v
    return ""


def get_whois(domain):
    """WHOIS عام فقط. يرجع قاموساً بالحقول الظاهرة علناً."""
    info = {"domain": domain, "registrar": "", "created": "", "expires": "",
            "org": "", "country": "", "nameservers": [], "raw_note": ""}
    if not domain or "." not in domain:
        return info
    first = whois_query("whois.iana.org", domain)
    if not first:
        info["raw_note"] = "تعذر الوصول لخادم WHOIS (قد يكون محجوباً في شبكتك)"
        return info
    # خادم WHOIS المرجعي من رد IANA
    ref = parse_whois_field(first, ["whois"])
    if ref:
        second = whois_query(ref, domain)
        if second:
            text = second
        else:
            text = first
    else:
        text = first
    info["registrar"] = parse_whois_field(text, ["Registrar", "registrar"])
    info["created"] = parse_whois_field(text, ["Creation Date", "Created On", "Registered on"])
    info["expires"] = parse_whois_field(text, ["Registry Expiry Date", "Expiry Date", "Expiration Date", "paid-till"])
    info["org"] = parse_whois_field(text, ["Registrant Organization", "Registrant Organisation", "Org"])
    info["country"] = parse_whois_field(text, ["Registrant Country", "Registrant Country Code"])
    ns = re.findall(r"(?im)^\s*Name Server\s*:\s*(\S+)\s*$", text)
    # إزالة التكرار مع الحفاظ على الترتيب
    seen = set()
    for n in ns:
        low = n.lower()
        if low not in seen:
            seen.add(low)
            info["nameservers"].append(n)
    if not info["registrar"] and not info["created"]:
        info["raw_note"] = "البيانات محجوبة للخصوصية (GDPR / Redacted) أو غير متاحة"
    return info


def resolve_dns(hostname):
    out = {"ips": [], "reverse": "", "error": ""}
    if not hostname:
        return out
    try:
        _h, _a, ips = socket.gethostbyname_ex(hostname)
        out["ips"] = ips or []
    except Exception as exc:
        out["error"] = str(exc)
        return out
    # IPv6 إن وجد
    try:
        infos = socket.getaddrinfo(hostname, 443, socket.AF_INET6, socket.SOCK_STREAM)
        for _f, _t, _p, _c, sockaddr in infos:
            ip6 = sockaddr[0]
            if ip6 not in out["ips"]:
                out["ips"].append(ip6)
    except Exception:
        pass
    if out["ips"]:
        try:
            out["reverse"] = socket.gethostbyaddr(out["ips"][0])[0]
        except Exception:
            out["reverse"] = ""
    return out


def check_tls(hostname, port=443):
    """يرجع قاموساً بتفاصيل الشهادة."""
    res = {"ok": False, "days_left": None, "issuer": "", "subject": "",
           "version": "", "not_after": "", "error": "", "cipher": "", "sans": []}
    if not hostname:
        res["error"] = "لا يوجد hostname"
        return res
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                res["version"] = ssock.version() or ""
                res["ok"] = True
                try:
                    ciph = ssock.cipher()
                    if ciph:
                        res["cipher"] = "%s (%d-bit)" % (ciph[0], ciph[2])
                except Exception:
                    pass
        # Issuer / Subject
        def _flat(items):
            d = {}
            for tup in items or []:
                for k, v in tup:
                    d[k] = v
            return d
        iss = _flat(cert.get("issuer", []))
        sub = _flat(cert.get("subject", []))
        res["issuer"] = iss.get("organizationName", "") or iss.get("commonName", "")
        res["subject"] = sub.get("commonName", "")
        res["sans"] = [v for _t, v in cert.get("subjectAltName", [])]
        not_after = cert.get("notAfter", "")
        res["not_after"] = not_after
        if not_after:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            res["days_left"] = (expiry - now).days
    except Exception as exc:
        res["error"] = str(exc)
    return res


class ChainHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append((code, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url, timeout=15):
    """GET واحد عادي. يرجع (status, final_url, headers_dict, body_text, chain, error)."""
    handler = ChainHandler()
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers={"User-Agent": "Conan-Detective/2.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(120000).decode(errors="ignore")
            return resp.status, resp.geturl(), resp.headers, body, handler.chain, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(120000).decode(errors="ignore")
        except Exception:
            body = ""
        return exc.code, exc.geturl(), (exc.headers if exc.headers is not None else {}), body, handler.chain, "HTTP %s" % exc.code
    except Exception as exc:
        return None, url, {}, "", handler.chain, str(exc)


def fetch_small(base_url, path, timeout=8):
    """فحص وجود ملف عام مثل robots.txt. يرجع (status, size, snippet)."""
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(url, headers={"User-Agent": "Conan-Detective/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(8000).decode(errors="ignore")
            return resp.status, len(data), data[:300].replace("\n", " | ")
    except urllib.error.HTTPError as exc:
        return exc.code, 0, ""
    except Exception:
        return None, 0, ""


# ---------- v2.3: Website Security Intelligence ----------

def mask_value(v):
    """إخفاء قيمة حساسة (كوكيز): لا تظهر القيمة أبداً في التقرير."""
    return "••••••••"


def doh_query(name, rtype, timeout=8):
    """استعلام DNS عبر HTTPS (dns.google) — يعمل في Termux بدون dnspython."""
    try:
        q = "https://dns.google/resolve?name=%s&type=%s" % (urllib.parse.quote(name), rtype)
        req = urllib.request.Request(q, headers={"User-Agent": "Conan-Detective/2.3"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def check_dnssec(domain):
    """DNSSEC: هل يوجد سجل DS؟ وهل توجد DNSKEY؟ عبر DoH."""
    out = {"enabled": None, "ds": False, "dnskey": False, "ad": False}
    if not domain or "." not in domain:
        return out
    ds = doh_query(domain, "DS")
    if ds is None:
        return out
    if ds.get("AD"):
        out["ad"] = True
    answers = ds.get("Answer") or []
    out["ds"] = len(answers) > 0
    dk = doh_query(domain, "DNSKEY")
    if dk is not None:
        out["dnskey"] = len(dk.get("Answer") or []) > 0
    out["enabled"] = bool(out["ds"])
    return out


def analyze_hsts(hsts):
    """تحليل HSTS بعمق: max-age و includeSubDomains و preload."""
    d = {"present": bool(hsts), "max_age": None, "subdomains": False, "preload": False}
    if not hsts:
        return d
    low = hsts.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    if m:
        d["max_age"] = int(m.group(1))
    d["subdomains"] = "includesubdomains" in low
    d["preload"] = "preload" in low
    return d


def analyze_csp(csp):
    """تحليل CSP بعمق: التوجيهات والثغرات الشائعة."""
    d = {"present": bool(csp), "directives": {}, "unsafe_inline": False,
         "unsafe_eval": False, "wildcard": False, "missing": []}
    if not csp:
        return d
    low = csp.lower()
    d["unsafe_inline"] = "unsafe-inline" in low
    d["unsafe_eval"] = "unsafe-eval" in low
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        kv = part.split(None, 1)
        d["directives"][kv[0].lower()] = kv[1] if len(kv) > 1 else ""
    ss = d["directives"].get("script-src", "") or d["directives"].get("default-src", "")
    d["wildcard"] = "*" in ss or "data:" in ss
    for need in ("default-src", "object-src", "base-uri", "frame-ancestors"):
        if need not in d["directives"]:
            d["missing"].append(need)
    return d


TECH_PATTERNS = [
    ("WordPress", ["wp-content", "wp-includes", "wp-json"]),
    ("Joomla", ["joomla", "/media/jui/"]),
    ("Drupal", ["drupal", "sites/default/files"]),
    ("Laravel", ["laravel_session", "XSRF-TOKEN", "laravel"]),
    ("Django", ["csrftoken", "django"]),
    ("Next.js", ["_next/static", "__NEXT_DATA__"]),
    ("React", ["react", "__REACT"]),
    ("Vue.js", ["vue.js", "data-v-"]),
    ("Angular", ["ng-version", "angular"]),
    ("jQuery", ["jquery"]),
    ("Bootstrap", ["bootstrap"]),
    ("Cloudflare", ["cf-ray", "cloudflare"]),
    ("Nginx", ["nginx"]),
    ("Apache", ["apache"]),
    ("PHP", ["x-powered-by: php", ".php"]),
    ("ASP.NET", ["asp.net", "x-aspnet-version"]),
]


def detect_tech(lower, body):
    """كشف التقنيات سلبياً: من الرؤوس و HTML فقط، بدون أي طلب إضافي."""
    found = []
    server = lower.get("server", "")
    powered = lower.get("x-powered-by", "")
    if server:
        found.append("Server: %s" % server)
    if powered:
        found.append("X-Powered-By: %s" % powered)
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body or "", re.I)
    if m:
        found.append("Generator: %s" % m.group(1))
    hay = ((body or "") + " " + server + " " + powered).lower()
    for name, markers in TECH_PATTERNS:
        if any(mk.lower() in hay for mk in markers):
            if not any(name in f for f in found):
                found.append(name)
    return found


def analyze_robots(text):
    """تحليل robots.txt: عدد Disallow/Allow و Sitemap والمسارات الحساسة."""
    d = {"present": bool(text), "disallow": [], "allow": [], "sitemaps": [], "sensitive": []}
    if not text:
        return d
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("disallow:"):
            d["disallow"].append(line.split(":", 1)[1].strip())
        elif low.startswith("allow:"):
            d["allow"].append(line.split(":", 1)[1].strip())
        elif low.startswith("sitemap:"):
            d["sitemaps"].append(line.split(":", 1)[1].strip())
    for pth in d["disallow"]:
        if any(k in pth.lower() for k in ("admin", "login", ".env", "config", "backup", ".git", "wp-admin", "private")):
            d["sensitive"].append(pth)
    return d


def analyze_sitemap(text):
    """تحليل sitemap.xml: عدد الروابط ووجود lastmod وصلاحية XML."""
    d = {"present": bool(text), "urls": 0, "has_lastmod": False, "valid_xml": False}
    if not text:
        return d
    d["urls"] = len(re.findall(r"<loc>", text))
    d["has_lastmod"] = "<lastmod>" in text
    d["valid_xml"] = text.strip().startswith("<?xml") or "<urlset" in text
    return d


def parse_cookies(headers):
    """تحليل الكوكيز: الاسم والأعلام فقط — القيمة مخفية دائماً."""
    raw_list = []
    try:
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            raw_list = get_all("Set-Cookie") or []
        elif isinstance(headers, dict):
            v = headers.get("Set-Cookie") or headers.get("set-cookie")
            if v:
                raw_list = [v]
    except Exception:
        raw_list = []
    cookies = []
    for raw in raw_list:
        parts = [x.strip() for x in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        low = raw.lower()
        cookies.append({
            "name": name,
            "value": mask_value(""),
            "secure": "secure" in low,
            "httponly": "httponly" in low,
            "samesite": ("samesite=lax" in low and "Lax")
                        or ("samesite=strict" in low and "Strict")
                        or ("samesite=none" in low and "None") or "",
        })
    return cookies


HISTORY_FILE = "conan-history.json"


def load_history():
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def compare_and_save(domain, url, score, grade_str, vuln_titles):
    """قارن مع آخر فحص لنفس النطاق، ثم احفظ الفحص الحالي في السجل."""
    hist = load_history()
    prev = None
    for e in reversed(hist):
        if e.get("domain") == domain:
            prev = e
            break
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    entry = {"domain": domain, "target": url, "score": score, "grade": grade_str,
             "vulns": list(vuln_titles), "checked_at_utc": now}
    if prev is None:
        comp = {"previous": None, "delta": None, "new": [], "fixed": []}
    else:
        prev_set, cur_set = set(prev.get("vulns", [])), set(vuln_titles)
        comp = {"previous": {"score": prev.get("score"), "grade": prev.get("grade"),
                             "checked_at_utc": prev.get("checked_at_utc")},
                "delta": score - int(prev.get("score") or 0),
                "new": sorted(cur_set - prev_set), "fixed": sorted(prev_set - cur_set)}
    hist.append(entry)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(hist[-50:], f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return comp


def tr_detail(detail):
    """ترجمة أجزاء التفاصيل العربية الشائعة في وضع en/fr."""
    if LANG == "ar" or not detail:
        return detail
    out_d = detail
    m = re.search(r"تنتهي بعد (\d+) يوم", out_d)
    if m:
        out_d = out_d.replace(m.group(0), "expires in %s days" % m.group(1) if LANG == "en" else "expire dans %s jours" % m.group(1))
    repl = {
        "موجود": "present" if LANG == "en" else "présent",
        "مفقود": "missing" if LANG == "en" else "manquant",
        "ناقصة Secure أو HttpOnly": "missing Secure or HttpOnly" if LANG == "en" else "Secure ou HttpOnly manquant",
        "لا يوجد http ظاهر": "no http found" if LANG == "en" else "aucun http trouvé",
        "رأس خصوصية/صلاحيات مفقود": "missing privacy/permissions header" if LANG == "en" else "en-tête de confidentialité/autorisations manquant",
        "لا توجد كوكيز في الرد": "no cookies in the response" if LANG == "en" else "aucun cookie dans la réponse",
        "لا توجد ملفات تعريف ارتباط في الرد": "no cookies in the response" if LANG == "en" else "aucun cookie dans la réponse",
    }
    for k, v in repl.items():
        out_d = out_d.replace(k, v)
    return out_d


def generate_html_report(r):
    """تقرير HTML احترافي مستقل (CSS مضمّن)، يدعم RTL للعربية."""
    lang = r.get("language", LANG)
    direction = "rtl" if lang == "ar" else "ltr"
    score = r["score"]
    color = "#16a34a" if score >= 80 else "#ca8a04" if score >= 60 else "#dc2626"
    sev_map = {"عالي": "HIGH", "متوسط": "MEDIUM", "منخفض": "LOW"}
    rows = ""
    for c in r["checks"]:
        mark = "✔" if c["passed"] else "✘"
        rows += "<tr><td>%s</td><td>%s</td><td>%s/%s</td><td>%s</td></tr>" % (
            mark, c["name"], c["points"] if c["passed"] else 0, c["points"], c["detail"])
    vrows = ""
    for v in r["vulnerabilities"]:
        vrows += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            sev_map.get(v["severity"], v["severity"]), v["title"], v["detail"], v["fix"])
    comp = r.get("comparison") or {}
    comp_html = ""
    if comp.get("previous"):
        comp_html = "<p>Previous score: %s &nbsp; Change: %+d</p>" % (
            comp["previous"].get("score"), comp.get("delta") or 0)
    html = """<!DOCTYPE html><html lang="%s" dir="%s"><head><meta charset="utf-8">
<title>Conan Detective — %s</title><style>
body{font-family:system-ui,Arial,sans-serif;max-width:900px;margin:20px auto;padding:0 16px;color:#111}
h1{font-size:22px} .score{font-size:44px;color:%s} table{border-collapse:collapse;width:100%%;margin:12px 0}
td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:14px}
th{background:#f3f4f6} .high{color:#dc2626;font-weight:bold}
footer{color:#666;font-size:13px;margin-top:20px}</style></head><body>
<h1>🔍 Conan Detective — Website Security Intelligence</h1>
<p>Target: <b>%s</b><br>Date (UTC): %s<br>Developer: %s — Algeria 🇩🇿</p>
<p class="score">%d%% — %s</p>%s
<h2>Checks</h2><table><tr><th></th><th>Check</th><th>Points</th><th>Detail</th></tr>%s</table>
<h2>Weaknesses (%d)</h2><table><tr><th>Severity</th><th>Title</th><th>Detail</th><th>Fix</th></tr>%s</table>
<footer>Conan Detective v%s — passive defensive audit only. No exploitation.</footer>
</body></html>""" % (lang, direction, r["target"], color, r["target"],
                     r["checked_at_utc"], DEVELOPER_NAME, score, r["grade"],
                     comp_html, rows, len(r["vulnerabilities"]), vrows, VERSION)
    return html


GRADE_WORDS = {
    "A+": {"en": "Excellent", "fr": "Excellent", "ar": "ممتاز"},
    "A": {"en": "Very good", "fr": "Très bien", "ar": "جيد جداً"},
    "B": {"en": "Good", "fr": "Bien", "ar": "جيد"},
    "C": {"en": "Fair", "fr": "Passable", "ar": "مقبول"},
    "D": {"en": "Weak", "fr": "Faible", "ar": "ضعيف"},
    "E": {"en": "Poor", "fr": "Médiocre", "ar": "سيئ جداً"},
    "F": {"en": "Critical", "fr": "Critique", "ar": "خطر"},
}


def grade(score):
    if score >= 95:
        letter = "A+"
    elif score >= 90:
        letter = "A"
    elif score >= 80:
        letter = "B"
    elif score >= 70:
        letter = "C"
    elif score >= 60:
        letter = "D"
    elif score >= 50:
        letter = "E"
    else:
        letter = "F"
    return "%s - %s" % (letter, GRADE_WORDS[letter].get(LANG, GRADE_WORDS[letter]["ar"]))


# ---------- الفحص الرئيسي ----------

def run_check(target_url):
    url = normalize_url(target_url)
    parsed = urllib.parse.urlparse(url)
    is_https = parsed.scheme == "https"
    hostname = parsed.hostname or ""
    domain = registrable_domain(hostname)

    vulns = []  # {severity, title, detail, fix}
    infos = []  # معلومات عامة
    score_points = []  # (name, passed, points, detail)

    def add_vuln(sev, title, detail, fix):
        vulns.append({"severity": sev, "title": title, "detail": detail, "fix": fix})

    # 1) DNS
    dns = resolve_dns(hostname)
    if dns["ips"]:
        infos.append("IP: %s" % ", ".join(dns["ips"][:3]))
        if dns["reverse"]:
            infos.append("Reverse DNS: %s" % dns["reverse"])
    else:
        add_vuln("عالي", "تعذر حل DNS", dns["error"] or "لا يوجد IP", "تحقق من إعدادات DNS والنطاق")

    # 1b) DNSSEC
    dnssec = check_dnssec(domain)
    if dnssec.get("enabled") is True:
        infos.append("DNSSEC: مفعّل (DS موجود)")
    elif dnssec.get("enabled") is False:
        add_vuln("منخفض", "DNSSEC غير مفعّل", "لا يوجد سجل DS للنطاق", "فعّل DNSSEC عند مسجل النطاق")
    else:
        infos.append("DNSSEC: تعذر التحقق")

    # 2) WHOIS
    whois = get_whois(domain)

    # 3) TLS
    tls = {"ok": False, "days_left": None}
    if is_https and hostname:
        tls = check_tls(hostname)
        score_points.append(("HTTPS مفعل", True, 10, "https"))
        if tls["ok"] and tls["days_left"] is not None:
            if tls["days_left"] > 30:
                score_points.append(("شهادة TLS صالحة", True, 10, "تنتهي بعد %d يوماً - %s" % (tls["days_left"], tls["issuer"])))
            elif tls["days_left"] > 0:
                score_points.append(("شهادة TLS صالحة", False, 10, "تنتهي قريباً بعد %d يوماً" % tls["days_left"]))
                add_vuln("متوسط", "شهادة TLS تنتهي قريباً", "بقي %d يوماً" % tls["days_left"], "جدد الشهادة قبل الانتهاء")
            else:
                score_points.append(("شهادة TLS صالحة", False, 10, "منتهية"))
                add_vuln("عالي", "شهادة TLS منتهية", tls["not_after"], "جدد الشهادة فوراً")
            if tls["version"] and tls["version"] in ("TLSv1", "TLSv1.1"):
                add_vuln("عالي", "إصدار TLS قديم وغير آمن", tls["version"], "فعّل TLS 1.2 كحد أدنى ويفضل 1.3 فقط")
            if tls.get("cipher"):
                infos.append("TLS cipher: %s" % tls["cipher"])
                low_ciph = tls["cipher"].lower()
                if any(w in low_ciph for w in ("rc4", "3des", "des", "md5", "null", "export")):
                    add_vuln("عالي", "تشفير TLS ضعيف", tls["cipher"], "عطّل الشفرات الضعيفة (RC4/3DES/DES) في الخادم")
            if tls.get("sans"):
                infos.append("SANs: %d (%s)" % (len(tls["sans"]), ", ".join(tls["sans"][:3])))
        else:
            score_points.append(("شهادة TLS صالحة", False, 10, tls["error"] or "تعذر الفحص"))
            add_vuln("عالي", "تعذر التحقق من شهادة TLS", tls["error"], "تحقق من تثبيت الشهادة وسلسلتها")
    else:
        score_points.append(("HTTPS مفعل", False, 10, "http فقط - غير آمن"))
        add_vuln("عالي", "الموقع يعمل بدون HTTPS", "الاتصال غير مشفر", "فعّل HTTPS وأعد توجيه http إلى https")

    # 4) HTTP + Headers
    status, final_url, headers, body, chain, fetch_error = fetch_url(url)
    lower = {k.lower(): v for k, v in headers.items()}

    if status is not None:
        infos.append("HTTP: %s" % status)
        if chain:
            infos.append("سلسلة تحويل: %s" % " -> ".join("%s %s" % (c, u) for c, u in chain))
        if final_url != url:
            infos.append("الوجهة النهائية: %s" % final_url)
        # http -> https redirect check
        if not is_https and final_url.startswith("https://"):
            infos.append("يوجد تحويل http إلى https")
    else:
        add_vuln("عالي", "تعذر الوصول للموقع", fetch_error or "", "تحقق أن الموقع يعمل والرابط صحيح")

    def has(name):
        return name in lower and bool(lower[name])

    # HSTS (تحليل عميق)
    hsts = lower.get("strict-transport-security", "")
    hsts_info = analyze_hsts(hsts)
    if has("strict-transport-security"):
        score_points.append(("HSTS", True, 10, hsts))
        if hsts_info["max_age"] is not None and hsts_info["max_age"] < 31536000:
            add_vuln("متوسط", "HSTS max-age قصير", "max-age=%d" % hsts_info["max_age"], "ارفع max-age إلى 31536000 على الأقل")
        if not hsts_info["subdomains"]:
            infos.append("HSTS بدون includeSubDomains")
        if not hsts_info["preload"]:
            infos.append("HSTS موجود بدون preload - يمكن إضافته بعد التأكد")
    else:
        score_points.append(("HSTS", False, 10, "مفقود"))
        if is_https:
            add_vuln("عالي", "غياب HSTS", "المتصفح قد يقبل اتصال http أول مرة", "أضف Strict-Transport-Security: max-age=31536000; includeSubDomains")

    # CSP (تحليل عميق)
    csp = lower.get("content-security-policy", "")
    csp_info = analyze_csp(csp)
    if has("content-security-policy"):
        score_points.append(("Content-Security-Policy", True, 10, "موجود"))
        if csp_info["unsafe_inline"] or csp_info["unsafe_eval"]:
            add_vuln("متوسط", "CSP ضعيف", "يحتوي unsafe-inline أو unsafe-eval", "أزل unsafe-inline/eval واستعمل nonce أو hash")
        if csp_info["wildcard"]:
            add_vuln("متوسط", "CSP يسمح بـ wildcard", "script-src يحتوي * أو data:", "قيّد script-src بنطاقات محددة بدل *")
        if csp_info["missing"]:
            infos.append("CSP ينقصه: %s" % ", ".join(csp_info["missing"]))
    else:
        score_points.append(("Content-Security-Policy", False, 10, "مفقود"))
        add_vuln("عالي", "غياب Content-Security-Policy", "خطر XSS وحقن محتوى", "أضف CSP مناسباً لموقعك، ابدأ بـ default-src 'self'")

    # Clickjacking
    xfo = lower.get("x-frame-options", "")
    frame_ok = bool(xfo) or "frame-ancestors" in csp
    score_points.append(("حماية من التضمين X-Frame", frame_ok, 8, xfo or ("frame-ancestors في CSP" if frame_ok else "مفقود")))
    if not frame_ok:
        add_vuln("متوسط", "خطر Clickjacking", "لا يوجد X-Frame-Options ولا frame-ancestors", "أضف X-Frame-Options: DENY أو SAMEORIGIN")

    # nosniff
    nosniff_ok = lower.get("x-content-type-options", "").lower() == "nosniff"
    score_points.append(("X-Content-Type-Options nosniff", nosniff_ok, 7, lower.get("x-content-type-options", "مفقود")))
    if not nosniff_ok:
        add_vuln("متوسط", "غياب nosniff", "المتصفح قد يخمن نوع المحتوى", "أضف X-Content-Type-Options: nosniff")

    # Referrer / Permissions / COOP / COEP
    for hdr, pts, title in [
        ("referrer-policy", 5, "Referrer-Policy"),
        ("permissions-policy", 5, "Permissions-Policy"),
        ("cross-origin-opener-policy", 3, "Cross-Origin-Opener-Policy"),
        ("cross-origin-embedder-policy", 3, "Cross-Origin-Embedder-Policy"),
    ]:
        ok = has(hdr)
        score_points.append((title, ok, pts, lower.get(hdr, "مفقود")))
        if not ok:
            add_vuln("منخفض", "غياب %s" % title, "رأس خصوصية/صلاحيات مفقود", "أضف %s مناسباً" % title)

    # Server disclosure + passive tech detection
    tech = detect_tech(lower, body)
    server = lower.get("server", "")
    powered = lower.get("x-powered-by", "")
    if server and any(ch.isdigit() for ch in server):
        add_vuln("منخفض", "الخادم يكشف إصداره", server, "أخفِ رقم الإصدار من رأس Server")
    if powered:
        add_vuln("منخفض", "كشف التقنية X-Powered-By", powered, "أزل رأس X-Powered-By")

    # Cookies (القيم مخفية دائماً — يظهر الاسم والأعلام فقط)
    cookies = parse_cookies(headers)
    if cookies:
        cookie_ok = all(c["secure"] and c["httponly"] for c in cookies)
        score_points.append(("كوكيز آمنة", cookie_ok, 5, "Secure+HttpOnly" if cookie_ok else "ناقصة Secure أو HttpOnly"))
        for c in cookies:
            if not (c["secure"] and c["httponly"]):
                add_vuln("متوسط", "كوكيز بدون حماية كاملة", "%s: Secure=%s HttpOnly=%s (value masked)" % (c["name"], c["secure"], c["httponly"]), "أضف Secure و HttpOnly و SameSite=Lax للكوكيز")
            if not c["samesite"]:
                add_vuln("منخفض", "كوكيز بدون SameSite", "%s: بدون SameSite" % c["name"], "أضف SameSite=Lax أو Strict")
    else:
        cookies = []
        score_points.append(("كوكيز آمنة", True, 5, "لا توجد كوكيز في الرد"))

    # Mixed content
    if is_https and body:
        http_links = re.findall(r'(?:src|href)\s*=\s*["\']http://[^"\']+', body, re.I)
        if http_links:
            add_vuln("عالي", "محتوى مختلط Mixed Content", "%d رابط http داخل صفحة https" % len(http_links), "حوّل كل الموارد إلى https أو روابط نسبية")
            score_points.append(("بدون محتوى مختلط", False, 5, "%d رابط http" % len(http_links)))
        else:
            score_points.append(("بدون محتوى مختلط", True, 5, "لا يوجد http ظاهر"))

    # ملفات عامة: تحليل robots/sitemap + التحقق من محتوى security.txt
    base = "%s://%s" % (parsed.scheme, parsed.netloc)
    public_files = {}
    bodies = {}
    for path, label in [("/robots.txt", "robots.txt"), ("/sitemap.xml", "sitemap.xml"), ("/security.txt", "security.txt"), ("/.well-known/security.txt", "well-known/security.txt")]:
        st, size, snippet = fetch_small(base, path)
        public_files[label] = {"status": st, "size": size}
        bodies[label] = snippet
        if st == 200:
            infos.append("%s موجود (%d بايت)" % (label, size))
    robots = analyze_robots(bodies.get("robots.txt", "")) if public_files.get("robots.txt", {}).get("status") == 200 else {"present": False, "disallow": [], "allow": [], "sitemaps": [], "sensitive": []}
    sitemap = analyze_sitemap(bodies.get("sitemap.xml", "")) if public_files.get("sitemap.xml", {}).get("status") == 200 else {"present": False, "urls": 0, "has_lastmod": False, "valid_xml": False}
    if robots.get("present"):
        infos.append("robots.txt: %d Disallow, %d Allow, %d Sitemap" % (len(robots["disallow"]), len(robots["allow"]), len(robots["sitemaps"])))
        if robots.get("sensitive"):
            add_vuln("منخفض", "robots.txt يكشف مسارات حساسة", ", ".join(robots["sensitive"][:3]), "أزل المسارات الحساسة من robots.txt")
    if sitemap.get("present"):
        infos.append("sitemap.xml: %d URL, lastmod=%s, XML صالح=%s" % (sitemap["urls"], sitemap["has_lastmod"], sitemap["valid_xml"]))
    sec_valid = False
    for lbl in ("security.txt", "well-known/security.txt"):
        b = bodies.get(lbl, "")
        if public_files.get(lbl, {}).get("status") == 200 and "contact:" in b.lower() and b != bodies.get("sitemap.xml", ""):
            sec_valid = True
    if not sec_valid:
        add_vuln("منخفض", "لا يوجد security.txt", "لا توجد طريقة معلنة للإبلاغ عن ثغرة", "أضف /.well-known/security.txt مع بريد للتواصل الأمني")

    # النتيجة
    total = sum(p for _n, ok, p, _d in score_points if ok)
    max_total = sum(p for _n, _ok, p, _d in score_points)
    score = int(round(100.0 * total / max_total)) if max_total else 0

    # ترتيب الثغرات حسب الخطورة
    order = {"عالي": 0, "متوسط": 1, "منخفض": 2}
    vulns_sorted = sorted(vulns, key=lambda v: order.get(v["severity"], 3))
    counts = {"عالي": 0, "متوسط": 0, "منخفض": 0}
    for v in vulns_sorted:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1

    top_fixes = [v["fix"] for v in vulns_sorted[:3]]

    comparison = compare_and_save(domain, url, score, grade(score), [v["title"] for v in vulns_sorted])

    report = {
        "tool": "Conan Detective 2.3 - المحقق كونان",
        "version": VERSION,
        "language": LANG,
        "developer": DEVELOPER_NAME,
        "developer_country": "Algeria - الجزائر",
        "target": url,
        "final_url": final_url,
        "hostname": hostname,
        "domain": domain,
        "status": status,
        "score": score,
        "grade": grade(score),
        "dns": dns,
        "dnssec": dnssec,
        "whois": whois,
        "tls": tls,
        "tech_hints": tech,
        "cookies": cookies,
        "robots": robots,
        "sitemap": sitemap,
        "comparison": comparison,
        "infos": infos,
        "checks": [{"name": n, "passed": ok, "points": p, "detail": d} for n, ok, p, d in score_points],
        "vulnerabilities": vulns_sorted,
        "counts": counts,
        "top_fixes": top_fixes,
        "public_files": public_files,
        "checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "note": "فحص سلبي دفاعي فقط - لا استغلال ولا دخول ولا تجربة حمولات. استعمل على موقعك أو بإذن كتابي.",
    }
    return report


def _tr_check(name):
    if LANG == "ar":
        return name
    m = CHECK_TR.get(name, {})
    return m.get(LANG, name)


def _tr_vuln(v):
    """ترجمة عنوان الثغرة وإصلاحها حسب اللغة (التفاصيل التقنية تبقى كما هي)."""
    if LANG == "ar":
        return v["severity"], v["title"], v["fix"]
    sev = SEV_TR.get(v["severity"], {}).get(LANG, v["severity"])
    tr = VULN_TR.get(v["title"])
    if not tr:
        return sev, v["title"], v["fix"]
    # tr = (en_title, fr_title, ar_fix, en_fix, fr_fix)
    title = tr[0] if LANG == "en" else tr[1]
    fix = tr[3] if LANG == "en" else tr[4]
    return sev, title, fix


def print_report(r):
    print("=" * 60)
    out("🔍 " + TOOL_NAME + " — " + t("report_title"))
    out("Target: " + r["target"] if LANG != "ar" else "الموقع: " + r["target"])
    if r["final_url"] != r["target"]:
        out(t("final_url") + ": " + r["final_url"])
    out(t("date") + ": " + r["checked_at_utc"])
    print("=" * 60)

    out("\n--- 👤 " + t("owner_section") + " ---")
    w = r["whois"]
    out(t("domain") + ": " + w["domain"])
    out(t("registrar") + ": " + (w["registrar"] or t("hidden")))
    out(t("created") + ": " + (w["created"] or "-"))
    out(t("expires") + ": " + (w["expires"] or "-"))
    out(t("org") + ": " + (w["org"] or t("hidden")))
    out(t("nameservers") + ": " + (", ".join(w["nameservers"]) if w["nameservers"] else "-"))
    if w["raw_note"]:
        out(w["raw_note"])

    out("\n--- 🌐 " + t("dns_section") + " ---")
    out("IP: " + (", ".join(r["dns"]["ips"]) if r["dns"]["ips"] else "-"))
    if r["dns"]["reverse"]:
        out("Reverse DNS: " + r["dns"]["reverse"])
    out("TLS: " + (r["tls"]["version"] or "-") + " | " + (r["tls"]["issuer"] or "-") + " | " + (("%d" % r["tls"]["days_left"]) if r["tls"]["days_left"] is not None else "-"))
    if r["tls"].get("cipher"):
        out(t("cipher") + ": " + r["tls"]["cipher"])
    if r["tls"].get("sans"):
        out(t("sans") + ": " + ", ".join(r["tls"]["sans"][:5]))
    ds = r.get("dnssec") or {}
    if ds:
        out("DNSSEC: " + ("enabled" if ds.get("enabled") else ("disabled" if ds.get("enabled") is False else "unknown")))
    if r["tech_hints"]:
        out(" | ".join(r["tech_hints"]))

    out("\n--- ✅ " + t("checks_section") + " ---")
    for c in r["checks"]:
        mark = "✔" if c["passed"] else "✘"
        out(" %s %s : %d/%d - %s" % (mark, _tr_check(c["name"]), c["points"] if c["passed"] else 0, c["points"], tr_detail(c["detail"])))

    if r["infos"]:
        out("\n--- ℹ️ " + t("notes_section") + " ---")
        for info in r["infos"]:
            out(" - " + tr_detail(info))
    if r.get("tech_hints"):
        out("\n--- 🛠️ " + t("tech_section") + " ---")
        for tech_item in r["tech_hints"]:
            out(" - " + tech_item)
    rb = r.get("robots") or {}
    sm = r.get("sitemap") or {}
    if rb.get("present") or sm.get("present"):
        out("\n--- 🤖 " + t("robots_section") + " ---")
        if rb.get("present"):
            out("robots.txt: Disallow=%d, Allow=%d, Sitemap=%d" % (len(rb.get("disallow", [])), len(rb.get("allow", [])), len(rb.get("sitemaps", []))))
            if rb.get("sensitive"):
                out("Sensitive paths: " + ", ".join(rb["sensitive"][:5]))
        if sm.get("present"):
            out("sitemap.xml: URLs=%d, lastmod=%s, valid XML=%s" % (sm.get("urls", 0), sm.get("has_lastmod"), sm.get("valid_xml")))
    if r.get("cookies") is not None:
        out("\n--- 🍪 " + t("cookies_section") + " ---")
        if not r["cookies"]:
            out(" - none")
        for c in r["cookies"]:
            out(" - %s: value=%s Secure=%s HttpOnly=%s SameSite=%s" % (c["name"], c["value"], c["secure"], c["httponly"], c["samesite"] or "-"))
    comp = r.get("comparison") or {}
    out("\n--- 📊 " + t("comparison_section") + " ---")
    if comp.get("previous"):
        out(t("prev_score") + ": %s  |  %s: %+d" % (comp["previous"].get("score"), t("score_change"), comp.get("delta") or 0))
        out(t("new_vulns") + ": " + (", ".join(comp.get("new", [])) or "-"))
        out(t("fixed_vulns") + ": " + (", ".join(comp.get("fixed", [])) or "-"))
    else:
        out(t("no_previous"))

    out("\n--- ⚠️ " + t("vulns_section") + " (%d) ---" % len(r["vulnerabilities"]))
    sev_h = SEV_TR["عالي"].get(LANG, "عالي")
    sev_m = SEV_TR["متوسط"].get(LANG, "متوسط")
    sev_l = SEV_TR["منخفض"].get(LANG, "منخفض")
    out("%s: %d | %s: %d | %s: %d" % (sev_h, r["counts"]["عالي"], sev_m, r["counts"]["متوسط"], sev_l, r["counts"]["منخفض"]))
    if not r["vulnerabilities"]:
        out(" " + t("no_vulns"))
    for v in r["vulnerabilities"]:
        sev, title, fix = _tr_vuln(v)
        out("\n [%s] %s" % (sev, title))
        out("   " + t("details") + " " + v["detail"])
        out("   " + t("fix") + " " + fix)

    print("\n" + "=" * 60)
    out("📊 " + t("summary") + ": " + t("score") + " %d%%" % r["score"])
    out(t("grade") + ": " + r["grade"])
    if r["vulnerabilities"]:
        out(t("top_fixes"))
        for i, v in enumerate(r["vulnerabilities"][:3], 1):
            _sev, _title, _fix = _tr_vuln(v)
            out(" %d. %s" % (i, _fix))
    print("=" * 60)
    out(t("warning"))
    out(t("developer") + ": " + DEVELOPER_NAME + " — " + DEVELOPER_COUNTRY + "  •  " + t("works_strong") + " 💪")


def main():
    ap = argparse.ArgumentParser(description="المحقق كونان - فحص أمان دفاعي سلبي | Conan Detective - Metasploit-style console, en/fr/ar")
    ap.add_argument("url", nargs="?", help="رابط الموقع مثال https://example.com")
    ap.add_argument("--json", action="store_true", help="إخراج JSON فقط")
    ap.add_argument("-o", "--output", help="حفظ التقرير JSON في ملف")
    ap.add_argument("--html", help="حفظ تقرير HTML احترافي في ملف")
    ap.add_argument("--about", action="store_true", help="عرض معلومات عن الأداة فقط")
    ap.add_argument("--developer", action="store_true", help="عرض معلومات عن المطور فقط")
    ap.add_argument("--lang", choices=["en", "fr", "ar"], default=None, help="Language: en / fr / ar (Arabic RTL)")
    args = ap.parse_args()

    if args.lang:
        set_lang(args.lang)

    # أوضاع العرض المباشر — بدون فحص
    if args.about:
        show_banner()
        show_about_tool()
        return 0
    if args.developer:
        show_banner()
        show_about_developer()
        return 0

    # بدون رابط: اختيار اللغة ثم وحدة تحكم بأسلوب Metasploit
    if not args.url:
        if not args.lang:
            choose_language()
        return msf_console()

    # مع رابط: فحص مباشر (يحافظ على التوافق مع الأوامر القديمة)
    if not args.json:
        show_banner()
    raw = args.url
    report = run_check(raw)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("تم حفظ التقرير في:", args.output)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(generate_html_report(report))
        print("تم حفظ تقرير HTML في:", args.html)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
