#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
المحقق كونان - Conan Detective v2.1.1
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
    python3 conan.py                        # واجهة تفاعلية: قائمة، عن الأداة، عن المطور
    python3 conan.py https://example.com
    python3 conan.py example.com
    python3 conan.py https://example.com --json
    python3 conan.py https://example.com -o تقرير.json
    python3 conan.py --about               # عن الأداة فقط
    python3 conan.py --developer            # عن المطور فقط
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


VERSION = "2.1.1"
TOOL_NAME = "المحقق كونان - Conan Detective"
DEVELOPER_NAME = "Hafed Mehdi Salah Eddine"
DEVELOPER_COUNTRY = "الجزائر 🇩🇿"
DEVELOPER_GITHUB = "M-salah1"
SYSTEM_TAGLINE = "نظام فحص قوي — دقيق، سريع، ويعمل بقوة"

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
    print(C_CYAN("=" * 55))
    print(C_BOLD("   🔍  CONAN  DETECTIVE  —  المحقق كونان"))
    print(C_CYAN("   نظام فحص أمان قوي لمواقع الويب  |  الإصدار " + VERSION))
    print("   " + SYSTEM_TAGLINE)
    print(C_CYAN("=" * 55))
    print("   المطور: " + C_GREEN(DEVELOPER_NAME) + "  •  " + DEVELOPER_COUNTRY)
    print("   GitHub: " + DEVELOPER_GITHUB + "  •  يعمل بقوة 💪")
    print(C_CYAN("-" * 55))


def show_about_tool():
    print("\n" + "=" * 55)
    print("📖 عن الأداة — " + TOOL_NAME + " v" + VERSION)
    print("=" * 55)
    print("نظام فحص أمان دفاعي سلبي (Passive) يعمل في Termux")
    print("ببايثون فقط، بدون أي مكتبة خارجية.")
    print("\nماذا يفعل؟")
    print("  1. يفحص DNS و IP و Reverse DNS")
    print("  2. يجلب WHOIS العام: المسجل وتواريخ النطاق وخوادم الأسماء")
    print("     وبيانات المالك الظاهرة علناً فقط")
    print("  3. يفحص HTTPS وشهادة TLS والرؤوس الأمنية والكوكيز")
    print("  4. يكشف إصدار الخادم والتقنية الظاهرة والملفات العامة")
    print("  5. يعطيك ملخصاً ونسبة من 100 وتقييماً، وقائمة ثغرات")
    print("     (إعدادات ناقصة) مرتبة حسب الخطورة مع إصلاح لكل واحدة")
    print("\nماذا لا يفعل؟")
    print("  لا يستغل أي ثغرة، لا يرسل حمولات، لا يجرب كلمات مرور،")
    print("  ولا يسجل الدخول أو يتجاوز أي حماية.")
    print("\nالقاعدة الذهبية: استعمله فقط على موقعك الخاص")
    print("أو موقع عندك إذن كتابي لفحصه.")
    print("=" * 55)


def show_about_developer():
    print("\n" + "=" * 55)
    print("👨‍💻 عن المطور")
    print("=" * 55)
    print("الاسم: " + DEVELOPER_NAME)
    print("البلد: " + DEVELOPER_COUNTRY)
    print("GitHub: " + DEVELOPER_GITHUB)
    print("المشروع: " + TOOL_NAME + " v" + VERSION)
    print("\nمطور من الجزائر، يعمل بقوة 💪")
    print("يبني أدوات عملية تشتغل فعلاً في Termux،")
    print("بكود نظيف، وبدون تعقيد، وبدون وعود وهمية:")
    print("ما يشتغل يقال إنه يشتغل، وما لا يشتغل يقال بصراحة.")
    print("=" * 55)


def interactive_menu():
    """الواجهة التفاعلية: حلقة قائمة حتى يختار المستخدم الخروج."""
    while True:
        show_banner()
        print("\n  [1] 🔍  فحص موقع")
        print("  [2] 📖  عن الأداة")
        print("  [3] 👨‍💻  عن المطور")
        print("  [0] 🚪  خروج")
        try:
            choice = input("\nاختر رقماً: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nمع السلامة 👋")
            return 0
        if choice == "1":
            try:
                raw = input("ادخل رابط الموقع (مثال: https://example.com): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nألغيت.")
                continue
            if not raw:
                print("لم تدخل رابطاً.")
                continue
            print("\nجارٍ الفحص... 🔎")
            report = run_check(raw)
            print_report(report)
            try:
                save = input("\nهل تريد حفظ التقرير JSON؟ (y/N): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                save = ""
            if save in ("y", "yes", "نعم"):
                fname = "conan-تقرير.json"
                with open(fname, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
                print("تم الحفظ في:", fname)
            try:
                input("\nاضغط Enter للعودة للقائمة...")
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "2":
            show_about_tool()
            try:
                input("\nاضغط Enter للعودة للقائمة...")
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "3":
            show_about_developer()
            try:
                input("\nاضغط Enter للعودة للقائمة...")
            except (EOFError, KeyboardInterrupt):
                pass
        elif choice == "0":
            print("\nمع السلامة 👋 — " + TOOL_NAME)
            return 0
        else:
            print("اختيار غير صحيح، جرّب 1 أو 2 أو 3 أو 0.")


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
           "version": "", "not_after": "", "error": ""}
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
            return resp.status, resp.geturl(), dict(resp.headers), body, handler.chain, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(120000).decode(errors="ignore")
        except Exception:
            body = ""
        return exc.code, exc.geturl(), dict(exc.headers or {}), body, handler.chain, "HTTP %s" % exc.code
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


def grade(score):
    if score >= 90:
        return "A - ممتاز"
    if score >= 75:
        return "B - جيد"
    if score >= 60:
        return "C - مقبول"
    if score >= 40:
        return "D - ضعيف"
    return "F - خطر"


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

    # HSTS
    hsts = lower.get("strict-transport-security", "")
    if has("strict-transport-security"):
        score_points.append(("HSTS", True, 10, hsts))
        if "preload" not in hsts.lower():
            infos.append("HSTS موجود بدون preload - يمكن إضافته بعد التأكد")
    else:
        score_points.append(("HSTS", False, 10, "مفقود"))
        if is_https:
            add_vuln("عالي", "غياب HSTS", "المتصفح قد يقبل اتصال http أول مرة", "أضف Strict-Transport-Security: max-age=31536000; includeSubDomains")

    # CSP
    csp = lower.get("content-security-policy", "")
    if has("content-security-policy"):
        score_points.append(("Content-Security-Policy", True, 10, "موجود"))
        low_csp = csp.lower()
        if "unsafe-inline" in low_csp or "unsafe-eval" in low_csp:
            add_vuln("متوسط", "CSP ضعيف", "يحتوي unsafe-inline أو unsafe-eval", "أزل unsafe-inline/eval واستعمل nonce أو hash")
        if "default-src" not in low_csp:
            infos.append("CSP بدون default-src - يفضل إضافته")
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
    ]:
        ok = has(hdr)
        score_points.append((title, ok, pts, lower.get(hdr, "مفقود")))
        if not ok:
            add_vuln("منخفض", "غياب %s" % title, "رأس خصوصية/صلاحيات مفقود", "أضف %s مناسباً" % title)

    # Server disclosure
    server = lower.get("server", "")
    powered = lower.get("x-powered-by", "")
    tech = []
    if server:
        tech.append("Server: %s" % server)
    if powered:
        tech.append("X-Powered-By: %s" % powered)
    if server and any(ch.isdigit() for ch in server):
        add_vuln("منخفض", "الخادم يكشف إصداره", server, "أخفِ رقم الإصدار من رأس Server")
    if powered:
        add_vuln("منخفض", "كشف التقنية X-Powered-By", powered, "أزل رأس X-Powered-By")

    # Meta generator
    gen = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
    if m:
        gen = m.group(1)
        tech.append("Generator: %s" % gen)
    if gen and any(ch.isdigit() for ch in gen):
        infos.append("التقنية الظاهرة قد تكشف إصداراً - راجعها")

    # Cookies
    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    # urllib قد يدمج عدة كوكيز؛ نفحص النص المتاح
    if set_cookie:
        low_c = set_cookie.lower()
        cookie_ok = "secure" in low_c and "httponly" in low_c
        score_points.append(("كوكيز آمنة", cookie_ok, 5, "Secure+HttpOnly" if cookie_ok else "ناقصة Secure أو HttpOnly"))
        if not cookie_ok:
            add_vuln("متوسط", "كوكيز بدون حماية كاملة", set_cookie[:120], "أضف Secure و HttpOnly و SameSite=Lax للكوكيز")
        if "samesite" not in low_c:
            add_vuln("منخفض", "كوكيز بدون SameSite", "قد يسهل CSRF", "أضف SameSite=Lax أو Strict")
    else:
        score_points.append(("كوكيز آمنة", True, 5, "لا توجد كوكيز في الرد"))

    # Mixed content
    if is_https and body:
        http_links = re.findall(r'(?:src|href)\s*=\s*["\']http://[^"\']+', body, re.I)
        if http_links:
            add_vuln("عالي", "محتوى مختلط Mixed Content", "%d رابط http داخل صفحة https" % len(http_links), "حوّل كل الموارد إلى https أو روابط نسبية")
            score_points.append(("بدون محتوى مختلط", False, 5, "%d رابط http" % len(http_links)))
        else:
            score_points.append(("بدون محتوى مختلط", True, 5, "لا يوجد http ظاهر"))

    # ملفات عامة
    base = "%s://%s" % (parsed.scheme, parsed.netloc)
    public_files = {}
    for path, label in [("/robots.txt", "robots.txt"), ("/sitemap.xml", "sitemap.xml"), ("/security.txt", "security.txt"), ("/.well-known/security.txt", "well-known/security.txt")]:
        st, size, snippet = fetch_small(base, path)
        public_files[label] = {"status": st, "size": size}
        if st == 200:
            infos.append("%s موجود (%d بايت)" % (label, size))
    if public_files.get("security.txt", {}).get("status") != 200 and public_files.get("well-known/security.txt", {}).get("status") != 200:
        add_vuln("منخفض", "لا يوجد security.txt", "لا توجد طريقة معلنة للإبلاغ عن ثغرة", "أضف /.well-known/security.txt مع بريد للتواصل الأمني")
    if public_files.get("robots.txt", {}).get("status") == 200:
        infos.append("راجع robots.txt: قد يكشف مسارات حساسة إن ذكرتها")

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

    report = {
        "tool": "Conan Detective 2.1 - المحقق كونان",
        "version": VERSION,
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
        "whois": whois,
        "tls": tls,
        "tech_hints": tech,
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


def print_report(r):
    print("=" * 55)
    print("🔍 المحقق كونان - تقرير فحص أمان الموقع")
    print("الموقع:", r["target"])
    if r["final_url"] != r["target"]:
        print("الوجهة النهائية:", r["final_url"])
    print("التاريخ (UTC):", r["checked_at_utc"])
    print("=" * 55)

    print("\n--- 👤 معلومات المالك والنطاق (WHOIS عام) ---")
    w = r["whois"]
    print("النطاق:", w["domain"])
    print("المسجل:", w["registrar"] or "غير ظاهر / محجوب")
    print("تاريخ الإنشاء:", w["created"] or "-")
    print("تاريخ الانتهاء:", w["expires"] or "-")
    print("المنظمة المسجلة:", w["org"] or "محجوبة للخصوصية أو غير معلنة")
    print("البلد:", w["country"] or "-")
    print("خوادم الأسماء:", ", ".join(w["nameservers"]) if w["nameservers"] else "-")
    if w["raw_note"]:
        print("ملاحظة:", w["raw_note"])

    print("\n--- 🌐 DNS والشبكة ---")
    print("IP:", ", ".join(r["dns"]["ips"]) if r["dns"]["ips"] else "تعذر الحل")
    if r["dns"]["reverse"]:
        print("Reverse DNS:", r["dns"]["reverse"])
    print("TLS:", r["tls"]["version"] or "-", "| الجهة:", r["tls"]["issuer"] or "-", "| ينتهي بعد:", ("%d يوماً" % r["tls"]["days_left"]) if r["tls"]["days_left"] is not None else "-")
    if r["tech_hints"]:
        print("تقنية ظاهرة:", " | ".join(r["tech_hints"]))

    print("\n--- ✅ نتائج الفحص ---")
    for c in r["checks"]:
        mark = "✔" if c["passed"] else "✘"
        print(" %s %s : %d/%d - %s" % (mark, c["name"], c["points"] if c["passed"] else 0, c["points"], c["detail"]))

    if r["infos"]:
        print("\n--- ℹ️ ملاحظات ---")
        for info in r["infos"]:
            print(" -", info)

    print("\n--- ⚠️ الثغرات / نقاط الضعف (%d) ---" % len(r["vulnerabilities"]))
    print("عالي: %d | متوسط: %d | منخفض: %d" % (r["counts"]["عالي"], r["counts"]["متوسط"], r["counts"]["منخفض"]))
    if not r["vulnerabilities"]:
        print(" لا توجد نقاط ضعف ظاهرة في هذا الفحص السلبي. ممتاز!")
    for v in r["vulnerabilities"]:
        print("\n [%s] %s" % (v["severity"], v["title"]))
        print("   التفاصيل:", v["detail"])
        print("   الإصلاح:", v["fix"])

    print("\n" + "=" * 55)
    print("📊 الملخص: نسبة الأمان %d%%" % r["score"])
    print("التقييم:", r["grade"])
    if r["top_fixes"]:
        print("أول 3 إصلاحات:")
        for i, f in enumerate(r["top_fixes"], 1):
            print(" %d. %s" % (i, f))
    print("=" * 55)
    print("تنبيه: هذا فحص سلبي للإعدادات الظاهرة فقط، وليس ضماناً كاملاً للأمان.")
    print("المطور: %s — %s  •  يعمل بقوة 💪" % (DEVELOPER_NAME, DEVELOPER_COUNTRY))


def main():
    ap = argparse.ArgumentParser(description="المحقق كونان - فحص أمان دفاعي سلبي")
    ap.add_argument("url", nargs="?", help="رابط الموقع مثال https://example.com")
    ap.add_argument("--json", action="store_true", help="إخراج JSON فقط")
    ap.add_argument("-o", "--output", help="حفظ التقرير JSON في ملف")
    ap.add_argument("--about", action="store_true", help="عرض معلومات عن الأداة فقط")
    ap.add_argument("--developer", action="store_true", help="عرض معلومات عن المطور فقط")
    args = ap.parse_args()

    # أوضاع العرض المباشر — بدون فحص
    if args.about:
        show_banner()
        show_about_tool()
        return 0
    if args.developer:
        show_banner()
        show_about_developer()
        return 0

    # بدون رابط: الواجهة التفاعلية
    if not args.url:
        return interactive_menu()

    # مع رابط: فحص مباشر (يحافظ على التوافق مع الأوامر القديمة)
    if not args.json:
        show_banner()
    raw = args.url
    report = run_check(raw)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("تم حفظ التقرير في:", args.output)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
