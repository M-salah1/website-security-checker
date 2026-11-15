#!/usr/bin/env python3
"""
Website Security Checker - Termux friendly, Python standard library only.
Checks only public, non-intrusive information: HTTPS, TLS certificate
expiry, and security response headers. It does NOT try to exploit,
log in, or bypass anything. Use it on your own sites, or on public
sites you are allowed to check.

Usage:
    python3 security_check.py https://example.com
    python3 security_check.py example.com
    python3 security_check.py   (then type the URL when asked)
"""

import base64
import datetime
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request


def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    return raw


def check_tls(hostname, port=443):
    """Return (ok, days_left, error). Only for https hosts."""
    try:
        ctx = ssl.create_default_context()
        # If an HTTPS proxy is set (common in sandboxed networks, rare in
        # Termux), tunnel through it with CONNECT instead of a direct socket.
        proxy_url = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
        proxy = urllib.parse.urlparse(proxy_url) if proxy_url else None
        if proxy and proxy.hostname:
            raw = socket.create_connection((proxy.hostname, proxy.port or 8080), timeout=10)
            req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (hostname, port, hostname, port)
            if proxy.username:
                auth = base64.b64encode(("%s:%s" % (urllib.parse.unquote(proxy.username),
                                                    urllib.parse.unquote(proxy.password or ""))).encode()).decode()
                req += "Proxy-Authorization: Basic %s\r\n" % auth
            req += "\r\n"
            raw.sendall(req.encode())
            resp = raw.recv(4096).decode(errors="ignore")
            if " 200 " not in resp:
                raw.close()
                raise RuntimeError("proxy CONNECT failed")
            sock = raw
        else:
            sock = socket.create_connection((hostname, port), timeout=10)
        with sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
        not_after = cert.get("notAfter")
        if not not_after:
            return True, None, "no expiry in certificate"
        # Example: 'Oct 22 12:00:00 2027 GMT'
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        days = (expiry - now).days
        return True, days, "TLS " + str(version)
    except Exception as exc:  # noqa: BLE001 - show the reason to the user
        return False, None, str(exc)


def fetch_headers(url):
    """GET the URL (no exploit, just one normal request) and return headers."""
    req = urllib.request.Request(url, headers={"User-Agent": "Website-Security-Checker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.geturl(), dict(resp.headers), None
    except urllib.error.HTTPError as exc:
        return exc.code, exc.geturl(), dict(exc.headers or {}), "HTTP %s" % exc.code
    except Exception as exc:  # noqa: BLE001
        return None, url, {}, str(exc)


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


def main():
    if len(sys.argv) > 1:
        raw = sys.argv[1]
    else:
        raw = input("ادخل رابط الموقع (مثال: https://example.com): ").strip()
    url = normalize_url(raw)
    if not url:
        print("لم تدخل رابطا.")
        return 1

    parsed = urllib.parse.urlparse(url)
    is_https = parsed.scheme == "https"
    hostname = parsed.hostname or ""

    print("=" * 50)
    print("فحص أمان الموقع")
    print("الموقع:", url)
    print("=" * 50)

    checks = []  # (name, passed, points, detail)

    # 1. HTTPS
    checks.append(("HTTPS مفعل", is_https, 15, "https" if is_https else "http فقط - غير آمن"))

    # 2. TLS certificate
    if is_https and hostname:
        ok, days, detail = check_tls(hostname)
        if ok and days is not None:
            passed = days > 0
            checks.append(("شهادة TLS صالحة", passed, 10,
                           "تنتهي بعد %d يوما (%s)" % (days, detail) if passed else "منتهية!"))
            if days is not None and 0 < days <= 30:
                print("تنبيه: الشهادة تنتهي قريبا (خلال 30 يوما).")
        else:
            checks.append(("شهادة TLS صالحة", False, 10, detail))
    else:
        checks.append(("شهادة TLS صالحة", False, 10, "لا يوجد HTTPS"))

    status, final_url, headers, fetch_error = fetch_headers(url)
    lower = {k.lower(): v for k, v in headers.items()}

    if status is not None:
        print("حالة الموقع (HTTP):", status)
        if final_url != url:
            print("الوجهة النهائية بعد التحويل:", final_url)
    else:
        print("تعذر الوصول إلى الموقع:", fetch_error)

    def has(name):
        return name in lower and bool(lower[name])

    # 3-9. Security headers
    checks.append(("Strict-Transport-Security (HSTS)", has("strict-transport-security"), 15,
                   lower.get("strict-transport-security", "مفقود")))
    checks.append(("Content-Security-Policy", has("content-security-policy"), 15,
                   "موجود" if has("content-security-policy") else "مفقود"))
    xfo = lower.get("x-frame-options", "")
    csp = lower.get("content-security-policy", "")
    frame_ok = bool(xfo) or "frame-ancestors" in csp
    checks.append(("حماية من التضمين في إطارات (X-Frame-Options)", frame_ok, 10,
                   xfo or ("frame-ancestors في CSP" if frame_ok else "مفقود")))
    checks.append(("X-Content-Type-Options: nosniff", lower.get("x-content-type-options", "").lower() == "nosniff", 10,
                   lower.get("x-content-type-options", "مفقود")))
    checks.append(("Referrer-Policy", has("referrer-policy"), 5,
                   lower.get("referrer-policy", "مفقود")))
    checks.append(("Permissions-Policy", has("permissions-policy"), 5,
                   "موجود" if has("permissions-policy") else "مفقود"))

    # 10. Cookies
    cookies = headers.get("Set-Cookie") or headers.get("set-cookie")
    if cookies:
        low = cookies.lower()
        secure_ok = "secure" in low and "httponly" in low
        checks.append(("ملفات تعريف الارتباط آمنة (Secure + HttpOnly)", secure_ok, 5,
                       "Secure و HttpOnly موجودان" if secure_ok else "ناقصة Secure أو HttpOnly"))
    else:
        checks.append(("ملفات تعريف الارتباط آمنة", True, 5, "لا توجد ملفات تعريف ارتباط في الرد"))

    # 11. Server version disclosure (penalty, not a fail by itself)
    server = lower.get("server", "")
    if server and any(ch.isdigit() for ch in server):
        print("ملاحظة: الخادم يكشف إصداره (%s) - يفضل إخفاؤه." % server)

    total = 0
    max_total = 0
    print("\nالنتائج:")
    for name, passed, points, detail in checks:
        mark = "✔" if passed else "✘"
        gained = points if passed else 0
        total += gained
        max_total += points
        print(" %s %s : %d/%d  - %s" % (mark, name, gained, points, detail))

    score = int(round(100.0 * total / max_total)) if max_total else 0
    print("\n" + "=" * 50)
    print("نسبة أمان الموقع: %d%%" % score)
    print("التقييم:", grade(score))
    print("=" * 50)
    if score < 60:
        print("نصيحة: ابدأ بتفعيل HTTPS و HSTS و Content-Security-Policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
