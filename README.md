# Website Security Checker — المحقق كونان v2.2

نظام فحص أمان قوي لمواقع الويب، بواجهة وحدة تحكم بأسلوب Metasploit،
يعمل في Termux ببايثون فقط (بدون مكتبات إضافية).
لا تحاول الأداة اختراق الموقع أو تسجيل الدخول أو تجاوز أي حماية.
استعملها فقط على موقعك الخاص أو موقع عندك إذن كتابي لفحصه.

**المطور: Hafed Mehdi Salah Eddine — الجزائر 🇩🇿 — يعمل بقوة 💪**
GitHub: M-salah1

## اللغات: English / Français / العربية (RTL)

- العربية تُعرض من اليمين لليسار (RTL) بعلامة اتجاه صحيحة، وليس معكوسة.
- اختر اللغة عند البدء، أو بأمر `lang en|fr|ar` داخل وحدة التحكم،
  أو بخيار `--lang en|fr|ar` في سطر الأوامر.

## الأداة الرئيسية: `conan.py` — المحقق كونان

تفحص:
- DNS و IP و Reverse DNS
- WHOIS العام: المسجل، تاريخ الإنشاء والانتهاء، خوادم الأسماء، وبيانات المالك الظاهرة علناً فقط
- HTTPS وشهادة TLS: الصلاحية بالأيام، الجهة المصدرة، إصدار TLS
- رؤوس الأمان: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy
- الكوكيز: Secure + HttpOnly + SameSite
- كشف إصدار الخادم والتقنية الظاهرة، وملفات robots.txt / sitemap.xml / security.txt، والمحتوى المختلط
- ملخص + نسبة من 100 + تقييم، وقائمة ثغرات (إعدادات ناقصة) مرتبة عالي / متوسط / منخفض مع توصية إصلاح لكل واحدة

## التشغيل في Termux — وحدة تحكم بأسلوب Metasploit

```bash
pkg update && pkg install -y python git
git clone https://github.com/M-salah1/website-security-checker.git
cd website-security-checker
python3 conan.py
```

تختار اللغة أولاً (1 English / 2 Français / 3 العربية)، ثم تظهر وحدة التحكم:

```
   ____ ___  _   _    _    _   _
  / ___/ _ \| \ | |  / \  | \ | |
  ...
   Conan Framework v2.2  •  8 passive checks  •  0 exploits  •  3 languages
   Developer: Hafed Mehdi Salah Eddine  •  الجزائر 🇩🇿

conan >
```

أوامر وحدة التحكم:

```
conan > help
conan > scan https://example.com
conan > set target https://example.com
conan > run
conan > about
conan > developer
conan > lang fr
conan > banner
conan > clear
conan > exit
```

أو فحص مباشر بدون وحدة تحكم:

```bash
python3 conan.py https://example.com
python3 conan.py --lang en https://example.com
python3 conan.py --lang fr https://example.com --json
python3 conan.py https://example.com -o تقرير.json
python3 conan.py --about
python3 conan.py --developer
```

## الأداة البسيطة: `security_check.py`

نسخة أخف تفحص HTTPS وشهادة TLS ورؤوس الأمان فقط وتعطي نسبة وتقييماً:

```bash
python3 security_check.py https://example.com
```

## مثال على النتيجة

```
نسبة أمان الموقع: 85%
التقييم: B - جيد
```

## ملاحظة

النسبة تقدير مبني على الإعدادات الظاهرة فقط، وليست ضمانا كاملا لأمان الموقع.
إذا فحصت من شبكة فيها بروكسي، قد تختلف نتيجة TLS و WHOIS، أما في Termux باتصال مباشر فالنتائج تعكس الموقع الحقيقي.
