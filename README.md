# Website Security Checker — المحقق كونان v2.1

نظام فحص أمان قوي لمواقع الويب، يعمل في Termux ببايثون فقط (بدون مكتبات إضافية).
لا تحاول الأداة اختراق الموقع أو تسجيل الدخول أو تجاوز أي حماية.
استعملها فقط على موقعك الخاص أو موقع عندك إذن كتابي لفحصه.

**المطور: Hafed Mehdi Salaj Eddine — الجزائر 🇩🇿 — يعمل بقوة 💪**
GitHub: M-salah1

## الأداة الرئيسية: `conan.py` — المحقق كونان

تفحص:
- DNS و IP و Reverse DNS
- WHOIS العام: المسجل، تاريخ الإنشاء والانتهاء، خوادم الأسماء، وبيانات المالك الظاهرة علناً فقط
- HTTPS وشهادة TLS: الصلاحية بالأيام، الجهة المصدرة، إصدار TLS
- رؤوس الأمان: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy
- الكوكيز: Secure + HttpOnly + SameSite
- كشف إصدار الخادم والتقنية الظاهرة، وملفات robots.txt / sitemap.xml / security.txt، والمحتوى المختلط
- ملخص + نسبة من 100 + تقييم، وقائمة ثغرات (إعدادات ناقصة) مرتبة عالي / متوسط / منخفض مع توصية إصلاح لكل واحدة

## التشغيل في Termux — الواجهة التفاعلية

```bash
pkg update && pkg install -y python git
git clone https://github.com/M-salah1/website-security-checker.git
cd website-security-checker
python3 conan.py
```

تفتح لك الواجهة القوية:
- **[1] فحص موقع** — اكتب الرابط ويعطيك التقرير الكامل، مع خيار حفظ JSON
- **[2] عن الأداة** — تعريف كامل بالنظام وما يفحص وما لا يفعل
- **[3] عن المطور** — Hafed Mehdi Salaj Eddine من الجزائر
- **[0] خروج**

أو فحص مباشر بدون قائمة:

```bash
python3 conan.py https://example.com
python3 conan.py https://example.com --json
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
