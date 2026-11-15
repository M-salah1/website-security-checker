# المحقق كونان - Conan Detective 2.0

أداة فحص أمان دفاعية سلبية لموقع ويب، تعمل في Termux ببايثون فقط (بدون مكتبات إضافية).

## ماذا تفحص؟
- DNS و IP و Reverse DNS
- WHOIS العام: المسجل، تاريخ الإنشاء والانتهاء، خوادم الأسماء، وبيانات المالك الظاهرة علناً فقط
- HTTPS وشهادة TLS: الصلاحية بالأيام، الجهة المصدرة، إصدار TLS
- رؤوس الأمان: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy
- الكوكيز: Secure + HttpOnly + SameSite
- كشف إصدار الخادم والتقنية الظاهرة
- ملفات عامة: robots.txt / sitemap.xml / security.txt
- محتوى مختلط http داخل صفحة https
- ملخص + نسبة من 100 + تقييم + قائمة ثغرات (إعدادات ناقصة) مرتبة عالي / متوسط / منخفض مع توصية إصلاح لكل واحدة

## ماذا لا تفعل؟
لا تستغل أي ثغرة، لا ترسل حمولات SQLi / XSS، لا تجرب كلمات مرور، لا تبحث عن لوحات تحكم بالقوة، ولا تسجل الدخول.
استعملها فقط على موقعك الخاص أو موقع عندك إذن كتابي لفحصه.

## التشغيل في Termux
```bash
pkg update && pkg install -y python
python3 conan.py https://example.com
```

خيارات:
```bash
python3 conan.py https://example.com --json
python3 conan.py https://example.com -o تقرير.json
python3 conan.py
# ثم اكتب الرابط عندما تسألك الأداة
```

## الحصول على الملف في Termux
المستودع على GitHub لم يُنشأ بعد، لذلك لا يوجد رابط clone يعمل حالياً.
أسرع طريقة: حمّل ملف `conan.py` المرفق من تطبيق Muse، ثم انسخه إلى Termux:
```bash
termux-setup-storage
cp ~/storage/downloads/conan.py ~/
python3 ~/conan.py https://example.com
```

## ملاحظة عن النتائج
النسبة تقدير مبني على الإعدادات الظاهرة فقط، وليست ضماناً كاملاً للأمان.
إذا فحصت من شبكة فيها بروكسي، قد تختلف نتيجة TLS و WHOIS، أما في Termux باتصال مباشر فالنتائج تعكس الموقع الحقيقي.
