#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Conan AI Brain — the detective's reasoning engine.

What it is: a smart expert engine that reads the whole scan the way a
human ethical hacker would — it correlates separate findings into
attack chains ("if A and B are both true, an attacker can do C"),
ranks what to fix first by exploitability, writes a plain-language
verdict, and plans the next authorized tests to run. It learns from
the Site Brain profile: what is new since the last scan is flagged
first.

What it is NOT: it is not a large language model. No LLM can run
offline inside a stdlib-only Termux tool, and this module never
pretends otherwise — it reasons from the tool's own observed evidence
only, and every conclusion names the evidence behind it. (Connecting
an external AI service with the user's own API key is a possible
later step; the key would live only in the user's local .env.)

What it NEVER does: it never executes an attack, never exploits a
vulnerability, never logs in, never extracts data, never brute-forces
and never bypasses anything. It describes attack paths so the
defender can close them — the description is the defense.
"""
import re

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                   "info": 0}
ADMIN_PORTS = {21, 22, 23, 3306, 3389, 5432, 6379, 27017, 5900, 1433}

TEXT = {
    "ar": {
        "verdict_strong": "الموقع قوي دفاعياً: لم أجد مسار هجوم متكامل. أخطر ما وجدته هو: %s",
        "verdict_weak": "الموقع ضعيف: أخطر مسار هجوم هو: %s",
        "verdict_none": "لم أجد مسار هجوم متكاملاً في هذه النتائج، لكن النتيجة العامة (%s%%) تستحق المراجعة.",
        "verdict_incomplete": "الفحص غير مكتمل — لم تُقَس معظم الوحدات، لذلك لا يمكن إعطاء نتيجة أمان. أعد الفحص وستظهر النتيجة الحقيقية.",
        "first_fix": "أول إصلاح: %s",
        "priority": "الأولويات",
        "chains": "مسارات الهجوم المحتملة",
        "next_tests": "الاختبارات التالية المقترحة",
        "new_since_last": "جديد منذ الفحص السابق — افحصه أولاً: %s",
    },
    "en": {
        "verdict_strong": "The site is defensively strong: I found no complete attack path. The most dangerous thing found is: %s",
        "verdict_weak": "The site is weak: the most dangerous attack path is: %s",
        "verdict_none": "I found no complete attack path in these results, but the overall score (%s%%) deserves a review.",
        "verdict_incomplete": "The scan is incomplete — most modules could not be measured, so no security score can be given. Re-run the scan and the real score will appear.",
        "first_fix": "First fix: %s",
        "priority": "Priorities",
        "chains": "Possible attack paths",
        "next_tests": "Suggested next tests",
        "new_since_last": "New since the last scan — check it first: %s",
    },
    "fr": {
        "verdict_strong": "Le site est défensivement solide : je n'ai trouvé aucun chemin d'attaque complet. Le plus dangereux est : %s",
        "verdict_weak": "Le site est faible : le chemin d'attaque le plus dangereux est : %s",
        "verdict_none": "Je n'ai trouvé aucun chemin d'attaque complet, mais le score global (%s%%) mérite un examen.",
        "verdict_incomplete": "Le scan est incomplet — la plupart des modules n'ont pas pu être mesurés, donc aucun score de sécurité ne peut être donné. Relancez le scan et le vrai score apparaîtra.",
        "first_fix": "Premier correctif : %s",
        "priority": "Priorités",
        "chains": "Chemins d'attaque possibles",
        "next_tests": "Tests suivants suggérés",
        "new_since_last": "Nouveau depuis le dernier scan — vérifiez-le d'abord : %s",
    },
}

# Each chain: signals it needs, severity, and its story in 3 languages.
# The story describes the path conceptually so the defender can close
# it — it is a pentest report, not an exploit.
CHAINS = [
    {
        "id": "xss-session-theft",
        "needs": ["csp_missing", "httponly_missing"],
        "keywords": ["content-security-policy", "httponly"],
        "severity": "high",
        "title": {
            "ar": "سرقة جلسة عبر XSS",
            "en": "Session theft via XSS",
            "fr": "Vol de session via XSS"},
        "story": {
            "ar": "لا توجد سياسة CSP تحصر مصادر السكربت، وكوكيز الجلسة بلا HttpOnly. إن وُجد حقل يعكس مدخلات الزائر، يستطيع مهاجم حقن سكربت يقرأ كوكيز الجلسة.",
            "en": "No CSP restricts script sources, and the session cookie lacks HttpOnly. If any field reflects visitor input, an attacker can inject a script that reads the session cookie.",
            "fr": "Aucun CSP ne limite les sources de scripts et le cookie de session n'a pas HttpOnly. Si un champ reflète l'entrée du visiteur, un attaquant peut injecter un script qui lit le cookie de session."},
        "stop": {
            "ar": "فعّل CSP صارماً (default-src 'self') وأضف HttpOnly وSecure لكل كوكيز الجلسة.",
            "en": "Enable a strict CSP (default-src 'self') and add HttpOnly and Secure to every session cookie.",
            "fr": "Activez un CSP strict (default-src 'self') et ajoutez HttpOnly et Secure à chaque cookie de session."},
    },
    {
        "id": "session-hijack-wire",
        "needs": ["secure_missing", "http_site"],
        "keywords": ["secure", "https"],
        "severity": "high",
        "title": {
            "ar": "اختطاف جلسة عبر الشبكة",
            "en": "Session hijacking over the network",
            "fr": "Détournement de session sur le réseau"},
        "story": {
            "ar": "الموقع يعمل بدون HTTPS وكوكيز الجلسة بلا Secure، فيُرسَل معرّف الجلسة نصاً صريحاً. أي شخص على نفس الشبكة يستطيع التقاطه واستعماله.",
            "en": "The site runs without HTTPS and the session cookie lacks Secure, so the session ID travels in plain text. Anyone on the same network can capture and reuse it.",
            "fr": "Le site fonctionne sans HTTPS et le cookie de session n'a pas Secure : l'identifiant de session circule en clair. Toute personne sur le même réseau peut le capturer et le réutiliser."},
        "stop": {
            "ar": "فعّل HTTPS وأعد توجيه كل http إلى https، وأضف Secure وHSTS.",
            "en": "Enable HTTPS, redirect all http to https, and add Secure and HSTS.",
            "fr": "Activez HTTPS, redirigez tout http vers https, et ajoutez Secure et HSTS."},
    },
    {
        "id": "clickjacking",
        "needs": ["xframe_missing", "forms_present"],
        "keywords": ["x-frame-options"],
        "severity": "medium",
        "title": {
            "ar": "خداع النقر (Clickjacking)",
            "en": "Clickjacking",
            "fr": "Clickjacking"},
        "story": {
            "ar": "لا يوجد X-Frame-Options والموقع فيه نماذج. يستطيع مهاجم تضمين الموقع داخل إطار خفي في صفحة أخرى وخداع الزائر للنقر على أزرار لا يراها.",
            "en": "No X-Frame-Options and the site has forms. An attacker can embed the site in a hidden frame on another page and trick visitors into clicking buttons they cannot see.",
            "fr": "Pas de X-Frame-Options et le site a des formulaires. Un attaquant peut intégrer le site dans un cadre caché et tromper les visiteurs pour qu'ils cliquent sur des boutons invisibles."},
        "stop": {
            "ar": "أضف X-Frame-Options: DENY أو SAMEORIGIN.",
            "en": "Add X-Frame-Options: DENY or SAMEORIGIN.",
            "fr": "Ajoutez X-Frame-Options : DENY ou SAMEORIGIN."},
    },
    {
        "id": "admin-service-exposed",
        "needs": ["admin_ports_open"],
        "keywords": [],
        "severity": "high",
        "title": {
            "ar": "خدمة إدارية مكشوفة للإنترنت",
            "en": "Admin service exposed to the internet",
            "fr": "Service d'administration exposé à Internet"},
        "story": {
            "ar": "منافذ إدارية (SSH / RDP / قواعد بيانات) مفتوحة للإنترنت. كل محاولة تخمين أو ثغرة في واحدة منها تصبح باباً مباشراً إلى الخادم.",
            "en": "Admin ports (SSH / RDP / databases) are open to the internet. Every guessing attempt or flaw in one of them becomes a direct door into the server.",
            "fr": "Des ports d'administration (SSH / RDP / bases de données) sont ouverts à Internet. Chaque tentative de devinette ou faille devient une porte directe vers le serveur."},
        "stop": {
            "ar": "أغلق المنافذ الإدارية عن الإنترنت أو قيّدها بعناوين IP موثوقة وVPN.",
            "en": "Close admin ports to the internet or restrict them to trusted IPs and a VPN.",
            "fr": "Fermez les ports d'administration à Internet ou limitez-les aux IP de confiance et à un VPN."},
    },
    {
        "id": "fingerprint-targeting",
        "needs": ["server_version"],
        "keywords": ["server"],
        "severity": "medium",
        "title": {
            "ar": "بصمة الخادم تكشف هدفه",
            "en": "Server fingerprinting enables targeting",
            "fr": "Empreinte du serveur permet le ciblage"},
        "story": {
            "ar": "ترويسة الخادم تكشف نوعه وإصداره. المهاجم لا يحتاج أن يجرّب كل شيء — يعرف مباشرة أي ثغرات معروفة تنطبق على هذا الإصدار بالذات.",
            "en": "The server header reveals its type and version. An attacker does not need to guess — they know immediately which known vulnerabilities apply to this exact version.",
            "fr": "L'en-tête du serveur révèle son type et sa version. L'attaquant n'a pas besoin de deviner — il sait immédiatement quelles vulnérabilités connues s'appliquent à cette version."},
        "stop": {
            "ar": "أخفِ إصدار الخادم من الترويسات وصفحات الخطأ.",
            "en": "Hide the server version from headers and error pages.",
            "fr": "Masquez la version du serveur dans les en-têtes et les pages d'erreur."},
    },
    {
        "id": "cors-data-theft",
        "needs": ["cors_wildcard", "api_endpoints"],
        "keywords": ["cors"],
        "severity": "medium",
        "title": {
            "ar": "سرقة بيانات عبر CORS مفتوح",
            "en": "Data theft via open CORS",
            "fr": "Vol de données via CORS ouvert"},
        "story": {
            "ar": "الموقع يسمح لأي مصدر (CORS *) ولديه نقاط API. موقع خبيث يستطيع استدعاء الـ API من متصفح الزائر وقراءة ما يردّ به.",
            "en": "The site allows any origin (CORS *) and has API endpoints. A malicious site can call the API from the visitor's browser and read its responses.",
            "fr": "Le site autorise toute origine (CORS *) et possède des points d'API. Un site malveillant peut appeler l'API depuis le navigateur du visiteur et lire ses réponses."},
        "stop": {
            "ar": "قيّد Access-Control-Allow-Origin بنطاقاتك فقط، ولا تعتمد على CORS للحماية.",
            "en": "Restrict Access-Control-Allow-Origin to your own domains only.",
            "fr": "Limitez Access-Control-Allow-Origin à vos propres domaines."},
    },
]

NEXT_TESTS = [
    {
        "id": "auth-audit",
        "when": ["forms_present"],
        "text": {
            "ar": "تدقيق المصادقة (القائمة 8) — اختبر نموذج الدخول بإذن صريح",
            "en": "Authentication audit (menu 8) — test the login form with explicit permission",
            "fr": "Audit d'authentification (menu 8) — testez le formulaire de connexion avec permission explicite"},
    },
    {
        "id": "api-audit",
        "when": ["api_endpoints"],
        "text": {
            "ar": "تدقيق الـ API (القائمة 10) — افحص النقاط المكتشفة",
            "en": "API audit (menu 10) — inspect the discovered endpoints",
            "fr": "Audit API (menu 10) — inspectez les points découverts"},
    },
    {
        "id": "full-port-scan",
        "when": ["admin_ports_open"],
        "text": {
            "ar": "فحص كامل للمنافذ (لوحة النتائج 6) — تأكد من كل الأبواب",
            "en": "Full port scan (dashboard 6) — verify every door",
            "fr": "Scan complet des ports (tableau 6) — vérifiez chaque porte"},
    },
    {
        "id": "session-test",
        "when": ["httponly_missing", "secure_missing"],
        "text": {
            "ar": "اختبار الجلسات (القائمة 8/9) — تحقق من حماية الكوكيز بعد الإصلاح",
            "en": "Session test (menu 8/9) — verify cookie protection after the fix",
            "fr": "Test de session (menu 8/9) — vérifiez la protection des cookies après correctif"},
    },
    {
        "id": "rescan",
        "when": [],
        "text": {
            "ar": "أصلح أول نتيجة ثم أعد الفحص — قارن النتيجة الجديدة بالملف التعريفي",
            "en": "Fix the top finding, then re-scan — compare the new score with the profile",
            "fr": "Corrigez le premier résultat puis relancez le scan — comparez le nouveau score au profil"},
    },
]


def _signals(scan):
    """Boolean signals computed from the scan's own evidence."""
    blob = []
    for f in (scan.get("findings") or []):
        blob.append((f.get("name", "") + " " + f.get("evidence", "")).lower())
    text = " ".join(blob)
    ports = scan.get("ports") or {}
    open_ports = [p["port"] for p in (ports.get("open_ports") or [])]
    perms = scan.get("permissions") or {}
    server = (scan.get("servers") or {}).get("server_header") or ""
    return {
        "csp_missing": "content-security-policy" in text and "missing" in text,
        "httponly_missing": "httponly" in text,
        "secure_missing": "secure" in text and "cookie" in text,
        "hsts_missing": "hsts" in text,
        "xframe_missing": "x-frame-options" in text,
        "http_site": ("without https" in text or "بدون https" in text
                      or (scan.get("target") or "").startswith("http://")),
        "forms_present": bool((scan.get("forms") or {}).get("forms")),
        "admin_ports_open": bool(set(open_ports) & ADMIN_PORTS),
        "server_version": bool(re.search(r"\d+\.\d+", server)),
        "cors_wildcard": (perms.get("cors") or "").strip() == "*",
        "api_endpoints": bool((scan.get("js_api") or {}).get("endpoints")),
    }


def _priority_list(scan):
    """Rank findings by exploitability: severity × confidence."""
    ranked = []
    for f in (scan.get("findings") or []):
        weight = SEVERITY_WEIGHT.get(f.get("severity"), 0)
        conf = int(f.get("confidence") or 0)
        ranked.append((weight * conf, f))
    ranked.sort(key=lambda item: -item[0])
    return [{"name": f["name"], "severity": f["severity"],
             "score": score, "remediation": f.get("remediation", "")}
            for score, f in ranked[:5] if score > 0]


def analyze(scan, lang="ar"):
    """Reason over a full scan. Returns the AI Brain verdict dict."""
    labels = TEXT.get(lang, TEXT["en"])
    sig = _signals(scan)
    chains = []
    for chain in CHAINS:
        if all(sig.get(need) for need in chain["needs"]):
            keywords = chain.get("keywords") or []
            evidence = [f["name"] for f in (scan.get("findings") or [])
                        if any(kw in (f.get("name", "") + " " +
                                      f.get("evidence", "")).lower()
                               for kw in keywords)][:3]
            if chain["id"] == "admin-service-exposed":
                ports = scan.get("ports") or {}
                admin_open = [p["port"] for p in
                              (ports.get("open_ports") or [])
                              if p["port"] in ADMIN_PORTS]
                evidence = ["open port %d" % p for p in admin_open][:3]
            chains.append({
                "id": chain["id"], "severity": chain["severity"],
                "title": chain["title"].get(lang, chain["title"]["en"]),
                "story": chain["story"].get(lang, chain["story"]["en"]),
                "stop": chain["stop"].get(lang, chain["stop"]["en"]),
                "evidence": evidence,
            })
    priorities = _priority_list(scan)
    next_tests = []
    for test in NEXT_TESTS:
        if all(sig.get(w) for w in test["when"]):
            next_tests.append(test["text"].get(lang, test["text"]["en"]))
    new_items = []
    for ch in (scan.get("learned_changes") or []):
        if ch.get("kind") == "added":
            new_items.append(ch.get("detail", ""))
    if chains:
        top = chains[0]
        score = scan.get("score")
        if score is None:
            verdict = labels["verdict_incomplete"]
        elif isinstance(score, (int, float)) and score >= 70:
            verdict = labels["verdict_strong"] % top["title"]
        else:
            verdict = labels["verdict_weak"] % top["title"]
    elif scan.get("score") is None:
        verdict = labels["verdict_incomplete"]
    elif priorities:
        verdict = labels["verdict_none"] % (scan.get("score"))
    else:
        verdict = labels["verdict_none"] % (scan.get("score"))
    first_fix = ""
    if priorities:
        first_fix = labels["first_fix"] % (
            priorities[0]["remediation"] or priorities[0]["name"])
    return {
        "verdict": verdict,
        "first_fix": first_fix,
        "chains": chains,
        "priorities": priorities,
        "next_tests": next_tests[:4],
        "new_since_last": [
            labels["new_since_last"] % item for item in new_items[:3]],
    }
