#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN VICTIM PROTECTION — help for people being threatened online.

For girls, children and anyone facing threats, harassment, doxxing or
non-consensual images. This module never fetches the reported URL, never
downloads or stores any content from it, and never contacts anyone:
it gives the victim a safety plan, an evidence checklist and the
official reporting channels, and records safe metadata only.

If a child is in immediate danger, contact local police / emergency
services first — before using any tool.
"""
from ..scanners.child_safety import REPORT_CHANNELS, analyze_reported_url

_SAFETY_PLAN = {
    "ar": [
        "لا تردّي على المهدِّد ولا تتفاوضي معه — كل ردّ يعطيه معلومات أكثر.",
        "احفظي الأدلة فوراً: روابط، لقطات شاشة، رسائل، تواريخ وأوقات — ولا تحذفي شيئاً.",
        "احظري الحساب المهدِّد وبلّغي عنه داخل المنصة نفسها (زر الإبلاغ).",
        "غيّري كلمات المرور من الموقع الرسمي فقط، وفعّلي التحقق بخطوتين، وسجّلي الخروج من كل الأجهزة.",
        "أخبري شخصاً بالغاً تثقين به (أحد الوالدين أو معلّم) — لا تواجهي هذا وحدك.",
        "بلّغي الشرطة والقنوات الرسمية أدناه، وقدّمي لهم الأدلة المحفوظة.",
        "لا تنشري الأدلة علناً ولا ترسليها لأشخاص آخرين.",
    ],
    "en": [
        "Do not reply to the person threatening you and do not negotiate — every reply gives them more information.",
        "Preserve evidence immediately: URLs, screenshots, messages, dates and times — do not delete anything.",
        "Block the threatening account and report it inside the platform itself (the report button).",
        "Change passwords from the official site only, enable two-factor authentication, and sign out of all devices.",
        "Tell a trusted adult (a parent or teacher) — do not face this alone.",
        "Report to the police and the official channels below, and give them the preserved evidence.",
        "Do not publish the evidence publicly and do not forward it to other people.",
    ],
    "fr": [
        "Ne répondez pas à la personne qui vous menace et ne négociez pas — chaque réponse lui donne plus d'informations.",
        "Préservez les preuves immédiatement : URL, captures d'écran, messages, dates et heures — ne supprimez rien.",
        "Bloquez le compte menaçant et signalez-le dans la plateforme elle-même (bouton de signalement).",
        "Changez vos mots de passe depuis le site officiel uniquement, activez l'authentification à deux facteurs et déconnectez tous les appareils.",
        "Parlez-en à un adulte de confiance (un parent ou un enseignant) — n'affrontez pas cela seule.",
        "Signalez à la police et aux canaux officiels ci-dessous, et remettez-leur les preuves conservées.",
        "Ne publiez pas les preuves publiquement et ne les transférez pas à d'autres personnes.",
    ],
}

_EVIDENCE_CHECKLIST = {
    "ar": [
        "رابط الصفحة أو الحساب المهدِّد (انسخيه كما هو).",
        "لقطة شاشة كاملة تظهر فيها الرسالة والتاريخ والوقت واسم الحساب.",
        "تصدير المحادثة إن أمكن (من إعدادات التطبيق).",
        "تاريخ ووقت أول تهديد وآخر تهديد.",
        "أي أسماء مستعارة أو حسابات أخرى لنفس الشخص.",
        "احسبي بصمة SHA-256 للملفات المحفوظة واحتفظي بها دون تعديل.",
    ],
    "en": [
        "The URL of the threatening page or account (copy it as-is).",
        "A full screenshot showing the message, date, time and account name.",
        "An export of the conversation if the app allows it (from settings).",
        "Date and time of the first and the latest threat.",
        "Any other nicknames or accounts belonging to the same person.",
        "Compute the SHA-256 hash of the saved files and keep them unmodified.",
    ],
    "fr": [
        "L'URL de la page ou du compte menaçant (copiez-la telle quelle).",
        "Une capture d'écran complète montrant le message, la date, l'heure et le nom du compte.",
        "Un export de la conversation si l'application le permet (depuis les paramètres).",
        "Date et heure de la première et de la dernière menace.",
        "Tout autre pseudonyme ou compte appartenant à la même personne.",
        "Calculez l'empreinte SHA-256 des fichiers conservés et gardez-les intacts.",
    ],
}


def safety_plan(lang="ar"):
    return list(_SAFETY_PLAN.get(lang, _SAFETY_PLAN["en"]))


def evidence_checklist(lang="ar"):
    return list(_EVIDENCE_CHECKLIST.get(lang, _EVIDENCE_CHECKLIST["en"]))


def report_channels():
    return list(REPORT_CHANNELS)


def create_protection_case(url, category, notes=""):
    """Record a protection case: safe metadata only, URL never fetched.

    Returns the incident record plus the safety plan and evidence
    checklist in the three languages. No content is downloaded or stored.
    """
    rec = analyze_reported_url(url, category, notes)
    rec["safety_plan"] = {lang: safety_plan(lang) for lang in ("ar", "en", "fr")}
    rec["evidence_checklist"] = {lang: evidence_checklist(lang) for lang in ("ar", "en", "fr")}
    rec["content_downloaded"] = False
    rec["content_stored"] = False
    return rec
