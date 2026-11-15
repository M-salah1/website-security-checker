# CONAN FRAMEWORK v4.1 — ULTIMATE CYBER INVESTIGATION SYSTEM 🔍

**CONAN DETECTIVE** — منصة تحقيق سيبراني معيارية متعددة اللغات.

Developer: **Hafed Mehdi Salah Eddine** — Algeria 🇩🇿
GitHub: **M-salah1** — Copyright © 2026

- Python standard library only — no required dependencies
- 17-option interactive menu • wizard-driven investigations • 3 languages (العربية / Français / English, RTL)
- Works on Android Termux, Linux and Windows PowerShell

## Start

```bash
python3 conan.py                        # menu: welcome + language + 17 options
python3 conan.py shell                  # interactive shell: conan >
python3 conan.py https://example.com    # direct full scan
python3 conan.py https://example.com --json
python3 conan.py --version
```

## Main menu

| # | Option | What it really does |
|---|---|---|
| 1 | Website Security Investigation | Full universal investigation (DNS, TLS, headers, cookies, health, discovery, forms, API, exposure, phishing, paths, vulns) with bounded concurrency + case ID |
| 2 | Advanced Website Vulnerability Audit | Headers, cookies, CSRF, SQLi, XSS, file-upload inspection (authorized only) |
| 3 | IP Intelligence & Network Investigation | Geo estimate (ip-api.com), RDAP, PTR, TCP/TLS/HTTP checks for IPv4/IPv6 |
| 4 | Phishing & Fake Website Detection | Homograph, typosquat similarity, domain age, TLS, redirects, cross-domain login forms — risk 0–100 |
| 5 | Domain & Ownership Intelligence | WHOIS, DNS, hosting, CDN, TLS issuer, Certificate Transparency, org facts (unknown = UNKNOWN) |
| 6 | Sensitive Information Exposure Audit | Public files, sitemap, CT subdomains, secret-pattern scan — values always [REDACTED] |
| 7 | Hidden Paths & File Discovery | Bounded path list on authorized domains, categorized by real HTTP status |
| 8 | Authentication & Login Security | Login-form discovery + authorized login test (rotation, rate limit) |
| 9 | Registration Security Testing | Registration-form analysis on authorized staging sites |
| 10 | API Discovery & Analysis | Public endpoints from HTML/JS + intentionally exposed OpenAPI docs |
| 11 | Malware & Trojan Detection | Static analysis of page + linked JS (no code executed) |
| 12 | Malware Laboratory Simulator | Isolated lab with harmless samples (EICAR test string, benign + obfuscated demo) |
| 13 | Website Availability Monitoring | DNS/TCP/TLS/HTTP timing + stored history (a 403 is ONLINE, not offline) |
| 14 | Digital Evidence Collection | Export case evidence (JSON + HTML + SHA-256) and record safety/abuse incidents (metadata only) |
| 15 | Previous Investigations | Cases + sessions, compare two scans |
| 16 | Settings | Language, animation, timeout, max pages, scope |
| 17 | Exit | |

Navigation: no commands to memorise. After the language screen you get a
numbered menu — type `1` for a scan, enter the URL, press Enter. At any
prompt, **0** is the back button (also `BACK` / `رجوع`): it returns to the
previous screen or the main menu, and `0` on the main menu exits.
BACK preserves completed results — cases live in `conan-cases.json` and
sessions in `conan-sessions.json`.

## Scope and authorization — read this first

Passive checks run on any public site. **Active tests** (vulnerability
audit, path discovery, login/registration tests) require explicit
authorization:

```
scope add https://your-site.com owned
```

Localhost / private test environments are always in scope. State-changing
operations ask for confirmation right before they run.

**Never built into Conan:** password guessing, brute force, credential
stuffing, account takeover, auth bypass, destructive testing, unauthorized
account creation, covert Trojans, remote-access malware, credential
stealers, hidden web shells. **Passwords and session-cookie values are
never displayed, logged or stored in any report** — exposure is reported
(type + location + [REDACTED]) with rotation advice, exactly as the spec
requires (sections 6, 7, 12, 15).

**Child safety:** the reporting module never downloads, stores or displays
abuse content and never crawls for it. It records safe incident metadata
only and gives official channels (NCMEC CyberTipline, INHOPE, INTERPOL,
local law enforcement).

Use Conan only on your own sites or sites you have written authorization to test.

## Installation

**Termux (Android):**
```bash
pkg update && pkg install -y python git
git clone https://github.com/M-salah1/website-security-checker.git
cd website-security-checker
python3 conan.py
```

**Linux:**
```bash
git clone https://github.com/M-salah1/website-security-checker.git
cd website-security-checker
python3 conan.py
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/M-salah1/website-security-checker.git
cd website-security-checker
python conan.py
```

No `pip install` needed. Optional: `pip install cryptography argon2-cffi rich`
for faster crypto and richer rendering (fallbacks are built in).

## Architecture

```
conan.py                 Launcher (menu / shell / direct scan)
conan/
  __init__.py  menu_app.py  cli.py        # menu app + v3 shell (preserved)
  core/
    engine.py            v2.4 audit engine (preserved, VERSION 4.0)
    menu.py              17-option menu + wizard
    navigation.py        stack + persistent sessions
    i18n.py              ar/fr/en (JSON files in localization/)
    authorization.py     scope wizard (wraps scope.py)
    terminal.py          colours, terminal detection, progress bar
    animation.py         threaded cinematic investigation
    scope.py             authorization manager
    configuration.py     settings (conan-settings.json)
    security.py          secret redaction
    encryption.py        AES-256-GCM + scrypt/Argon2id + HMAC
    evidence.py          finding model (severity, confidence, evidence)
  scanners/
    website.py  ip_intelligence.py  domain_intelligence.py  exposure.py
    paths.py  malware.py  child_safety.py  discovery.py  vulnerabilities.py
    authentication.py  registration.py  phishing.py  health.py  tls.py
    dns.py  cookies.py  headers.py  forms.py  api.py  sessions.py  _http.py
  intelligence/
    osint.py  reputation.py  organization.py  relationships.py
  laboratory/
    simulator.py  test_samples.py  static_analysis.py
  reporting/
    json_report.py  html_report.py   # multilingual, redacted at the boundary
  storage/
    database.py  history.py  cases.py  # case IDs + SHA-256 evidence hashes
  localization/
    ar.json  fr.json  en.json
tests/                   unittest suite (offline + live, skips gracefully)
requirements.txt         stdlib only (optional deps commented)
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Test results (2026-11-15, sandbox): **52 tests, all passing** — i18n key
parity across 3 languages, navigation stack, persistent sessions, cases +
evidence export, redaction, scope, encryption vectors (FIPS-197 AES-256 +
NIST GCM test case 3), phishing similarity/homograph, headers/cookies,
health (403 = ONLINE), DNS classification, TLS shape, IP validation, path
categorization, exposure redaction, EICAR detection, lab simulation,
child-safety metadata-only, live website investigation.

Live smoke tests: menu in Arabic → English (IP 8.8.8.8: Google LLC,
Ashburn, ASN AS15169, RDAP, TCP 80/443 open), malware lab (EICAR detected),
option 1 full investigation on https://example.com (case CN-20261115-0001,
score 28% F, 10 findings, confidence 88%), evidence export
(JSON + HTML + SHA-256), shell and direct-scan modes preserved.

Note: in sandboxed/proxied environments some public sources are
unreachable (WHOIS server, crt.sh returns 502) — those fields are reported
as UNKNOWN/unverifiable, never invented. Real Termux results are the true ones.

## The simple tool: `security_check.py`

The original light checker (HTTPS/TLS/headers, score) is still in the repo
unchanged for quick one-off checks.
