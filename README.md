# CONAN FRAMEWORK v5.6 — ULTIMATE CYBER INVESTIGATION SYSTEM 🔍

**CONAN DETECTIVE** — منصة تحقيق سيبراني معيارية متعددة اللغات.

Developer: **Hafed Mehdi Salah Eddine** — Algeria 🇩🇿
GitHub: **M-salah1** — Copyright © 2026

- Python standard library only — no required dependencies
- **Command console**: full welcome page on entry, then a `conan >` prompt — `scan <url>`, `help`, `menu`, `about`, `lang`, `version`, `clear`, `exit`
- **MEGA SCAN**: `scan <url>` runs every module together, one detailed report (identity, domain history, admin contact, country, servers, paths, deep tests)
- 20-option interactive menu (via `menu`, or `python3 conan.py menu`) • 3 languages (العربية / Français / English, RTL)
- v5.6 Ethical Defender Edition: safe lab, victim protection, defense center, animated reports
- Works on Android Termux, Linux and Windows PowerShell

## Start

```bash
python3 conan.py                        # welcome page + language + console (conan >)
python3 conan.py menu                   # classic 20-option menu
python3 conan.py shell                  # advanced interactive shell: conan >
python3 conan.py https://example.com    # direct full scan
python3 conan.py https://example.com --json
python3 conan.py --version
```

## Console — commands & work guide

After the welcome page and language selection you are at the `conan >` prompt:

| Command | What it does |
|---|---|
| `scan <url>` | Mega scan: terms question (type `y`), then everything together — during the scan only `Scanning...` is shown |
| `<url>` | Same as `scan <url>` — just type the site directly |
| `help` | The full work guide (all commands + how to work with the tool) |
| `menu` | Classic 20-option menu (returns to the console afterwards) |
| `about` | The welcome page again: tool + developer |
| `lang` | Change language |
| `version` | Show version |
| `clear` | Clear the screen |
| `exit` | Quit |

## Entry flow — welcome, URL, ethical terms

1. **Welcome page**: a complete graphical entry screen introducing the tool and its developer — Hafed Mehdi Salah Eddine (Algeria, GitHub M-salah1, FOX COMPANY) — plus how to work with it.
2. **Enter the site**: at the console, type `scan example.com` (a bare domain works too).
3. **Ethical terms**: the tool asks whether you really want to continue — you confirm you are an ethical hacker, you audit only your own site or one you have written permission for, and you are responsible for everything under the terms and the law. Type **y** to accept and the work begins; anything else cancels back to the console.

## Mega Scan — what the detailed report contains

1. **Identity & location** — domain, country (geo estimate), city/region, hosting org
2. **Domain history** — registration / expiry / registrar / registrant org from public WHOIS, earliest certificate from the public CT log, logged hostnames. Previous names and rename dates are WHOIS history (paid service) — shown as UNKNOWN with the reason, never invented
3. **Admin contact** — only what the site itself publishes (security.txt contacts, public WHOIS org, mailto links and contact lines from its own public about/contact pages); redacted or undisclosed = UNKNOWN
4. **Servers** — web-server header, IPs, nameservers, MX, TLS issuer, allowed HTTP methods, redirect chain
5. **Paths** — bounded deep-path probe (authorized targets only) + discovered pages
6. **Cookies** — shown by name and flags (Secure / HttpOnly / SameSite) only; values are never shown
7. **API & reverse engineering** — endpoints, GraphQL and WebSocket URLs extracted from the site's own publicly served JavaScript
8. **Real IP & origin** — every resolved IP, CDN detection, one plain direct-IP request; the origin is UNCONFIRMED unless a direct request proves it
9. **Permissions & certificates** — Permissions-Policy, CORS, CSP, TLS issuer and days left, CT certificate count
10. **Deep tests** — health, DNS/DNSSEC, TLS, headers, cookies, forms, API, discovery, exposure, phishing, vulnerability indicators, core score/grade — with findings, evidence and fixes

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
| 17 | Safe Lab & Ethical Training | Deliberately vulnerable demo site on 127.0.0.1 only — practice the scanners safely, every finding explained with its fix |
| 18 | Victim Protection & Incident Response | Safety plan, evidence checklist and official reporting channels (NCMEC / INHOPE / INTERPOL) — no URL is ever fetched, no content downloaded |
| 19 | Defense, Hardening & Deterrence | Apache/Nginx hardening snippets, CSP, rate-limit guidance, incident-response plan, abuse-report letter template, animated HTML report |
| 20 | Exit | |

Navigation: no commands to memorise. After the language screen you get a
numbered menu — type `1` for a scan, enter the URL, press Enter. At any
prompt, **0** is the back button (also `BACK` / `رجوع`): it returns to the
previous screen or the main menu, and `0` on the main menu exits.
BACK preserves completed results — cases live in `conan-cases.json` and
sessions in `conan-sessions.json`.

## Ethical Defender Edition — what it is and what it is not

**Built for ethical hackers and defenders:** a safe lab on localhost to
train on, authorized non-destructive tests on your own sites (or sites
with written authorization), strong public-information gathering, and
defense tools that protect victims — safety plan, evidence preservation
and official reporting channels for girls, children and anyone
threatened online.

**"Counter-attacks" in Conan mean defensive deterrence only:** hardening
your own server, rate-limiting and blocking abuse at your own firewall,
preserving evidence, and reporting to the host/registrar and the police.
Conan never attacks an attacker's machine, never launches DDoS, never
guesses passwords, never bypasses logins, and never shows password or
session-cookie values.

## v5.1 Design release — animated interface, one-line loader, readable Arabic

- **Animated design:** a magnifying-glass sweep intro on startup, a
  coloured numbered menu (orange numbers, green protection-mode line),
  and the existing animated HTML report (radar sweep, animated score ring).
- **One-line loader:** the whole scan progress lives on a single
  terminal line — spinner, radar, progress bar, elapsed time, current
  phase and the latest log message are redrawn in place; nothing opens
  a new line while loading.
- **Readable Arabic on Termux:** some terminals show Arabic reversed
  ("عربي" appears as "يبرع"). Conan now prints Arabic pre-reversed by
  default, so the terminal flips it back to readable Arabic. Latin
  text, digits and URLs are untouched. Toggle it in Settings (menu 16,
  option 6) or in `conan-settings.json` (`"reverse_arabic": false`).

## Telegram delivery (v5.6) — optional

After a scan, the dashboard offers **5. Telegram**: the tool sends the
full private report to your own Telegram account.

1. On Telegram, create a bot with [@BotFather](https://t.me/BotFather)
   and copy its token. Start a chat with your bot.
2. Find your own account ID (Chat ID) with
   [@userinfobot](https://t.me/userinfobot).
3. In Conan, after a scan choose **5**, enter your Chat ID, then type
   the bot token — it is typed hidden, sent only to Telegram's official
   API (`api.telegram.org`), and **never saved, stored or printed**
   anywhere. The message contains the tool name, the developer, a short
   intro, the target site, the score/grade, the findings and the
   detailed sections; long reports are split into several messages
   (Telegram's 4096-character limit).

If the token or the ID is wrong, Conan prints the Telegram error and
nothing is sent.

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
    menu.py              20-option menu + wizard
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
