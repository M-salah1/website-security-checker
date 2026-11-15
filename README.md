# CONAN FRAMEWORK v3.0 — ADVANCED WEBSITE SECURITY DETECTIVE 🔍

**المحقق كونان** — منصة تدقيق أمان مواقع احترافية ومعيارية.

Developer: **Hafed Mehdi Salah Eddine** — Algeria 🇩🇿
GitHub: **M-salah1** — Copyright © 2026

- Python standard library only — no required dependencies
- 16 passive checks • 0 exploits • 3 languages (English / Français / العربية RTL)
- Works on Android Termux, Linux and Windows PowerShell

## What it does

| Module | What it really measures |
|---|---|
| Core audit (`conan/core/engine.py`) | DNS/IP/Reverse, public WHOIS, TLS, deep security headers, cookies, tech disclosure, robots/sitemap/security.txt, mixed content, sensitive-file exposure — evidence-weighted score + confidence |
| Discovery (`scanners/discovery.py`) | Real crawler: internal links, pages, robots, sitemap, JS, API refs, forms, redirects — every path classified by real HTTP status |
| Vulnerability tests (`scanners/vulnerabilities.py`) | Non-destructive SQLi (DB-error signatures), reflected-XSS markers, CSRF token inspection, IDOR (two authorized accounts), upload-form inspection, info disclosure (redacted), misconfiguration |
| Auth audit (`scanners/authentication.py`) | Login-form discovery, one invalid + one valid login, session rotation, cookie attributes, bounded rate-limit probe (max 3 attempts) |
| Registration audit (`scanners/registration.py`) | Form/policy analysis; one disposable test account only after explicit confirmation |
| Anti-phishing (`scanners/phishing.py`) | Homograph/IDN, typosquat similarity, domain age, TLS, redirect chains, cross-domain login forms — risk 0–100 |
| Health monitor (`scanners/health.py`) | DNS/TCP/TLS/HTTP, TTFB, total time, retries — ONLINE/DEGRADED/OFFLINE/DNS_ERROR/TLS_ERROR/HTTP_ERROR (a 403 is ONLINE, not offline) |
| TLS & DNS (`scanners/tls.py`, `dns.py`) | Cert issuer/SANs/expiry/chain, protocol-version probing, A/AAAA/CNAME/MX/NS/TXT/SOA, reverse DNS, DNSSEC |
| Cookies (`scanners/cookies.py`) | Per-cookie Secure/HttpOnly/SameSite/expiry/session classification — values always masked |
| API discovery (`scanners/api.py`) | Public endpoints from HTML/JS + intentionally exposed OpenAPI docs |
| Encryption (`core/encryption.py`) | AES-256-GCM (pure-Python, verified vs FIPS-197 + NIST GCM vectors; `cryptography` used when installed), Argon2id when available else scrypt, HMAC integrity via GCM tag |
| Storage (`storage/database.py`) | SQLite scan history, report payloads encrypted with a device key (`conan-key.txt`, mode 0600) |
| Animation (`core/animation.py`) | Threaded cinematic investigation (radar, progress, live log) tied to real phases — `--no-animation` disables it |

## Scope and authorization — read this first

Passive checks (headers, DNS, TLS, health, phishing, discovery) run on any
public site. **Active tests** (`xss`, `sqli`, `auth-test`,
`registration-test`) require explicit authorization:

```
conan > scope add https://your-site.com owned
conan > scope add https://staging.example.com staging
```

Localhost / private test environments are always in scope. State-changing
operations (login, registration) ask for confirmation right before they run.

**Never built into Conan:** password guessing, brute force, credential
stuffing, account takeover, auth bypass, destructive testing, unauthorized
account creation. **Passwords and session-cookie values are never displayed,
logged or stored in any report** — exposure is reported (where + which key
name) with rotation advice. This is also what the spec itself requires
(sections 6, 7, 12, 15: redact secrets, mask credentials).

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

## Usage

```bash
python3 conan.py                              # interactive shell: conan >
python3 conan.py https://example.com          # direct full scan
python3 conan.py https://example.com --json    # unified JSON report
python3 conan.py https://example.com --html report.html --pdf owner.pdf
python3 conan.py --no-animation https://example.com
python3 conan.py --lang en
python3 conan.py --version
```

Inside the shell:
```
conan > help
conan > scan https://example.com
conan > discover https://example.com
conan > headers https://example.com
conan > tls https://example.com
conan > cookies https://example.com
conan > forms https://example.com
conan > api https://example.com
conan > phishing https://example.com
conan > health https://example.com
conan > scope add https://example.com owned
conan > xss https://example.com/?q=test
conan > sqli https://example.com/?id=1
conan > csrf https://example.com
conan > auth-test https://example.com
conan > registration-test https://example.com
conan > session-test https://example.com
conan > report json
conan > report html
conan > history
conan > history compare 1 2
conan > settings
conan > language en
conan > status
conan > exit
```

## Architecture

```
conan.py                 Launcher (interactive shell / direct scan)
conan/
  __init__.py
  cli.py                 Interactive shell + full scan pipeline
  core/
    engine.py            v2.4 audit engine (preserved, VERSION 3.0)
    terminal.py          Colours, terminal detection, progress bar
    animation.py         Threaded cinematic investigation
    scope.py             Authorization manager (scope file, confirmations)
    configuration.py     Settings (conan-settings.json)
    security.py          Secret redaction (passwords/tokens never shown)
    encryption.py        AES-256-GCM + scrypt/Argon2id + HMAC
    evidence.py          Finding model (severity, confidence, evidence)
  scanners/
    discovery.py  vulnerabilities.py  authentication.py  registration.py
    phishing.py  health.py  tls.py  dns.py  cookies.py  headers.py
    forms.py  api.py  sessions.py  _http.py
  reporting/
    json_report.py  html_report.py
  storage/
    database.py  history.py
tests/                   unittest suite (offline + live, skips gracefully)
requirements.txt         stdlib only (optional deps commented)
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Test results (2026-11-15, sandbox): **25 tests, all passing** — scope,
encryption vectors (FIPS-197 AES-256 + NIST GCM test case 3), phishing
similarity/homograph, headers/cookies, health (incl. 403 = ONLINE),
DNS classification, TLS shape, redaction. Live smoke test: full `scan`
on https://example.com — 11/11 phases, score 28% F (confirmed missing
headers only; TLS marked unverifiable with 88% confidence), saved to
encrypted SQLite history, JSON + HTML + PDF reports generated and verified
(`%PDF-1.4`, no secrets in any report file).

## The simple tool: `security_check.py`

The original light checker (HTTPS/TLS/headers, score) is still in the repo
unchanged for quick one-off checks.
