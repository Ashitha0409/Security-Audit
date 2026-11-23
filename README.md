# 🛡️ PRAWL — Know Before They Do

> AI-powered cybersecurity scanner for Indian small businesses. Free. 30 seconds.

---

## 🚀 What is PRAWL?

PRAWL is a web-based security audit tool that scans any website for vulnerabilities, misconfigurations, and data breaches — then explains every issue in plain English  using AI.

Built for Indian small business owners and also developers who don't have a security team.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔒 SSL Check | Validates certificate, checks expiry |
| 🛡️ Security Headers | Checks 6 critical HTTP headers |
| 🔄 HTTPS Redirect | Ensures HTTP → HTTPS |
| 🔍 Open Port Scan | Detects exposed database/service ports |
| 💾 Data Breach History | HaveIBeenPwned API check |
| 🔖 Software Disclosure | Detects version leaks in headers |
| 🤖 AI Analysis | Groq/Llama generates plain-English summary |
| 🌐 Regional Languages | Summary in Hindi, Telugu, Tamil, Kannada, Marathi, Bengali |
| 📈 Score History | SQLite tracks score over time with chart |
| 💬 AI Chatbot | Ask questions about your scan results |
| 📄 PDF Report | Download a professional security report |

---

## 🏗️ Project Structure

```
Cyber/
├── backend/
│   ├── app.py              # Flask server & API routes
│   ├── scanner.py          # All security scan modules
│   ├── chatbot.py          # AI chatbot (Groq → Anthropic → OpenRouter → Fallback)
│   ├── report_generator.py # PDF report generation
│   ├── prawl_history.db    # SQLite scan history (auto-created)
│   └── reports/            # Generated PDFs saved here
├── frontend/
│   ├── templates/
│   │   └── index.html      # Main UI
│   └── static/             # CSS / JS / images
├── requirements.txt
├── run.bat                  # Windows one-click launcher
└── .env                     # API keys (never commit this)
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/Ch-Anvitha/Cyber.git
cd Cyber
```

### 2. Create your `.env` file
```bash
copy .env.example .env
```
Open `.env` and add your API key:
```
GROQ_API_KEY=your_groq_key_here
```
Get a free Groq API key at → https://console.groq.com

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
cd backend
python app.py
```
Or just double-click `run.bat` on Windows.

### 5. Open browser
```
http://localhost:5000
```

---

## 🔑 Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GROQ_API_KEY` | ✅ Recommended | Free AI summaries via Groq/Llama |
| `ANTHROPIC_API_KEY` | ❌ Optional | Claude AI (paid, higher quality) |
| `OPENROUTER_API_KEY` | ❌ Optional | OpenRouter fallback (free tier) |
| `FLASK_DEBUG` | ❌ Optional | Set `true` for development only |
| `ALLOWED_ORIGINS` | ❌ Optional | CORS origins for production |

---

## 📊 Risk Scoring (evidence-based)

Score = **100 − weighted deductions for confirmed issues**. Nothing is guessed:

* Checks that could not run (timeouts, a WAF/bot-protection challenge page) are shown as *info / not assessed* and **never** lower the score. They are never reported as "passed" either.
* Weights follow real impact: a missing `Permissions-Policy` costs 1 point, a CVE on the CISA Known-Exploited list 20, a publicly downloadable `.env` 30.
* A critical finding caps the score at 35, a high finding at 59, so serious problems cannot hide inside a green score.
* The attack-path engine can only lower the score further, and only from chains built from **confirmed** findings (e.g. leaked credentials + exposed DB port, unauthenticated Redis, confirmed reflected XSS + weak cookies). A missing header or an open port alone never creates an attack path.

| Score | Risk Level | Color |
|---|---|---|
| 80 – 100 | LOW | 🟢 Green |
| 60 – 79 | MEDIUM | 🟡 Yellow |
| 40 – 59 | HIGH | 🟠 Orange |
| 0 – 39 | CRITICAL | 🔴 Red |

A hardened, CDN-fronted site such as `chatgpt.com` scores **99/100 (green)**; the only deduction found in a passive check was the missing `Permissions-Policy` header (1 point). Every scan returns `score_breakdown` listing each deduction.

---

### Known limits (read before trusting a score)

* **Weights, caps and colour bands are policy choices**, not statistics or an industry standard. They all live in `backend/scoring_policy.py` and are returned in every scan as `score_policy`. Attack-path "confidence" numbers in `data/attack_transitions.json` are analyst heuristics used only to rank chains.
* **External view only.** No login, no business logic, no source review, no exploitation. A green score means *no issue was found by these checks*, not "unhackable".
* **WAF / bot protection:** HTTP-layer checks are skipped (and said to be skipped) when the site serves a challenge page.
* **DNS, TLS and timeouts are "unknown", never "pass" or "missing":** a DNS timeout produces an info note, not a "no DMARC" finding; a TLS 1.0/1.1 probe that cannot be run is reported as untested.
* **CVE matching is banner-based.** Linux distributions back-port fixes without changing the version string, and NVD sometimes lists only an upper version bound; those matches are labelled *Approximate*, capped at medium severity and cannot drag the score below the green/yellow boundary on their own. KEV-listed matches are never downgraded.
* The CVE snapshot keeps CRITICAL CVEs, CISA-KEV CVEs and CVEs for ~25 fingerprintable web-stack products, not all 17k NVD entries.

---

## 🧬 Real CVE intelligence (October 2026)

`backend/cve_intel.py` downloads **real** data, nothing is hand-written:

* **NVD CVE API 2.0**: CVEs published 2026-10-01 → 2026-10-31 (17,481 published; CRITICAL/HIGH and fingerprintable web-stack products kept)
* **CISA Known Exploited Vulnerabilities**: 36 CVEs added to the catalogue in October 2026

```bash
python backend/cve_intel.py refresh                      # re-download October 2026
python backend/cve_intel.py refresh 2026-11-01 2026-11-30  # any other window
export NVD_API_KEY=...                                   # optional, faster downloads
```

Snapshot: `backend/data/cve_snapshot.json` (records source URLs + `fetched_at`). A CVE is attached to a scan **only** when the site discloses a software version (`Server`, `X-Powered-By`, generator meta, jQuery file name) that falls inside the CPE version range NVD publishes. It is an indicator, not proof of exploitation (distros back-port fixes), and the report says so. Sites that hide versions get a pass, not a guess. `GET /api/cves/recent` serves the feed.

---

## 🎓 Penetration-testing concepts built in (VAPT syllabus)

| Syllabus topic | Where it appears |
|---|---|
| Unit I: social engineering, recon | SPF/DMARC check, look-alike domain watch, passive recon (DNS, TLS, banners, robots.txt, security.txt) |
| Unit III: planning, executing, reporting a test | Scope + rules of engagement, phases performed / not performed, prioritised remediation plan (P1/P2/P3) |
| Unit III: buffer overflows, SEH, DEP/ASLR | Concept notes (`GET /api/concepts`); version → CVE matching for memory-corruption bugs |
| Unit IV: OWASP Top 10, injection, XSS | Every finding tagged OWASP 2021 + CWE; reflected-input marker probe; SQLMap (consented) |
| Unit IV: passive and source-code analysis | Header/cookie/TLS checks and landing-page HTML analysis (mixed content, login over HTTP, comments) |
| Unit V: client-side exploits, honeypots, malware analysis | CSP / XFO / SRI checks; concept notes |
| Unit II: Metasploit, physical, insider | Listed as *out of scope* in each report; CISA KEV flag marks the CVEs attackers actually weaponise |

Concept notes cite the textbook chapter and section headings (verified against the supplied PDF outlines: Gray Hat Hacking, Linux Penetration Testing Bible, Penetration Testing For Dummies).

Modules: `taxonomy.py` (OWASP/CWE mapping), `engagement.py` (methodology, remediation plan, concept notes), `data/concepts.json`.

---



## 🤖 AI Provider Chain

The chatbot and summary generator try providers in this order:

1. **Groq** (free) — Llama 3.3 70B
2. **Anthropic** (paid) — Claude Sonnet
3. **OpenRouter** (free tier) — Mistral 7B
4. **Rule-based fallback** — always works, no API key needed

---

## 🛠️ Tech Stack

- **Backend** — Python, Flask, Flask-Limiter, Flask-CORS
- **AI** — Groq (Llama 3.3), Anthropic (Claude), OpenRouter (Mistral)
- **Database** — SQLite (scan history)
- **PDF** — ReportLab
- **Frontend** — Vanilla HTML/CSS/JS, Chart.js
- **Security checks** — Python `ssl`, `socket`, `requests`

---

## 🔒 Security Notes

- Only scan websites you own or have explicit permission to test
- Rate limited to 5 scans per minute per IP
- Reports stored locally in `backend/reports/`
- Never commit your `.env` file

---

## 📄 License

Built for Hackathon 2026 · Python + Flask + Groq AI

---

*PRAWL — Know Before They Do* 🛡️
