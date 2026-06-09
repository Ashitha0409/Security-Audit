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
| 💾 Data Breach History | Checks if the domain appears in known breaches (XposedOrNot — free, no API key) |
| 🔖 Software Disclosure | Detects version leaks in headers |
| 🤖 AI Analysis | Groq/Llama generates plain-English summary |
| 🌐 Regional Languages | Summary in Hindi, Telugu, Tamil, Kannada, Marathi, Bengali |
| 📈 Score History | SQLite tracks score over time with chart |
| 💬 AI Chatbot | Ask questions about your scan results (RAG-grounded on your scan data) |
| 📄 PDF Report | Download a professional security report |
| 🕸️ Threat Map | Neo4j graph of hosts/services/vulns with ranked attack-path analysis |
| 🌐 Network Sweep | Nmap CIDR sweep to map every live host & open service on a subnet |

---

## 🏗️ Project Structure

```
Cyber/
├── backend/
│   ├── app.py              # Flask server & API routes
│   ├── scanner.py          # All security scan modules (SSL, headers, ports, breaches…)
│   ├── network_scanner.py  # Nmap subnet sweep (on-prem / LAN)
│   ├── chatbot.py          # AI chatbot (Groq → Anthropic → OpenRouter → Fallback)
│   ├── rag.py              # RAG pipeline — grounds chatbot answers in your scan data
│   ├── report_generator.py # PDF report generation
│   ├── prawl_history.db    # SQLite scan history (auto-created, gitignored)
│   └── reports/            # Generated PDFs saved here
│   ├── graph_mapper.py     # Neo4j threat graph + attack-path detection
├── advanced_scanner.py     # Docker-based tools: Nmap / Nikto / SQLMap / WhatWeb / crt.sh
├── validation.py           # Target sanitisation (blocks argument injection)
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

## 📊 Risk Scoring

| Score | Risk Level | Color |
|---|---|---|
| 80 – 95 | LOW | 🟢 Green |
| 60 – 79 | MEDIUM | 🟡 Yellow |
| 40 – 59 | HIGH | 🟠 Orange |
| 0 – 39 | CRITICAL | 🔴 Red |

---



## 🧠 Grounded RAG Chatbot (what makes PRAWL different)

PRAWL's assistant doesn't just chat — every answer is **retrieval-augmented and
cited against your actual scan**:

1. Each scan (basic findings **and** the advanced Nmap/Nikto/SQLMap/breach data)
   is turned into small retrievable documents.
2. When you ask a question, PRAWL retrieves only the findings relevant to *that*
   question and feeds them to the LLM — so answers are specific to your site,
   not generic security advice.
3. Under every answer the UI shows **source chips** — the exact findings the
   answer was grounded in, colour-coded by severity. Click a chip (or the
   **🤖 Ask AI about this** button on any finding) to drill deeper.

Retrieval runs locally with **zero external dependencies** (pure-Python TF-IDF),
and transparently upgrades to semantic search if `sentence-transformers` is
installed. No data leaves your machine for retrieval — important for on-prem use.

See `backend/rag.py`.

---

## 🕸️ Threat Map — Graph-Based Attack-Path Analysis (Neo4j)

PRAWL doesn't just list findings — it **connects them**. Scan results and network
sweeps are mapped into a property graph:

```
(Host)-[:EXPOSES]->(Service)-[:HAS_VULN]->(Vulnerability)
(Host)-[:HAS_FINDING]->(Vulnerability)
(Host)-[:RUNS]->(Technology)
(Host)-[:HAS_SUBDOMAIN]->(Subdomain)
(Host)-[:BREACHED_IN]->(Breach)
```

From this graph PRAWL derives **ranked attack paths** — how an attacker could chain
exposures end to end:

```
🌐 Internet ➜ MySQL :3306 ➜ shop.local ➜ SQL Injection (MySQL)   [CRITICAL · score 27]
```

- The graph is **persisted to Neo4j** when reachable (`NEO4J_URI`) — explore it
  visually in the **Neo4j Browser** at http://localhost:7474.
- If Neo4j isn't running, an **in-memory graph** is built instead, so the map and
  attack-path detection still work (graceful fallback).
- The dashboard renders the graph interactively (vis-network) and lists the ranked
  attack paths beneath it.

Explore in Neo4j Browser:
```cypher
MATCH p=(:Service)-[:HAS_VULN]->(:Vulnerability) RETURN p;
MATCH (h:Host)-[*1..3]->(v:Vulnerability) RETURN h, v;
```

See `backend/graph_mapper.py`. Spin up Neo4j with `docker compose up`.

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
- **RAG** — pure-Python TF-IDF retriever over scan data (optional sentence-transformers for semantic search)
- **Breach data** — XposedOrNot (free, no API key)
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
