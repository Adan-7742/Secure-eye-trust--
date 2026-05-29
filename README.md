# LogVault — Encrypted Windows Log Analyzer

A properly structured Flask application for analyzing Windows Event Logs
with Homomorphic Encryption and AI-powered security analysis.

---

## 📁 Directory Structure

```
logvault/
│
├── app.py                          ← ENTRY POINT — run this
│
├── api/                            ← Flask API blueprints (HTTP layer only)
│   ├── system_api.py               → GET /api/status, POST /api/fetch-real, GET /api/stats
│   ├── logs_api.py                 → GET /api/logs/<category>, GET /api/days/<category>
│   ├── analysis_api.py             → GET /api/analyze/* (all analysis endpoints)
│   ├── upload_api.py               → POST /api/upload
│   └── realtime_api.py             → GET /api/events (Server-Sent Events stream)
│
├── chatbot/                        ← AI chatbot
│   ├── bot.py                      → POST /api/chat (Groq API + offline fallback)
│   └── offline_engine.py           → Rule-based responses when offline
│
├── core/                           ← Business logic (no HTTP here)
│   ├── event_collector/
│   │   └── windows_reader.py       → Reads REAL Windows Event Logs via pywin32
│   ├── he_engine/
│   │   └── encryptor.py            → BFV + CKKS Homomorphic Encryption engine
│   └── ml_engine/
│       └── analyzer.py             → All ML/AI analysis: patterns, Z-score, threats
│
├── database/
│   └── db.py                       → SQLite schema, init_db(), get_conn()
│
├── templates/
│   └── index.html                  → Main HTML (loads separate CSS + JS)
│
├── static/
│   ├── css/
│   │   ├── main.css                → Layout, sidebar, cards, tables, badges
│   │   └── chat.css                → AI chat page styles
│   └── js/
│       ├── api.js                  → Shared fetch helpers (api(), apiPost(), toast())
│       ├── navigation.js           → Page router, showPage(), doFetch()
│       ├── dashboard.js            → Stat cards + Chart.js charts
│       ├── logs.js                 → Log browser, pagination, day/level filter
│       ├── analysis.js             → Frequency, anomaly, patterns, full analysis
│       ├── chat.js                 → AI chat UI, Groq API, offline fallback
│       └── realtime.js             → SSE listener for live updates
│
├── utils/
│   └── helpers.py                  → Shared Python utilities
│
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run as Administrator (for Security logs)
python app.py

# 3. Open browser
http://localhost:5000
```

---

## 🤖 Free AI Chat Setup

Uses **Groq API** — free, no credit card required.

1. Go to https://console.groq.com → sign up → create API key
2. Click **AI Chat** in sidebar → **⚙ API Key** → paste key → **Save**
3. Pill turns 🌐 Online — llama3-70b-8192 active
4. OR set env var: `set GROQ_API_KEY=gsk_...` before running

---

## 📡 How Data Flows

### Fetching Windows Logs:
```
Windows Event Log Service
  └─► core/event_collector/windows_reader.py  (pywin32 reads channels)
        └─► api/system_api.py  POST /api/fetch-real  (HTTP trigger)
              └─► database/db.py  INSERT logs_*  (stored in SQLite)
                    └─► static/js/dashboard.js  GET /api/stats  (browser renders)
```

### Analysis Pipeline:
```
database/db.py  (SQLite: logs_application, logs_system, etc.)
  └─► core/ml_engine/analyzer.py  (Python analysis functions)
        └─► core/he_engine/encryptor.py  (encrypt → compute → decrypt)
              └─► api/analysis_api.py  GET /api/analyze/*  (JSON response)
                    └─► static/js/analysis.js  (Chart.js renders)
```

### AI Chat Flow:
```
static/js/chat.js  (user types message)
  └─► POST /api/chat
        └─► chatbot/bot.py
              ├── get_log_context() → reads live stats from SQLite
              ├── call_groq() → api.groq.com/openai/v1/chat/completions (FREE)
              │       └─► llama3-70b reply
              └── OR offline_engine.py → rule-based reply (no internet)
        └─► JSON { reply, online, model }
              └─► static/js/chat.js renders bubble
```

### Real-Time Updates:
```
Any action (fetch, analysis, chat) → database/db.py log_app_event()
  └─► app_events table
        └─► api/realtime_api.py polls every 2s → SSE stream
              └─► static/js/realtime.js EventSource
                    └─► Updates badges, toasts, dashboard — no page refresh
```

---

## 🔐 Homomorphic Encryption

| Scheme | Used For | Location |
|--------|----------|----------|
| BFV    | Error count frequency maps | `core/he_engine/encryptor.py` → `HomomorphicEncryptor` |
| CKKS   | Z-score anomaly detection (floats) | `core/he_engine/encryptor.py` → `CKKSEncryptor` |

**Pipeline:**
```
Raw count (e.g. 42 errors)
  → BFV encrypt: ct = (42 × secret_key) + noise = 26554
    → HE-ADD on ciphertexts (no decryption)
      → HE-SUM all error ciphertexts
        → Decrypt ONCE at output: 26554 → 42
```

---

## 🧠 ML Analysis Methods

| Method | Engine | Description |
|--------|--------|-------------|
| Frequency Analysis | BFV + SQL COUNT | Error counts per source, encrypted |
| Z-Score Anomaly | CKKS + statistics | Daily error volume outlier detection |
| Pattern Scan | 15 regex patterns | Threat signatures in log messages |
| Top Offenders | Blended scoring | 40% raw count + 60% error rate |
| Temporal Analysis | datetime parsing | Peak hours, weekday breakdown, trends |
| Zero-Day Heuristics | Rare event detection | Source+EventID combos seen ≤3 times |
| Security Classification | Event ID mapping | 20 Security event IDs mapped to threats |

---

## 🔑 API Endpoints

| Method | URL | Handler | Description |
|--------|-----|---------|-------------|
| GET | `/api/status` | `system_api.status` | Admin + pywin32 check |
| POST | `/api/fetch-real` | `system_api.fetch_real` | Fetch Windows Event Logs |
| GET | `/api/stats` | `system_api.stats` | Counts per category |
| GET | `/api/logs/<cat>` | `logs_api.get_logs` | Paginated log browser |
| GET | `/api/days/<cat>` | `logs_api.get_days` | Day picker data |
| GET | `/api/analyze/frequency` | `analysis_api.frequency` | BFV frequency analysis |
| GET | `/api/analyze/anomaly` | `analysis_api.anomaly` | CKKS Z-score anomaly |
| GET | `/api/analyze/patterns` | `analysis_api.patterns` | Threat pattern scan |
| GET | `/api/analyze/full` | `analysis_api.full_analysis` | All engines combined |
| GET | `/api/analyze/search` | `analysis_api.search` | Keyword search |
| POST | `/api/upload` | `upload_api.upload` | Upload log file |
| GET | `/api/events` | `realtime_api.sse_events` | SSE real-time stream |
| POST | `/api/chat` | `chatbot.bot.chat` | AI chat (Groq/offline) |
| GET | `/api/chat/status` | `chatbot.bot.chat_status` | AI connectivity check |
