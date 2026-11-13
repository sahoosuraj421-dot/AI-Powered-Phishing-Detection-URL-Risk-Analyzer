# Tripwire: AI-Powered Phishing Detection & URL Risk Analyzer

A FastAPI + modern responsive web application that inspects URLs **and** email bodies for phishing risk, backed by real-time threat intelligence (VirusTotal, Google Safe Browsing, WHOIS, typosquatting heuristics) and a cybersecurity advisor chatbot powered by Qwen2.5-7B (with built-in offline fallback).

---

## Features

| Area | Description |
|---|---|
| **URL Analysis** | Heuristics inspecting length, `@` symbol, IP-as-host, subdomains, HTTPS enforcement, suspicious keywords, hyphens, punycode homoglyphs, non-standard ports |
| **Risk Scoring** | Transparent weighted score (0–100) mapped to verdicts: **Legitimate**, **Suspicious**, or **Phishing** |
| **Threat Intelligence** | VirusTotal (70+ vendor engines), Google Safe Browsing, WHOIS domain age lookup, and Levenshtein typosquatting detection for 45+ top brands |
| **Email NLP Scanner** | Identifies urgent/high-pressure language, parses SPF/DKIM header authentication results, and extracts embedded URLs |
| **Authentication** | JWT (HS256) registration/login, scrypt password hashing with complexity rules, and per-user scan history |
| **AI Security Advisor** | Qwen2.5-7B via Hugging Face Inference API with scan context; includes built-in offline incident-response advisory if no key is configured |
| **Incident Reports** | Authenticated PDF report generation (fpdf2) and CSV exports with Unicode-safe sanitization |
| **Hardened Security** | SlowAPI rate limiting, Content Security Policy (CSP), anti-clickjacking headers, and secrets isolated in `.env` |
| **Containerized** | Production-ready Dockerfile and Docker Compose with persistent SQLite volume storage |

---

## Project Structure

```
phishing-detector/
├── backend/
│   ├── __init__.py
│   ├── main.py            # FastAPI app, routing, middleware, lifespan
│   ├── ml_engine.py       # PhishingFeatureExtractor (lexical heuristics & feature vectors)
│   ├── email_analysis.py  # NLP email scanner (urgency phrases, SPF/DKIM, links)
│   ├── threat_intel.py    # VirusTotal, Safe Browsing, WHOIS age, typosquatting
│   ├── qwen_service.py    # Hugging Face Qwen client with offline advisory fallback
│   ├── report_generator.py# Unicode-safe PDF (fpdf2) and CSV incident export
│   ├── security.py        # Input validation, scrypt hashing, JWT auth dependencies
│   ├── models.py          # User, ScanLog, EmailScan tables (SQLModel)
│   ├── database.py        # SQLite engine, sessions, and schema initializer
│   └── requirements.txt   # Python dependencies
├── frontend/
│   ├── index.html         # Responsive single-page app (Home, History, Contact, Auth, Profile)
│   ├── script.js          # Client-side routing, authenticated report downloads, UI state
│   └── styles.css         # Dark theme design system
├── test_core.py           # Offline unit test suite (standard library, zero network/server required)
├── test_api.py            # End-to-end smoke test script against a running server
├── docker-compose.yml     # Multi-platform container configuration
├── Dockerfile             # Multi-stage non-root container build
├── .env.example           # Environment template
├── .env                   # Local configuration & secrets
└── README.md              # Project documentation & runnable commands
```

---

## Requirements

- **Python 3.10+** (Python 3.11 or 3.12/3.13 recommended)
- **pip** package manager
- *(Optional)* Free Hugging Face account token for live Qwen2.5-7B responses (runs in offline advisory mode if omitted)
- *(Optional)* VirusTotal free tier API key & Google Safe Browsing API key

---

## Quick Start & Setup Guide

### 1. Clone & Enter Project Root

```bash
cd phishing-detector
```

> [!IMPORTANT]
> Always execute commands from the **project root** directory (`phishing-detector`), not from inside `backend/`.

---

### 2. Create and Activate Virtual Environment

#### On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(If script execution is restricted in PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

#### On Windows (Command Prompt `cmd`):
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

#### On macOS / Linux (bash/zsh):
```bash
python3 -m venv .venv
source .venv/bin/activate
```

> [!TIP]
> **Windows Note:** On Windows, use `python`, not `python3`. Typing `python3` on Windows often invokes the Microsoft Store stub.

---

### 3. Install Dependencies

With the virtual environment activated:

#### Windows:
```powershell
python -m pip install -r backend/requirements.txt
```

#### macOS / Linux:
```bash
pip install -r backend/requirements.txt
```

---

### 4. Configure Environment Variables (`.env`)

A default `.env` is included, and a template is available at `.env.example`.

To generate a new secure JWT secret, run:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Edit your `.env` file:
```ini
# Hugging Face (Optional: built-in offline security advisor answers if omitted)
HF_API_KEY=
HF_MODEL=Qwen/Qwen2.5-7B-Instruct

# JWT Secret Key (required for authentication, minimum 32 characters)
JWT_SECRET=zK9eP3rM8xW2vQ7bN4jL1sT6yU5iO0pA_TripwireSecureKey2026_x87y21q

# Database
DATABASE_URL=sqlite:///./phishing.db

# CORS Allowed Origins
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000

# Rate Limiting
RATE_LIMITING_ENABLED=true

# Optional Threat Intelligence Keys
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_KEY=
```

---

## Running the Application

### Option A: Direct Python Runner (Recommended for Local Dev)

From the project root:

```bash
python -m backend.main
```

### Option B: Uvicorn with Hot Reload

```bash
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### Option C: Production Server (Linux / Docker multi-worker)

> [!NOTE]
> On Windows, Uvicorn multi-worker mode (`--workers 2`) is restricted by the Windows OS socket sharing architecture (`WinError 10022`). On Windows, run single-process or use Docker for multi-worker setups:

```bash
# Windows:
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Linux / Docker container:
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 2
```

### Option D: Docker & Docker Compose

Using Docker Compose:
```bash
docker compose up --build
```

Or standalone Docker:
```bash
docker build -t tripwire:latest .
docker run -d -p 8000:8000 --name tripwire --env-file .env tripwire:latest
```

---

## Accessing the Web Interface

Open your browser to:
👉 **[http://localhost:8000](http://localhost:8000)** (or [http://127.0.0.1:8000](http://127.0.0.1:8000))

The SQLite database file (`phishing.db`) is automatically created and initialized on first launch.

---

## Running Tests

### 1. Offline Unit Test Suite (No server or internet needed)

Runs 15+ comprehensive unit tests covering URL lexical heuristics, feature vectors, email urgency parsing, SPF/DKIM flags, password hashing, typosquatting logic, Unicode-safe PDF/CSV reports, and offline AI fallback:

```bash
python test_core.py
```
or:
```bash
python -m unittest test_core.py
```

### 2. End-to-End Live Smoke Tests (Against running server)

First start the server (`uvicorn backend.main:app --reload`), then in a separate terminal:

```bash
python test_api.py
```

This validates all live endpoints: logs, URL scanner, bad scheme rejections (422), email scanning, user registration, JWT authentication, user profile, password updates, authenticated PDF/CSV report downloads, and AI chat.

---

## API Reference & Runnable cURL Commands

### 1. Scan a URL
Checks lexical risk factors and enriches with threat intelligence.

**Bash / Linux / macOS:**
```bash
curl -X POST http://localhost:8000/api/scan \
     -H "Content-Type: application/json" \
     -d '{"url":"http://paypa1-secure-login.example.com/verify"}'
```

**Windows PowerShell:**
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/scan" -ContentType "application/json" -Body '{"url":"http://paypa1-secure-login.example.com/verify"}'
```

---

### 2. Scan an Email Body
Analyzes body content, urgency phrases, SPF/DKIM flags, and embedded links.

**Bash / Linux / macOS:**
```bash
curl -X POST http://localhost:8000/api/email-scan \
     -H "Content-Type: application/json" \
     -d '{
       "subject": "URGENT: Verify your account",
       "raw": "Dear customer, your account is suspended. Click here immediately: http://login-verify.example.com spf=fail dkim=fail"
     }'
```

**Windows PowerShell:**
```powershell
$body = @{
  subject = "URGENT: Verify your account"
  raw = "Dear customer, your account is suspended. Click here immediately: http://login-verify.example.com spf=fail dkim=fail"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/email-scan" -ContentType "application/json" -Body $body
```

---

### 3. User Registration & Login (Auth)

**Register a new user:**
```bash
curl -X POST http://localhost:8000/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"username":"analyst_01","email":"analyst@example.com","password":"SecurePassword@2026!"}'
```

**Log in to get access token:**
```bash
curl -X POST http://localhost:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"analyst_01","password":"SecurePassword@2026!"}'
```

**View current user profile (`/api/auth/me`):**
```bash
curl -X GET http://localhost:8000/api/auth/me \
     -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"
```

---

### 4. Fetch Scan History Logs

```bash
curl -X GET "http://localhost:8000/api/logs?limit=10"
```

---

### 5. Download Incident Reports (CSV & PDF)

**Download CSV Report:**
```bash
curl -X GET http://localhost:8000/api/report/csv \
     -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
     -o scan_report.csv
```

**Download PDF Report:**
```bash
curl -X GET http://localhost:8000/api/report/pdf \
     -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
     -o scan_report.pdf
```

*(You can also use URL token queries for direct downloads: `http://localhost:8000/api/report/pdf?token=<YOUR_ACCESS_TOKEN>`)*

---

### 6. AI Security Advisor Chat

Works both with Qwen2.5-7B (when `HF_API_KEY` is configured) and in offline intelligent security advisory mode:

```bash
curl -X POST http://localhost:8000/api/chat \
     -H "Content-Type: application/json" \
     -d '{"message":"What should I do if I clicked a suspicious link?"}'
```

---

## Configuration Reference (`.env`)

| Variable | Description | Default |
|---|---|---|
| `JWT_SECRET` | Signing key for JWT tokens (≥ 32 chars) | Ephemeral auto-generated in dev if unset |
| `DATABASE_URL` | SQLAlchemy connection string | `sqlite:///./phishing.db` |
| `ALLOWED_ORIGINS` | Comma-delimited CORS origins | `http://localhost:8000,http://127.0.0.1:8000` |
| `RATE_LIMITING_ENABLED` | Toggles SlowAPI rate limits (`true`/`false`) | `true` |
| `HF_API_KEY` | Hugging Face API key for Qwen2.5 | None (runs in offline advisory mode) |
| `HF_MODEL` | Hugging Face model endpoint | `Qwen/Qwen2.5-7B-Instruct` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API v3 key | None (skipped if absent) |
| `GOOGLE_SAFE_BROWSING_KEY` | Safe Browsing v4 key | None (skipped if absent) |

---

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `Python was not found; run without arguments to install from the Microsoft Store...` | Windows mapped `python3` to the Microsoft Store alias | Use `python` or `pip` directly. Disable the alias under **Settings > Apps > Advanced app settings > App execution aliases**. |
| `ModuleNotFoundError: No module named 'backend'` | Command executed from inside `backend/` instead of project root | Change directory to the repository root (`cd ..`) and run `uvicorn backend.main:app` or `python -m backend.main`. |
| `HTTP 500: Server auth is not configured` | Missing or invalid `JWT_SECRET` | Ensure `JWT_SECRET` in `.env` has ≥ 32 characters and does not start with `replace`. |
| `HTTP 401 Unauthorized on report download` | Direct link clicked in browser without JWT header | Ensure you are logged in. The frontend now fetches the report via authenticated blob stream, or pass `?token=<jwt>` in the URL. |
| `HTTP 429 Too Many Requests` | SlowAPI rate limit triggered | Wait 60 seconds, or set `RATE_LIMITING_ENABLED=false` in `.env` for testing. |
| `fpdf.errors.FPDFUnicodeEncodingException` | Scanned URL contains Cyrillic or non-Latin homoglyphs | Already resolved: `report_generator.py` sanitizes text for Latin-1 encoding with automatic fallbacks. |

---

## License

MIT License. Designed for security analysis, educational research, and defensive threat awareness.
