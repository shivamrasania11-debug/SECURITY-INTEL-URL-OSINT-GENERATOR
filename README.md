# Security Analysis & URL Intelligence Generator

> **Defensive Cybersecurity Reconnaissance & Passive URL Threat Intelligence Web Platform**  
> Built with a Python Flask REST backend, standard library networking, and a modern 3D glassmorphic frontend powered by Three.js, Vanilla-Tilt, and GSAP.

---

## 1. Project Overview & Architecture

**Security Analysis & URL Intelligence Generator** helps security analysts, penetration testers, and website administrators safely gather publicly available OSINT intelligence on web properties and evaluate URLs for potential phishing, obfuscation, or structural threats.

The application adheres strictly to **passive reconnaissance rules**:
- **No port scanning** (standard web ports only: 80 / 443).
- **No payload delivery** or exploitation attempts.
- **No automated search engine scraping** (queries are generated and formatted for direct, authorized manual review in Google, Bing, or DuckDuckGo).
- **Mandatory ethical authorization** enforced on both the client interface and server API.

### Technology Stack
- **Backend**: Python 3.9+ (compatible with 3.8+), Flask, Flask-CORS, Requests, Python-Whois (optional with graceful fallback), standard library (`urllib.parse`, `socket`, `ssl`, `ipaddress`, `re`, `json`, `csv`, `threading`, `webbrowser`).
- **Frontend**: Single-Page Application (HTML5, CSS3, ES6+ JavaScript), Three.js (interactive 3D particle & wireframe globe background), Vanilla-Tilt (card 3D perspective tilt & glare), GSAP (smooth reveals and animations), Font Awesome 6 icons, Google Fonts (Space Grotesk, Inter, JetBrains Mono).
- **Testing**: Pytest automated test suite covering domain normalization, dork generation, URL parsing, threat pattern detection heuristics, and REST API endpoints.

---

## 2. Directory Structure

```text
security_url_intel/
├── app.py                      # Flask REST API server & auto-browser launcher
├── config.py                   # App settings, TLD lists, shorteners, keywords, risk weights
├── dork_generator.py           # 9-category OSINT Google search operator engine
├── url_analyzer.py             # Passive RFC structure, DNS, SSL cert & redirect tracker
├── pattern_detector.py         # 18+ heuristic phishing and deception detection rules
├── utils.py                    # Domain normalization, validators & TXT/CSV/JSON export formatters
├── requirements.txt            # Python dependencies (flask, flask-cors, requests, python-whois, pytest)
├── templates/
│   └── index.html              # Cyber-themed single-page frontend application
├── static/
│   ├── css/
│   │   └── style.css           # Glassmorphism, 3D card tilt, radar scanner & dark/light theme
│   ├── js/
│   │   ├── main.js             # API integrations, reactive state, tabs, exports, toasts
│   │   └── three-bg.js         # Interactive Three.js 3D background with mouse parallax
│   └── img/
│       └── logo.svg            # Cyber defense shield logo
└── tests/
    ├── test_validation.py      # Domain and URL normalization and regex tests
    ├── test_dorks.py           # 9-category OSINT query generator tests
    ├── test_analyzer.py        # URL structural parsing and multipart TLD tests
    ├── test_patterns.py        # Heuristic threat detection and scoring tests
    └── test_app.py             # Flask REST endpoints, health & authorization check tests
```

---

## 3. Quickstart & Installation

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Launch the Platform
```bash
python app.py
```

*The application automatically starts a local server at `http://127.0.0.1:5000` and automatically opens your default web browser.*

### Running Automated Tests
```bash
python -m pytest -v security_url_intel/tests
```

---

## 4. REST API Specification

All POST endpoints require `"authorized": true` in the JSON request payload.

### 4.1 Health Check
- **Endpoint**: `GET /api/health`
- **Response**:
```json
{
  "success": true,
  "data": {
    "service": "Security Analysis & URL Intelligence Generator",
    "status": "healthy",
    "timestamp": "2026-11-16T08:00:00.000Z",
    "version": "1.0.0"
  },
  "error": null
}
```

### 4.2 Generate OSINT Dork Queries
- **Endpoint**: `POST /api/dorks`
- **Request Body**:
```json
{
  "domain": "example.com",
  "categories": ["general", "documents", "login_admin"],
  "engine": "google",
  "authorized": true
}
```

### 4.3 Passive URL & Threat Analysis
- **Endpoint**: `POST /api/analyze`
- **Request Body**:
```json
{
  "url": "https://example.com/login",
  "authorized": true
}
```

### 4.4 Report Export
- **Endpoint**: `POST /api/export`
- **Request Body**:
```json
{
  "type": "txt",
  "report_type": "analysis",
  "data": { ... },
  "authorized": true
}
```

---

## 5. Sample Test Cases & Outputs

### Case 1: Normal URL
- **Input**: `https://www.google.com/search?q=cybersecurity`
- **Risk Score**: `0 / 100` (`Low Risk`)
- **Flags Triggered**: `0`
- **Output Summary**:
  `No suspicious structural anomalies, phishing indicators, or deceptive redirection behaviors were identified.`

### Case 2: Shortened URL
- **Input**: `https://tinyurl.com/sample-short-link`
- **Risk Score**: `15 / 100` (`Low Risk`)
- **Flags Triggered**:
  - `[MEDIUM] Known URL Shortening Service (tinyurl.com)` (+15 pts)

### Case 3: Phishing-Style Brand Impersonation URL
- **Input**: `http://paypal.com.account-verification-security.xyz/login.php?user=admin&token=123`
- **Risk Score**: `82 / 100` (`High Risk`)
- **Flags Triggered**:
  - `[CRITICAL] Brand Impersonation in URL Path/Subdomain` (+35 pts)
  - `[MEDIUM] High-Abuse Top-Level Domain (.xyz)` (+20 pts)
  - `[HIGH] Multiple Sensitive / Phishing Keywords (login, account, verification)` (+15 pts)
  - `[MEDIUM] Unencrypted HTTP Scheme` (+12 pts)

