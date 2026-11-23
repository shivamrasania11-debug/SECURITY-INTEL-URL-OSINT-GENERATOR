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
- **Response**:
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "engine": "google",
    "total_queries": 20,
    "categories": {
      "general": {
        "category_id": "general",
        "name": "General Information",
        "description": "Baseline domain indexing, related domains, page titles, and public metadata.",
        "icon": "fas fa-globe",
        "count": 7,
        "queries": [
          {
            "label": "All Indexed Domain Pages",
            "query": "site:example.com",
            "description": "Enumerates all search engine indexed pages for the primary domain.",
            "search_url": "https://www.google.com/search?q=site%3Aexample.com"
          }
        ]
      }
    }
  },
  "error": null
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
- **Response**:
```json
{
  "success": true,
  "data": {
    "url": "https://example.com/login",
    "structure": {
      "scheme": "https",
      "host": "example.com",
      "domain": "example.com",
      "subdomain": "",
      "tld": "com",
      "port": 443,
      "path": "/login",
      "query_params": [],
      "query_param_count": 0,
      "length": 25
    },
    "domain_details": {
      "ipv4": ["93.184.215.14"],
      "ipv6": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
      "reverse_dns": null,
      "ssl": {
        "enabled": true,
        "issuer": "DigiCert Global Root G2",
        "valid_to": "Jan 15 12:00:00 2027 GMT",
        "days_remaining": 320,
        "is_expired": false,
        "is_self_signed": false
      },
      "whois": {
        "available": true,
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "age_days": 10580
      }
    },
    "redirects": {
      "initial_url": "https://example.com/login",
      "final_url": "https://example.com/login",
      "hop_count": 1,
      "is_downgraded": false,
      "is_cross_domain": false,
      "chain": [
        {
          "hop": 1,
          "url": "https://example.com/login",
          "status_code": 200,
          "reason": "OK",
          "next_url": null
        }
      ]
    },
    "risk": {
      "score": 0,
      "level": "Low",
      "summary": "No suspicious structural anomalies, phishing indicators, or deceptive redirection behaviors were identified."
    },
    "flags": []
  },
  "error": null
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
- **Response**: File attachment stream (`Content-Type: text/plain`, `text/csv`, or `application/json`) with formatted filename.

---

## 5. OSINT Categories & Supported Operators

| Category | Icon | Target Operators | Defensive Goal |
|---|---|---|---|
| **1. General Information** | `fas fa-globe` | `site:`, `related:`, `intitle:` | Primary brand footprint and indexed surface. |
| **2. Exposed Documents** | `fas fa-file-alt` | `filetype:pdf`, `doc`, `xls`, `csv`, `txt` | Locate accidentally exposed financial/personnel files. |
| **3. Login & Admin Pages** | `fas fa-user-lock` | `inurl:admin`, `inurl:login`, `cpanel`, `auth` | Discover unprotected administrative portals. |
| **4. Directory Listings** | `fas fa-folder-open`| `intitle:"index of /"`, `intitle:"index of"` | Identify web servers with auto-indexing enabled. |
| **5. Configuration & Backups**| `fas fa-database` | `ext:env`, `ext:sql`, `ext:bak`, `ext:cfg`, `.git` | Detect leaked server credentials, SQL dumps, or `.env`. |
| **6. Subdomain Discovery** | `fas fa-network-wired`| `site:*.domain.com -www`, `inurl:api`, `dev` | Map dev, staging, API, and cloud infrastructure. |
| **7. Sensitive Keywords** | `fas fa-key` | `intext:"confidential"`, `"internal use"`, `api_key` | Flag proprietary documentation and leaked secrets. |
| **8. Technology & Errors** | `fas fa-bug` | `intext:"sql syntax near"`, `"Fatal error"` | Discover debug information exposing file paths. |
| **9. Public Mentions** | `fas fa-share-alt` | `site:pastebin.com`, `site:github.com` | Audit external credential pastes and code leaks. |

---

## 6. Heuristic Threat Pattern Rules & Scoring

The `SuspiciousPatternDetector` inspects 18+ signals and computes a weighted composite risk score from 0 to 100:

| Rule ID | Severity | Weight | Description |
|---|---|---|---|
| `IP_AS_DOMAIN` | High | 30 | Target uses raw IPv4/IPv6 instead of a domain name. |
| `USERINFO_AT_SYMBOL` | Critical | 35 | Target uses `@` before domain (credential spoofing). |
| `BRAND_SPOOFING` | Critical | 35 | Known brand (e.g., `paypal`, `apple`) found in subdomain/path of another domain. |
| `PUNYCODE_HOMOGRAPH`| High | 25 | Host uses `xn--` encoding (IDN homograph attack). |
| `SUSPICIOUS_TLD` | Medium | 20 | High-abuse domain extension (`.xyz`, `.top`, `.tk`, `.zip`, etc.). |
| `REDIRECT_DOWNGRADE`| High | 25 | Redirection downgrades from HTTPS to unencrypted HTTP. |
| `URL_SHORTENER` | Medium | 15 | Known URL shortener masking the true final destination. |
| `MISLEADING_KEYWORDS`| Medium/High | 5–15 | Phishing keywords (`login`, `verify`, `banking`, `confirm`). |
| `EXPIRED_SSL` | High | 25 | Server TLS certificate has expired. |
| `SELF_SIGNED_SSL` | High | 20 | Certificate is self-signed or unverified by public CA. |
| `NON_HTTPS_SCHEME` | Medium | 12 | URL transmits data over unencrypted cleartext HTTP. |
| `NON_STANDARD_PORT` | Low | 12 | Port is non-standard (e.g. `:8080`, `:8443`, `:1337`). |
| `CROSS_DOMAIN_REDIRECT` | Medium | 15 | Link redirects to a different registered domain. |
| `EXCESSIVE_SUBDOMAINS`| Medium | 10 | Host contains more than 3 subdomain levels. |
| `DOMAIN_HYPHENS_DIGITS`| Medium | 10 | High frequency of hyphens and numbers in domain name. |
| `EXCESSIVE_LENGTH` | Low/Med | 5–10 | URL exceeds 75 or 120 characters in total length. |
| `SUSPICIOUS_PATH_PATTERNS`| Medium | 12 | Path contains double slashes `//` or traversal `..`. |
| `HEX_PERCENT_ENCODING`| Low | 10 | Heavy percent-encoding (>5 instances) obscuring characters. |
| `EXCESSIVE_QUERY_PARAMS`| Info | 8 | More than 4 query parameters present. |

**Risk Level Categories**:
- `0 - 29`: **Low Risk** (Normal URL structure, valid SSL, standard conventions).
- `30 - 69`: **Medium Risk** (Unencrypted HTTP, URL shortener, non-standard TLD, or several warnings).
- `70 - 100`: **High Risk** (Brand impersonation, userinfo spoofing, Punycode homoglyphs, or multiple critical flags).

---

## 7. Sample Test Cases & Outputs

### Case 1: Normal URL
- **Input**: `https://www.google.com/search?q=cybersecurity`
- **Risk Score**: `0 / 100` (`Low Risk`)
- **Flags Triggered**: `0`
- **Output Summary**:
  ```text
  No suspicious structural anomalies, phishing indicators, or deceptive redirection behaviors were identified.
  ```

### Case 2: Shortened URL
- **Input**: `https://tinyurl.com/sample-short-link`
- **Risk Score**: `15 / 100` (`Low Risk`)
- **Flags Triggered**:
  - `[MEDIUM] Known URL Shortening Service (tinyurl.com)` (+15 pts)
- **Output Summary**:
  ```text
  Low risk detected (Score 15/100). Minor anomalies or informational attributes were noted, but no severe deceptive patterns were detected.
  ```

### Case 3: Phishing-Style Brand Impersonation URL
- **Input**: `http://paypal.com.account-verification-security.xyz/login.php?user=admin&token=123`
- **Risk Score**: `82 / 100` (`High Risk`)
- **Flags Triggered**:
  - `[CRITICAL] Brand Impersonation in URL Path/Subdomain` (+35 pts)
  - `[MEDIUM] High-Abuse Top-Level Domain (.xyz)` (+20 pts)
  - `[HIGH] Multiple Sensitive / Phishing Keywords (login, account, verification)` (+15 pts)
  - `[MEDIUM] Unencrypted HTTP Scheme` (+12 pts)
- **Output Summary**:
  ```text
  High risk detected (Score 82/100). The target exhibits deceptive structural characteristics consistent with phishing, brand impersonation, or obfuscated destination infrastructure. Primary threats: Brand Impersonation in URL Path/Subdomain; Multiple Sensitive / Phishing Keywords.
  ```

---

## 8. Alignment with Project Objectives

1. **Customized Google Search Queries**: Implemented in `dork_generator.py` across 9 distinct categories using `site:`, `inurl:`, `intitle:`, `intext:`, `filetype:`, `ext:`, `related:`, `-exclusion`, `OR`, and quotes.
2. **Collect Publicly Indexed Information**: Generates direct, encoded search links for Google, Bing, and DuckDuckGo for authorized manual review.
3. **Analyze URL Structures, Domain Details, and Redirects**: `url_analyzer.py` breaks down RFC-3986 components, resolves IPv4/IPv6, queries PTR reverse DNS, inspects SSL certificate validity, and follows up to 10 redirect hops.
4. **Identify Suspicious URL Patterns**: `pattern_detector.py` evaluates 18+ rules including IP addresses as hosts, `@` userinfo spoofing, Punycode, high-abuse TLDs, and brand impersonation.
5. **Categorized Search Queries**: UI and backend organize queries into 9 defensive categories with dedicated icons, descriptions, and filtering tabs.
6. **Copy and Open in Search Engine**: Interactive buttons allow one-click copying of individual queries, copying all queries in bulk, or opening directly in Google/Bing/DuckDuckGo in a new tab.
7. **Organized, Readable Results**: Modern glassmorphic cards, tabbed views, vertical timeline for redirects, circular SVG risk gauge, and downloadable reports in TXT, CSV, and JSON.

---

## 9. Customization & Theming

- **Dark / Light Mode**: Toggleable via the top navigation button; preferences persist in `localStorage`.
- **Colors & Accents**: Configured in `static/css/style.css` under `:root` and `[data-theme="light"]`:
  - `--neon-cyan`: Primary cyber blue accent.
  - `--neon-violet`: Secondary purple accent.
  - `--neon-green`: Success / low risk indicator.
  - `--neon-red`: Alert / high risk indicator.
  - `--neon-yellow`: Warning / medium risk indicator.
- **Threat Weights & Brand Lists**: Edit `config.py` to add new monitored brands in `POPULAR_BRANDS`, update `SUSPICIOUS_TLDS`, or adjust rule points in `RISK_WEIGHTS`.

---

## 10. Ethical Notice & Rules of Engagement

This tool is strictly for authorized security assessments, penetration testing, defensive administration, and cybersecurity education. Only analyze web domains that you own or have received formal, written authorization to evaluate. The authors assume no liability for misuse.

---

## 11. Extended Advanced Features

### Feature 1: Redirect Chain Visualizer
- **Telemetry & Loops**: `/api/analyze` traces up to 10 hops, returning `redirect_chain` with latency per hop (`response_time_ms`), cross-domain hops, HTTPS-to-HTTP downgrades, and loop detection.
- **Visual Graph**: Animated node-and-arrow visualizer with color-coded nodes (Green = Same Domain, Orange = Cross-Domain, Red = Downgrade / Loop, Cyan = Final Endpoint) and a click-to-expand telemetry modal.

### Feature 2: Executive PDF Report Export
- **Auditing Reports**: `POST /api/report/pdf` compiles a ReportLab assessment PDF with cover metadata, executive summaries, risk badge, URL/SSL telemetry, redirect hop tables, flagged heuristics, and generated OSINT dorks.
- **Customization Modal**: Modal prompts for custom report title and analyst/lab affiliation.

### Feature 3: Modern Help Center & Incident Triage
- **Interactive Knowledge Base**: Modern searchable help center with Ctrl+K shortcut, 6 category guides, and popular article playbooks.
- **Validated Incident & Support Form**: `POST /api/contact` provides full server-side validation, rate limiting, a honeypot spam trap, and appends submissions to `contacts.json`.
- **Kolkata, India Timezone (IST)**: Real-time clock and reporting timestamps configured for Asia/Kolkata (UTC+05:30).


