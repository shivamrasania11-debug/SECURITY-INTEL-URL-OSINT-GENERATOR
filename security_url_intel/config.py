"""
Configuration and constants for Security Analysis & URL Intelligence Generator.
"""

APP_NAME = "Security Analysis & URL Intelligence Generator"
APP_VERSION = "1.0.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

# Timezone settings (Kolkata, India / Indian Standard Time)
from datetime import timezone, timedelta
TIMEZONE_NAME = "Asia/Kolkata"
TIMEZONE_LABEL = "IST (UTC+05:30)"
KOLKATA_TZ = timezone(timedelta(hours=5, minutes=30), name="IST")

# Network and request safety settings
REQUEST_TIMEOUT = 5.0  # seconds per passive probe
MAX_REDIRECTS = 10
MAX_RESPONSE_BODY_PREVIEW = 2048
SAFE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 "
    "(SecurityAnalysisBot/1.0; Passive OSINT Research)"
)

# High-risk / frequently abused Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "click", "surf",
    "rest", "icu", "work", "buzz", "cam", "fit", "country", "stream",
    "gdn", "kim", "racing", "download", "loan", "win", "bid", "vip",
    "party", "science", "cricket", "accountant", "faith", "review",
    "trade", "date", "men", "pw", "cc", "ws", "link", "mov"
}

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "bl.ink", "shorturl.at", "tiny.cc",
    "tr.im", "cli.re", "rb.gy", "s.id", "soo.gd", "v.gd", "qr.ae",
    "adf.ly", "bc.vc", "shorte.st", "hyperurl.co", "soo.gd", "snip.ly"
}

# Misleading security, authentication and financial keywords
MISLEADING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "account", "banking", "bank",
    "paypal", "wallet", "confirm", "confirmation", "password", "passcode",
    "credential", "billing", "auth", "authenticate", "authentication",
    "oauth", "support", "helpdesk", "recover", "recovery", "suspended",
    "unusual-activity", "validation", "validate", "checkpoint", "unlock",
    "authorize", "authorization", "re-activate", "reactivate", "tax-refund"
]

# High-profile brands frequently targeted by brand-impersonation / spoofing
POPULAR_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "twitter", "chase", "wellsfargo",
    "bankofamerica", "citibank", "binance", "coinbase", "dropbox",
    "yahoo", "linkedin", "adobe", "steam", "ebay", "walmart", "dhl",
    "fedex", "usps", "telegram", "github", "gitlab", "outlook", "icloud"
]

# Supported search engines
SEARCH_ENGINES = {
    "google": {
        "name": "Google",
        "base_url": "https://www.google.com/search?q={query}",
        "icon": "fab fa-google"
    },
    "bing": {
        "name": "Bing",
        "base_url": "https://www.bing.com/search?q={query}",
        "icon": "fab fa-microsoft"
    },
    "duckduckgo": {
        "name": "DuckDuckGo",
        "base_url": "https://duckduckgo.com/?q={query}",
        "icon": "fas fa-shield-alt"
    }
}

# Standard ports that are considered normal for web traffic
STANDARD_WEB_PORTS = {80, 443}

# Risk Scoring Weight Configuration (points contributing to 0-100 score)
RISK_WEIGHTS = {
    "IP_AS_DOMAIN": 25,
    "USERINFO_AT_SYMBOL": 20,
    "PUNYCODE_HOMOGRAPH": 20,
    "BRAND_SPOOFING": 30,
    "URL_SHORTENER": 15,
    "SUSPICIOUS_TLD": 15,
    "NON_HTTPS_SCHEME": 10,
    "EXCESSIVE_SUBDOMAINS": 8,
    "REDIRECT_DOWNGRADE": 20,
    "EXPIRED_SSL": 20,
    "SELF_SIGNED_SSL": 15,
    "MISLEADING_KEYWORDS": 15,
    "NON_STANDARD_PORT": 10,
    "CROSS_DOMAIN_REDIRECT": 10,
    "DOMAIN_HYPHENS_DIGITS": 8,
    "EXCESSIVE_LENGTH": 8,
    "SUSPICIOUS_PATH_PATTERNS": 10,
    "HEX_PERCENT_ENCODING": 8,
    "EXCESSIVE_QUERY_PARAMS": 6,
    "UNRESOLVED_DOMAIN": 15,
}

# Risk Score Thresholds
RISK_THRESHOLDS = {
    "low": "0-30",
    "medium": "31-60",
    "high": "61-100"
}

# Developer / Project Academic Attribution
PROJECT_INFO = {
    "name": "Security Analysis & URL Intelligence Generator",
    "developer_name": "Senior Cybersecurity Research Lab",
    "course": "Advanced Cyber Threat Intelligence & OSINT",
    "professor": "Dr. Sarah Chen, Ph.D. (Cybersecurity)",
    "github_url": "https://github.com/cybersecurity-lab/security-url-intel",
    "version": "4.0.0"
}

# OSINT Category Metadata
DORK_CATEGORIES = {
    "general": {
        "id": "general",
        "name": "General Information",
        "description": "Baseline domain indexing, related domains, page titles, and public metadata.",
        "icon": "fas fa-globe"
    },
    "documents": {
        "id": "documents",
        "name": "Exposed Documents",
        "description": "Locate indexed PDF, DOCX, XLSX, PPTX, CSV, and text records.",
        "icon": "fas fa-file-alt"
    },
    "login_admin": {
        "id": "login_admin",
        "name": "Login & Admin Pages",
        "description": "Administrative dashboards, staff sign-in endpoints, and portal interfaces.",
        "icon": "fas fa-user-lock"
    },
    "directory_listings": {
        "id": "directory_listings",
        "name": "Directory Listings",
        "description": "Open server directories, Apache/Nginx directory indexing, and asset folders.",
        "icon": "fas fa-folder-open"
    },
    "config_backups": {
        "id": "config_backups",
        "name": "Configuration & Backup Files",
        "description": "Exposed .env, .sql, .bak, .cfg, and configuration repositories.",
        "icon": "fas fa-database"
    },
    "subdomains": {
        "id": "subdomains",
        "name": "Subdomain Discovery",
        "description": "Discover internal, dev, staging, api, and cloud-hosted subdomains.",
        "icon": "fas fa-network-wired"
    },
    "sensitive_keywords": {
        "id": "sensitive_keywords",
        "name": "Sensitive Keywords",
        "description": "Scan for confidential tags, private markings, internal notices, and credentials.",
        "icon": "fas fa-key"
    },
    "technology_errors": {
        "id": "technology_errors",
        "name": "Technology & Error Disclosure",
        "description": "Debug stack traces, SQL syntax leaks, PHP warnings, and server fingerprints.",
        "icon": "fas fa-bug"
    },
    "public_mentions": {
        "id": "public_mentions",
        "name": "Public Mentions & Third-Party Repos",
        "description": "Search Pastebin, GitHub, forums, and leak aggregators mentioning the domain.",
        "icon": "fas fa-share-alt"
    }
}
