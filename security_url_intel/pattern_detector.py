"""
Suspicious Pattern Detector (pattern_detector.py)
Evaluates URL structure, domain heuristics, SSL validity, and redirect behavior
against 18+ threat rules to produce an actionable risk score (0-100) and flag list.
"""

import ipaddress
import re
import urllib.parse
from typing import Dict, Any, List

from config import (
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    MISLEADING_KEYWORDS,
    POPULAR_BRANDS,
    RISK_WEIGHTS,
    STANDARD_WEB_PORTS
)


class SuspiciousPatternDetector:
    """
    Analyzes URLs and extracted metadata to detect deceptive, malicious, or irregular patterns.
    """

    def __init__(self):
        self.weights = RISK_WEIGHTS

    def evaluate(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes all heuristic checks against the parsed URL and analysis data.
        Returns a dict containing:
          - flags: list of detected flags {rule_id, name, severity, explanation, weight}
          - score: weighted risk score between 0 and 100
          - level: "Low", "Medium", or "High"
          - summary: narrative explanation of the risk assessment
        """
        raw_url = analysis_result.get("url", "")
        structure = analysis_result.get("structure", {})
        domain_details = analysis_result.get("domain_details", {})
        redirects = analysis_result.get("redirects", {})

        flags: List[Dict[str, Any]] = []

        # 1. IP Address used as host
        self._check_ip_as_domain(structure, flags)

        # 2. '@' Symbol in URL (userinfo spoofing)
        self._check_at_symbol(raw_url, structure, flags)

        # 3. Punycode / Homograph attack indicator (xn--)
        self._check_punycode(structure, flags)

        # 4. Brand spoofing / Brand name in subdomain or path
        self._check_brand_spoofing(structure, flags)

        # 5. Suspicious / High-Abuse TLD
        self._check_suspicious_tld(structure, flags)

        # 6. Known URL Shortener
        self._check_url_shortener(structure, flags)

        # 7. Misleading Phishing Keywords
        self._check_misleading_keywords(structure, flags)

        # 8. Excessive Subdomains (>3 levels)
        self._check_excessive_subdomains(structure, flags)

        # 9. Hyphens and Digits in Domain Name
        self._check_domain_hyphens_digits(structure, flags)

        # 10. URL Length (>75 chars)
        self._check_url_length(raw_url, flags)

        # 11. Non-HTTPS Scheme (checks final destination and upgrade status)
        self._check_non_https(structure, redirects, flags)

        # 12. Unresolved Hostname / NXDOMAIN
        self._check_unresolved_domain(structure, domain_details, flags)

        # 12. Non-Standard Port
        self._check_non_standard_port(structure, flags)

        # 13. Suspicious Path Patterns (double slashes // or traversal ..)
        self._check_suspicious_path(structure, flags)

        # 14. Excessive or Suspicious Hex / Percent-Encoding
        self._check_percent_encoding(raw_url, flags)

        # 15. Excessive Query Parameters (>4)
        self._check_excessive_query_params(structure, flags)

        # 16. Protocol Downgrade in Redirects (HTTPS -> HTTP)
        self._check_protocol_downgrade(redirects, flags)

        # 17. Cross-Domain Redirects
        self._check_cross_domain_redirect(redirects, flags)

        # 18. SSL Certificate Issues (Expired or Self-Signed)
        self._check_ssl_issues(domain_details, flags)

        # Standardize all flag payloads with required transparent fields
        for f in flags:
            rule_id = f.get("rule_id") or f.get("id") or "UNKNOWN_RULE"
            f["id"] = rule_id
            f["rule_id"] = rule_id
            weight = f.get("weight") or self.weights.get(rule_id, 10)
            f["weight"] = weight
            f["points_added"] = f.get("points_added", weight)

        # Compute transparent risk score strictly from triggered flags (capped at 100)
        flags_weight = sum(f.get("points_added", f.get("weight", 0)) for f in flags)
        score = min(100, max(0, flags_weight))

        # Assign risk label based on configured thresholds:
        # Low: 0-30, Medium: 31-60, High: 61-100
        if score > 60:
            level = "High"
        elif score > 30:
            level = "Medium"
        else:
            level = "Low"

        safety_score = max(0, 100 - score)
        summary = self._generate_summary(level, score, flags, safety_score)

        # Build transparent Score Breakdown (Feature 1)
        score_breakdown = {
            "total": score,
            "label": level,
            "contributions": [
                {
                    "flag_id": f.get("id"),
                    "flag_name": f.get("name"),
                    "points": f.get("points_added", f.get("weight", 0)),
                    "severity": f.get("severity"),
                    "explanation": f.get("explanation")
                }
                for f in flags
            ],
            "thresholds": {
                "low": "0-30",
                "medium": "31-60",
                "high": "61-100"
            }
        }

        return {
            "score": score,
            "safety_score": safety_score,
            "level": level,
            "flags": flags,
            "flag_count": len(flags),
            "summary": summary,
            "score_breakdown": score_breakdown
        }

    # Rule Implementations

    def _check_ip_as_domain(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        host = struct.get("host", "")
        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            flags.append({
                "rule_id": "IP_AS_DOMAIN",
                "name": "Direct IP Address Used",
                "severity": "high",
                "weight": self.weights.get("IP_AS_DOMAIN", 30),
                "explanation": f"The URL uses a raw IP address ('{host}') instead of a registered domain name, often used to evade domain-based reputation filters."
            })

    def _check_at_symbol(self, raw_url: str, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        userinfo = struct.get("userinfo", "")
        if "@" in raw_url or userinfo:
            flags.append({
                "rule_id": "USERINFO_AT_SYMBOL",
                "name": "Userinfo '@' Symbol Spoofing",
                "severity": "critical",
                "weight": self.weights.get("USERINFO_AT_SYMBOL", 35),
                "explanation": "URL contains an '@' character. Browsers treat characters before '@' as user credentials and navigate to the host after '@', a classic credential-spoofing technique."
            })

    def _check_punycode(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        host = struct.get("host", "").lower()
        if "xn--" in host:
            flags.append({
                "rule_id": "PUNYCODE_HOMOGRAPH",
                "name": "Punycode / Homograph Character Encoding",
                "severity": "high",
                "weight": self.weights.get("PUNYCODE_HOMOGRAPH", 25),
                "explanation": f"The domain uses Punycode encoding ('{host}'), which can visually impersonate legitimate characters using look-alike Cyrillic or Greek glyphs (IDN homograph attack)."
            })

    def _check_brand_spoofing(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        subdomain = struct.get("subdomain", "").lower()
        path = struct.get("path", "").lower()
        domain = struct.get("domain", "").lower()

        # Check if known brand name is in subdomain or path, but domain does not belong to that brand
        detected_brands = []
        for brand in POPULAR_BRANDS:
            # Check if domain itself starts with brand (e.g. google.com is legit)
            domain_name_part = domain.split(".")[0] if "." in domain else domain
            if domain_name_part == brand:
                continue

            # Check if brand appears in subdomain or path
            if (f"{brand}." in subdomain or f".{brand}" in subdomain or subdomain == brand or
                f"-{brand}" in subdomain or f"{brand}-" in subdomain):
                detected_brands.append(brand)
            elif f"/{brand}" in path or f"-{brand}-" in path or f"/{brand}." in path:
                detected_brands.append(brand)

        if detected_brands:
            brands_str = ", ".join(detected_brands)
            flags.append({
                "rule_id": "BRAND_SPOOFING",
                "name": "Brand Impersonation in URL Path/Subdomain",
                "severity": "critical",
                "weight": self.weights.get("BRAND_SPOOFING", 35),
                "explanation": f"The URL mentions reputable brand name(s) ({brands_str}) in the subdomain or path, but the registered domain is '{domain}'. This is strongly indicative of phishing."
            })

    def _check_suspicious_tld(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        tld = struct.get("tld", "").lower()
        if tld in SUSPICIOUS_TLDS:
            flags.append({
                "rule_id": "SUSPICIOUS_TLD",
                "name": f"High-Abuse Top-Level Domain (.{tld})",
                "severity": "medium",
                "weight": self.weights.get("SUSPICIOUS_TLD", 20),
                "explanation": f"The domain uses the '.{tld}' top-level domain, which has historically higher rates of spam, scam campaigns, and low-cost disposable registrations."
            })

    def _check_url_shortener(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        domain = struct.get("domain", "").lower()
        host = struct.get("host", "").lower()
        if domain in URL_SHORTENERS or host in URL_SHORTENERS:
            flags.append({
                "rule_id": "URL_SHORTENER",
                "name": "Known URL Shortening Service",
                "severity": "medium",
                "weight": self.weights.get("URL_SHORTENER", 15),
                "explanation": f"The link uses a URL shortener service ('{domain}'), masking the final destination and bypassing casual inspection."
            })

    def _check_misleading_keywords(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        subdomain = struct.get("subdomain", "").lower()
        path = struct.get("path", "").lower()
        query = struct.get("query_string", "").lower()
        text_to_check = f"{subdomain} {path} {query}"

        matched = []
        for kw in MISLEADING_KEYWORDS:
            # Word boundary search
            if re.search(r'(?i)(?:^|[-_./?=&#])' + re.escape(kw) + r'(?:$|[-_./?=&#])', text_to_check):
                matched.append(kw)

        if len(matched) >= 2:
            flags.append({
                "rule_id": "MISLEADING_KEYWORDS",
                "name": "Multiple Sensitive / Phishing Keywords",
                "severity": "high",
                "weight": self.weights.get("MISLEADING_KEYWORDS", 15),
                "explanation": f"The URL includes multiple high-risk authentication and security keywords ({', '.join(matched[:5])}) designed to simulate login or account verification."
            })
        elif len(matched) == 1:
            flags.append({
                "rule_id": "MISLEADING_KEYWORDS",
                "name": "Sensitive Authentication Keyword Present",
                "severity": "low",
                "weight": 5,
                "explanation": f"The URL contains a sensitive security/auth keyword ('{matched[0]}'). Verify this matches the genuine service origin."
            })

    def _check_excessive_subdomains(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        subdomain = struct.get("subdomain", "")
        if subdomain:
            parts = subdomain.split(".")
            if len(parts) > 3:
                flags.append({
                    "rule_id": "EXCESSIVE_SUBDOMAINS",
                    "name": "Deep Subdomain Nesting (>3 Levels)",
                    "severity": "medium",
                    "weight": self.weights.get("EXCESSIVE_SUBDOMAINS", 10),
                    "explanation": f"The host has {len(parts)} subdomain levels ('{subdomain}'). Multi-layered subdomains are frequently used in DNS tunneling or deceptive phishing links."
                })

    def _check_domain_hyphens_digits(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        domain = struct.get("domain", "")
        # Remove TLD part
        domain_name = domain.split(".")[0] if "." in domain else domain
        hyphen_count = domain_name.count("-")
        digit_count = sum(c.isdigit() for c in domain_name)

        if hyphen_count >= 3 or (hyphen_count >= 2 and digit_count >= 3):
            flags.append({
                "rule_id": "DOMAIN_HYPHENS_DIGITS",
                "name": "Excessive Hyphens / Digits in Domain",
                "severity": "medium",
                "weight": self.weights.get("DOMAIN_HYPHENS_DIGITS", 10),
                "explanation": f"The registered domain name '{domain_name}' contains {hyphen_count} hyphens and {digit_count} digits, typical of automated algorithmically generated domains (DGA)."
            })

    def _check_url_length(self, raw_url: str, flags: List[Dict[str, Any]]) -> None:
        length = len(raw_url)
        if length > 120:
            flags.append({
                "rule_id": "EXCESSIVE_LENGTH",
                "name": f"Exceptionally Long URL ({length} characters)",
                "severity": "medium",
                "weight": self.weights.get("EXCESSIVE_LENGTH", 10),
                "explanation": f"The URL length ({length} characters) is unusually long, which can be an attempt to push malicious destination hostnames out of the address bar viewport."
            })
        elif length > 75:
            flags.append({
                "rule_id": "EXCESSIVE_LENGTH",
                "name": f"Elevated URL Length ({length} characters)",
                "severity": "low",
                "weight": 5,
                "explanation": f"URL exceeds 75 characters ({length} chars). Inspect query parameters and path structures."
            })

    def _check_non_https(self, struct: Dict[str, Any], redirects: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        scheme = struct.get("scheme", "").lower()
        final_url = redirects.get("final_url", "").lower()
        is_upgraded = redirects.get("is_upgraded", False) or final_url.startswith("https://")

        if scheme == "http":
            if is_upgraded:
                # Site upgrades to HTTPS - informative / positive
                flags.append({
                    "rule_id": "HTTP_UPGRADE_ENFORCED",
                    "name": "HTTP to HTTPS Upgrade Enforced",
                    "severity": "info",
                    "weight": 0,
                    "explanation": "Target initially used plain HTTP, but successfully redirected to secure HTTPS, enforcing encrypted transport."
                })
            else:
                flags.append({
                    "rule_id": "NON_HTTPS_SCHEME",
                    "name": "Unencrypted HTTP Scheme",
                    "severity": "medium",
                    "weight": self.weights.get("NON_HTTPS_SCHEME", 12),
                    "explanation": "Traffic to this URL remains unencrypted in cleartext, vulnerable to eavesdropping, interception, and Man-in-the-Middle (MitM) packet manipulation."
                })

    def _check_unresolved_domain(self, struct: Dict[str, Any], domain_details: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        host = struct.get("host", "")
        # Don't flag raw IP addresses or localhost
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            pass

        if host in ("localhost", "127.0.0.1"):
            return

        ipv4 = domain_details.get("ipv4", [])
        ipv6 = domain_details.get("ipv6", [])
        if not ipv4 and not ipv6:
            flags.append({
                "rule_id": "UNRESOLVED_DOMAIN",
                "name": "Unresolved Hostname (NXDOMAIN / Inactive)",
                "severity": "medium",
                "weight": self.weights.get("UNRESOLVED_DOMAIN", 15),
                "explanation": f"The host '{host}' does not resolve to any active IPv4 or IPv6 DNS records. The domain may be non-existent, abandoned, parked, or previously suspended by anti-abuse registrars."
            })

    def _check_non_standard_port(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        port = struct.get("port")
        if port and port not in STANDARD_WEB_PORTS:
            flags.append({
                "rule_id": "NON_STANDARD_PORT",
                "name": f"Non-Standard Web Port (Port {port})",
                "severity": "low",
                "weight": self.weights.get("NON_STANDARD_PORT", 12),
                "explanation": f"The service runs on explicit custom port {port} instead of standard 80 (HTTP) or 443 (HTTPS), common in test setups or unconventional Command & Control infrastructure."
            })

    def _check_suspicious_path(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        path = struct.get("path", "")
        if "//" in path or "/../" in path or "/./" in path:
            flags.append({
                "rule_id": "SUSPICIOUS_PATH_PATTERNS",
                "name": "Abnormal Path Structure (Double Slashes / Traversal)",
                "severity": "medium",
                "weight": self.weights.get("SUSPICIOUS_PATH_PATTERNS", 12),
                "explanation": "URL path contains double slashes ('//') or directory traversal tokens ('..') used to bypass reverse-proxy routing rules or Web Application Firewalls."
            })

    def _check_percent_encoding(self, raw_url: str, flags: List[Dict[str, Any]]) -> None:
        encodings = re.findall(r'%[0-9a-fA-F]{2}', raw_url)
        if len(encodings) > 5:
            flags.append({
                "rule_id": "HEX_PERCENT_ENCODING",
                "name": f"High Frequency Hex / Percent Encoding ({len(encodings)} instances)",
                "severity": "low",
                "weight": self.weights.get("HEX_PERCENT_ENCODING", 10),
                "explanation": f"URL exhibits heavy percent-encoding ({len(encodings)} encoded bytes), often used to obfuscate script payloads, special characters, or target URLs."
            })

    def _check_excessive_query_params(self, struct: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        count = struct.get("query_param_count", 0)
        if count > 4:
            flags.append({
                "rule_id": "EXCESSIVE_QUERY_PARAMS",
                "name": f"Excessive Query Parameters ({count} parameters)",
                "severity": "info",
                "weight": self.weights.get("EXCESSIVE_QUERY_PARAMS", 8),
                "explanation": f"The request contains {count} query parameters. Complex parameters are often used for tracking tokens, referral cascades, or affiliate redirections."
            })

    def _check_protocol_downgrade(self, redirects: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        if redirects.get("is_downgraded"):
            flags.append({
                "rule_id": "REDIRECT_DOWNGRADE",
                "name": "HTTPS-to-HTTP Protocol Downgrade Detected",
                "severity": "high",
                "weight": self.weights.get("REDIRECT_DOWNGRADE", 25),
                "explanation": "The redirection sequence shifted from encrypted HTTPS to insecure cleartext HTTP, stripping SSL protections and exposing visitor data."
            })

    def _check_cross_domain_redirect(self, redirects: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        if redirects.get("is_cross_domain"):
            flags.append({
                "rule_id": "CROSS_DOMAIN_REDIRECT",
                "name": "Cross-Domain Redirection Observed",
                "severity": "medium",
                "weight": self.weights.get("CROSS_DOMAIN_REDIRECT", 15),
                "explanation": f"The initial target redirected off-site to a completely different registered domain ('{redirects.get('final_url')}'). Verify the target destination is trustworthy."
            })

    def _check_ssl_issues(self, domain_details: Dict[str, Any], flags: List[Dict[str, Any]]) -> None:
        ssl_info = domain_details.get("ssl", {})
        if not ssl_info.get("enabled"):
            return

        if ssl_info.get("is_expired"):
            flags.append({
                "rule_id": "EXPIRED_SSL",
                "name": "Expired SSL/TLS Certificate",
                "severity": "high",
                "weight": self.weights.get("EXPIRED_SSL", 25),
                "explanation": f"The SSL certificate has expired (validity ended on {ssl_info.get('valid_to')}), resulting in browser security warnings and broken trust."
            })

        if ssl_info.get("is_self_signed"):
            flags.append({
                "rule_id": "SELF_SIGNED_SSL",
                "name": "Self-Signed / Untrusted SSL Certificate",
                "severity": "high",
                "weight": self.weights.get("SELF_SIGNED_SSL", 20),
                "explanation": f"The certificate issuer matches the subject or failed CA chain verification (Issuer: {ssl_info.get('issuer')}), indicating an untrusted or self-signed certificate."
            })

    def _generate_summary(self, level: str, score: int, flags: List[Dict[str, Any]], safety_score: int = 0) -> str:
        high_flags = [f["name"] for f in flags if f.get("severity") in ("high", "critical")]
        if level == "High":
            reasons = f" Primary threats: {'; '.join(high_flags[:3])}." if high_flags else ""
            return f"High Threat Risk: {score}% (Safety Index: {safety_score}%). The analyzed URL exhibits critical deceptive patterns, high-risk infrastructure anomalies, or active brand spoofing characteristics.{reasons}"
        elif level == "Medium":
            medium_flags = [f["name"] for f in flags]
            flags_text = f" Observed warning factors: {'; '.join(medium_flags[:3])}." if medium_flags else ""
            return f"Moderate Threat Risk: {score}% (Safety Index: {safety_score}%). The URL exhibits several warning flags (such as protocol deficiencies, domain anomalies, or redirection behavior) that warrant caution before interacting.{flags_text}"
        else:
            return f"Low Threat Risk: {score}% (Safety Index: {safety_score}%). The URL exhibits standard RFC structural integrity and standard domain infrastructure. No critical phishing indicators or deceptive patterns were detected."
