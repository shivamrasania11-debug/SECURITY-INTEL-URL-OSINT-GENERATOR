"""
Utility functions for validation, normalization, search engine URL construction,
and report export formatting (TXT, CSV, JSON).
"""

import csv
import io
import json
import re
import urllib.parse
from datetime import datetime, date
from typing import Dict, Any, Optional

from config import SEARCH_ENGINES, APP_NAME, APP_VERSION, KOLKATA_TZ

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def normalize_domain(domain_str: str) -> str:
    """
    Normalizes a domain input by stripping protocols, 'www.', paths,
    query parameters, fragments, userinfo, and ports.
    """
    if not domain_str:
        return ""
    
    clean = domain_str.strip().lower()

    # If it contains scheme or slashes, try urllib.parse first
    if "://" in clean:
        try:
            parsed = urllib.parse.urlparse(clean)
            clean = parsed.netloc or parsed.path
        except Exception:
            clean = re.sub(r"^[a-zA-Z]+://", "", clean)
    elif clean.startswith("//"):
        clean = clean[2:]

    # Remove userinfo (e.g. user:pass@host)
    if "@" in clean:
        clean = clean.split("@")[-1]

    # Remove path, query, fragment
    clean = clean.split("/")[0]
    clean = clean.split("?")[0]
    clean = clean.split("#")[0]

    # Remove port if present (handle both ipv4:port and host:port, leaving ipv6 alone if enclosed)
    if ":" in clean and not (clean.startswith("[") and clean.endswith("]")):
        clean = clean.split(":")[0]

    # Strip leading 'www.'
    if clean.startswith("www."):
        clean = clean[4:]

    return clean.strip().rstrip(".")


def is_valid_domain(domain_str: str) -> bool:
    """
    Validates whether the string is a syntactically valid domain name or IPv4 address.
    """
    if not domain_str:
        return False
    norm = normalize_domain(domain_str)
    if not norm or len(norm) > 253:
        return False
    if IPV4_REGEX.match(norm):
        return True
    return bool(DOMAIN_REGEX.match(norm))


def is_valid_url(url_str: str) -> bool:
    """
    Validates whether the provided string is a valid HTTP/HTTPS URL.
    """
    if not url_str or not isinstance(url_str, str):
        return False
    clean = url_str.strip()
    try:
        parsed = urllib.parse.urlparse(clean)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False


def build_search_url(query: str, engine: str = "google") -> str:
    """
    Constructs an encoded web search URL for Google, Bing, or DuckDuckGo.
    """
    engine_key = engine.lower() if engine else "google"
    engine_info = SEARCH_ENGINES.get(engine_key, SEARCH_ENGINES["google"])
    encoded_query = urllib.parse.quote_plus(query)
    return engine_info["base_url"].format(query=encoded_query)


def json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    return str(obj)


def format_txt_report(report_data: Dict[str, Any], report_type: str = "analysis") -> str:
    """
    Generates a clean ASCII cyber intelligence report.
    """
    timestamp = datetime.now(KOLKATA_TZ).strftime("%Y-%m-%d %H:%M:%S IST (Kolkata)")
    lines = [
        "=" * 78,
        f"{APP_NAME.upper()} - {report_type.upper()} REPORT",
        f"Generated At: {timestamp}",
        f"Timezone: Asia/Kolkata (IST, UTC+05:30)",
        f"Engine Version: {APP_VERSION}",
        "=" * 78,
        ""
    ]

    if report_type == "dorks":
        target = report_data.get("domain", "Unknown Target")
        engine = report_data.get("engine", "google").capitalize()
        categories = report_data.get("categories", {})
        total_queries = report_data.get("total_queries", 0)

        lines.append(f"TARGET DOMAIN : {target}")
        lines.append(f"SEARCH ENGINE : {engine}")
        lines.append(f"TOTAL QUERIES : {total_queries}")
        lines.append("-" * 78)
        lines.append("")

        for cat_name, items in categories.items():
            lines.append(f"[{cat_name.upper()}] ({len(items)} queries)")
            lines.append("~" * 60)
            for idx, item in enumerate(items, 1):
                lines.append(f"  {idx}. {item.get('label', 'Query')}")
                lines.append(f"     Description : {item.get('description', '')}")
                lines.append(f"     Query       : {item.get('query', '')}")
                lines.append(f"     Search URL  : {item.get('search_url', '')}")
                lines.append("")
            lines.append("")

    else:
        # URL Analysis Report
        target_url = report_data.get("url", "Unknown Target")
        risk = report_data.get("risk", {})
        structure = report_data.get("structure", {})
        domain_info = report_data.get("domain_details", {})
        redirects = report_data.get("redirects", {})
        flags = report_data.get("flags", [])

        lines.append(f"TARGET URL    : {target_url}")
        lines.append(f"RISK LEVEL    : {risk.get('level', 'UNKNOWN').upper()} ({risk.get('score', 0)}/100)")
        lines.append(f"RISK SUMMARY  : {risk.get('summary', 'N/A')}")
        lines.append("-" * 78)
        lines.append("")

        lines.append("[1] SUSPICIOUS PATTERNS & SECURITY FLAGS")
        lines.append("~" * 60)
        if flags:
            for idx, flag in enumerate(flags, 1):
                lines.append(f"  [{flag.get('severity', 'INFO').upper()}] {flag.get('name')}")
                lines.append(f"    Explanation: {flag.get('explanation')}")
                lines.append("")
        else:
            lines.append("  No suspicious structural heuristics detected.\n")

        lines.append("[2] URL STRUCTURE BREAKDOWN")
        lines.append("~" * 60)
        lines.append(f"  Scheme          : {structure.get('scheme')}")
        lines.append(f"  Host / Domain   : {structure.get('domain')}")
        lines.append(f"  Subdomain       : {structure.get('subdomain') or '(none)'}")
        lines.append(f"  TLD             : {structure.get('tld')}")
        lines.append(f"  Port            : {structure.get('port')}")
        lines.append(f"  Path            : {structure.get('path')}")
        lines.append(f"  Query String    : {structure.get('query_string') or '(none)'}")
        lines.append(f"  Query Param Cnt : {structure.get('query_param_count', 0)}")
        lines.append(f"  Fragment        : {structure.get('fragment') or '(none)'}")
        lines.append(f"  Total Length    : {structure.get('length')} chars")
        lines.append("")

        lines.append("[3] DOMAIN, DNS & SSL DETAILS")
        lines.append("~" * 60)
        lines.append(f"  Resolved IPv4   : {', '.join(domain_info.get('ipv4', [])) or 'None'}")
        lines.append(f"  Resolved IPv6   : {', '.join(domain_info.get('ipv6', [])) or 'None'}")
        lines.append(f"  Reverse DNS PTR : {domain_info.get('reverse_dns') or 'N/A'}")
        
        ssl_info = domain_info.get("ssl", {})
        if ssl_info.get("enabled"):
            lines.append(f"  SSL Issuer      : {ssl_info.get('issuer')}")
            lines.append(f"  SSL Subject     : {ssl_info.get('subject')}")
            lines.append(f"  SSL Valid From  : {ssl_info.get('valid_from')}")
            lines.append(f"  SSL Valid To    : {ssl_info.get('valid_to')}")
            lines.append(f"  Days Remaining  : {ssl_info.get('days_remaining')}")
            lines.append(f"  Is Expired      : {ssl_info.get('is_expired')}")
            lines.append(f"  Is Self-Signed  : {ssl_info.get('is_self_signed')}")
        else:
            lines.append(f"  SSL Status      : Not Active / Non-HTTPS ({ssl_info.get('error', 'None')})")

        whois_info = domain_info.get("whois", {})
        lines.append(f"  WHOIS Registrar : {whois_info.get('registrar') or 'Unavailable'}")
        lines.append(f"  WHOIS Age (Days): {whois_info.get('age_days') or 'Unavailable'}")
        lines.append("")

        lines.append("[4] REDIRECT BEHAVIOR")
        lines.append("~" * 60)
        chain = redirects.get("chain", [])
        lines.append(f"  Total Hops      : {redirects.get('hop_count', 0)}")
        lines.append(f"  Final URL       : {redirects.get('final_url')}")
        lines.append(f"  Cross-Domain    : {redirects.get('is_cross_domain')}")
        lines.append(f"  HTTPS Downgrade : {redirects.get('is_downgraded')}")
        for hop in chain:
            lines.append(f"    Hop #{hop.get('hop')} -> [{hop.get('status_code')}] {hop.get('url')}")
            if hop.get("next_url"):
                lines.append(f"           Redirects to: {hop.get('next_url')}")
        lines.append("")

    lines.append("=" * 78)
    lines.append("DISCLAIMER: For authorized cybersecurity research and defensive analysis only.")
    lines.append("=" * 78)
    return "\n".join(lines)


def format_csv_report(report_data: Dict[str, Any], report_type: str = "analysis") -> str:
    """
    Generates a structured CSV report.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == "dorks":
        writer.writerow(["Target Domain", "Category", "Query Label", "Dork Query", "Description", "Search URL"])
        domain = report_data.get("domain", "")
        for cat_name, items in report_data.get("categories", {}).items():
            for item in items:
                writer.writerow([
                    domain,
                    cat_name,
                    item.get("label", ""),
                    item.get("query", ""),
                    item.get("description", ""),
                    item.get("search_url", "")
                ])
    else:
        writer.writerow(["Section", "Property", "Value", "Notes"])
        url = report_data.get("url", "")
        risk = report_data.get("risk", {})
        writer.writerow(["Target", "URL", url, "Analyzed target"])
        writer.writerow(["Risk", "Score", risk.get("score"), "Out of 100"])
        writer.writerow(["Risk", "Level", risk.get("level"), risk.get("summary", "")])

        # Flags
        for flag in report_data.get("flags", []):
            writer.writerow(["Flag", flag.get("name"), flag.get("severity"), flag.get("explanation")])

        # Structure
        struct = report_data.get("structure", {})
        for k, v in struct.items():
            writer.writerow(["Structure", k, str(v), ""])

        # Domain
        dinfo = report_data.get("domain_details", {})
        writer.writerow(["Domain", "IPv4", ", ".join(dinfo.get("ipv4", [])), ""])
        writer.writerow(["Domain", "IPv6", ", ".join(dinfo.get("ipv6", [])), ""])
        writer.writerow(["Domain", "Reverse DNS", str(dinfo.get("reverse_dns")), ""])

        # SSL
        ssl_info = dinfo.get("ssl", {})
        for k, v in ssl_info.items():
            writer.writerow(["SSL", k, str(v), ""])

        # Redirects
        red = report_data.get("redirects", {})
        writer.writerow(["Redirects", "Hop Count", red.get("hop_count"), ""])
        writer.writerow(["Redirects", "Final URL", red.get("final_url"), ""])
        writer.writerow(["Redirects", "Cross-Domain", red.get("is_cross_domain"), ""])
        writer.writerow(["Redirects", "Protocol Downgrade", red.get("is_downgraded"), ""])
        for hop in red.get("chain", []):
            writer.writerow(["Redirect Hop", f"Hop {hop.get('hop')}", hop.get("status_code"), hop.get("url")])

    return output.getvalue()


def format_json_report(report_data: Dict[str, Any]) -> str:
    """
    Returns pretty-printed JSON string with metadata.
    """
    export_payload = {
        "generator": APP_NAME,
        "version": APP_VERSION,
        "timezone": "Asia/Kolkata",
        "exported_at": datetime.now(KOLKATA_TZ).isoformat(),
        "payload": report_data
    }
    return json.dumps(export_payload, indent=2, default=json_serial)

