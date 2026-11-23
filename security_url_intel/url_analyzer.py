import time
"""
URL Analyzer (url_analyzer.py)
Performs strictly passive reconnaissance and structural breakdown:
- URL structure decomposition (scheme, domain, subdomain, TLD, port, path, params, fragment, length)
- Domain network details (IPv4/IPv6 resolution, reverse DNS PTR)
- SSL/TLS certificate inspection (issuer, validity, expiration, days remaining, self-signed flag)
  with support for self-signed / expired cert decoding
- RDAP and WHOIS intelligence (registrar, creation/expiry dates, domain age in days)
- Redirect chain tracing (up to 10 hops, cross-domain, downgrade, and upgrade detection)
"""

import datetime
import ipaddress
import re
import socket
import ssl
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

import requests
import urllib3
from requests.exceptions import RequestException

from config import REQUEST_TIMEOUT, MAX_REDIRECTS, SAFE_USER_AGENT, STANDARD_WEB_PORTS

# Suppress InsecureRequestWarning for passive reconnaissance
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common two-level TLDs to ensure accurate subdomain/domain separation
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.in", "net.in", "org.in", "gov.in", "edu.in", "res.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "edu.sg", "gov.sg",
    "co.za", "org.za", "web.za",
    "com.mx", "org.mx", "edu.mx", "gob.mx",
    "co.kr", "ne.kr", "or.kr", "re.kr"
}


class URLAnalyzer:
    """
    Performs safe, passive URL and domain intelligence gathering.
    """

    def __init__(self, timeout: float = REQUEST_TIMEOUT, user_agent: str = SAFE_USER_AGENT):
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        """
        Executes complete passive analysis pipeline for the provided URL.
        """
        if not raw_url or not isinstance(raw_url, str):
            raise ValueError("URL must be a non-empty string.")

        target_url = raw_url.strip()
        if not target_url.startswith(("http://", "https://")):
            # Prepend https by default if missing
            target_url = "https://" + target_url

        structure = self.parse_structure(target_url)
        domain = structure["domain"]
        host = structure["host"]
        port = structure["port"]
        is_https = structure["scheme"] == "https"

        # 1. Domain DNS & Network Resolution
        dns_info = self.resolve_dns(host)

        # 2. Trace Redirect Chain (passive HEAD/GET)
        redirect_info = self.trace_redirects(target_url)
        final_url = redirect_info.get("final_url", target_url)
        final_parsed = urllib.parse.urlsplit(final_url)
        final_host = final_parsed.netloc.split(":")[0].strip("[]").lower() if final_parsed.netloc else host
        final_is_https = final_parsed.scheme.lower() == "https"

        # 3. SSL/TLS Certificate Inspection
        # Inspect SSL if original was HTTPS, or final URL is HTTPS, or port 443 responds
        target_ssl_host = final_host if final_is_https else host
        if is_https or final_is_https or port == 443:
            ssl_info = self.inspect_ssl(target_ssl_host, 443)
        else:
            # Check if port 443 responds on host passively
            ssl_info = self._probe_ssl_fallback(host)

        # 4. WHOIS / RDAP Intelligence Lookup
        whois_info = self.lookup_whois(domain)

        return {
            "url": target_url,
            "structure": structure,
            "domain_details": {
                "host": host,
                "domain": domain,
                "ipv4": dns_info["ipv4"],
                "ipv6": dns_info["ipv6"],
                "reverse_dns": dns_info["reverse_dns"],
                "ssl": ssl_info,
                "whois": whois_info
            },
            "redirects": redirect_info
        }

    def parse_structure(self, url: str) -> Dict[str, Any]:
        """
        Deconstructs URL into discrete RFC-3986 components and calculates lengths.
        """
        parsed = urllib.parse.urlsplit(url)
        scheme = (parsed.scheme or "http").lower()
        netloc = parsed.netloc

        # Parse userinfo if present
        userinfo = ""
        host_port = netloc
        if "@" in netloc:
            userinfo, host_port = netloc.split("@", 1)

        # Parse port
        port = 443 if scheme == "https" else 80
        host = host_port
        if ":" in host_port and not (host_port.startswith("[") and host_port.endswith("]")):
            parts = host_port.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        host_clean = host.strip("[]").lower()
        subdomain, domain, tld = self._split_domain_parts(host_clean)

        # Parse query params
        raw_query = parsed.query
        query_params = []
        if raw_query:
            parsed_qs = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
            for k, vals in parsed_qs.items():
                for v in vals:
                    query_params.append({"key": k, "value": v})

        path = parsed.path or "/"

        return {
            "raw_url": url,
            "scheme": scheme,
            "host": host_clean,
            "subdomain": subdomain,
            "domain": domain,
            "tld": tld,
            "port": port,
            "is_standard_port": port in STANDARD_WEB_PORTS,
            "userinfo": userinfo,
            "path": path,
            "query_string": raw_query,
            "query_params": query_params,
            "query_param_count": len(query_params),
            "fragment": parsed.fragment,
            "length": len(url),
            "path_length": len(path),
            "query_length": len(raw_query)
        }

    def _split_domain_parts(self, host: str) -> Tuple[str, str, str]:
        """
        Splits a hostname into (subdomain, registered_domain, tld).
        Handles multi-part TLDs (e.g. .co.uk) and IP addresses.
        """
        try:
            ipaddress.ip_address(host)
            return "", host, ""
        except ValueError:
            pass

        labels = host.split(".")
        if len(labels) == 1:
            return "", host, ""

        # Check multi-part TLDs
        if len(labels) >= 3:
            last_two = f"{labels[-2]}.{labels[-1]}"
            if last_two in MULTI_PART_TLDS:
                tld = last_two
                domain_name = labels[-3]
                subdomain = ".".join(labels[:-3])
                registered_domain = f"{domain_name}.{tld}"
                return subdomain, registered_domain, tld

        # Standard single TLD
        tld = labels[-1]
        domain_name = labels[-2]
        subdomain = ".".join(labels[:-2])
        registered_domain = f"{domain_name}.{tld}"
        return subdomain, registered_domain, tld

    def resolve_dns(self, host: str) -> Dict[str, Any]:
        """
        Performs passive forward and reverse DNS lookups using socket.
        """
        ipv4_list = []
        ipv6_list = []
        reverse_dns = None

        clean_host = host.strip("[]")

        # Resolve IPv4 and IPv6
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            for item in addr_info:
                family, _, _, _, sockaddr = item
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ipv4_list:
                    ipv4_list.append(ip)
                elif family == socket.AF_INET6 and ip not in ipv6_list:
                    ipv6_list.append(ip)
        except (socket.gaierror, socket.herror, Exception):
            pass

        # Reverse DNS lookup on the primary IPv4 or host
        target_ip = ipv4_list[0] if ipv4_list else None
        if target_ip:
            try:
                ptr_info = socket.gethostbyaddr(target_ip)
                if ptr_info and ptr_info[0]:
                    reverse_dns = ptr_info[0]
            except (socket.herror, socket.gaierror, Exception):
                reverse_dns = None

        return {
            "ipv4": ipv4_list,
            "ipv6": ipv6_list,
            "reverse_dns": reverse_dns
        }

    def inspect_ssl(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Connects via TLS to inspect server certificate validity and attributes.
        Extracts issuer, subject, validity dates, days remaining, and self-signed flags.
        Handles both verified and unverified/self-signed certificates.
        """
        clean_host = host.strip("[]")
        result = {
            "enabled": False,
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "is_expired": False,
            "is_self_signed": False,
            "sans": [],
            "error": None
        }

        # 1. Attempt verified SSL handshake
        verified_context = ssl.create_default_context()
        verified_context.check_hostname = True
        verified_context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((clean_host, port), timeout=self.timeout) as sock:
                with verified_context.wrap_socket(sock, server_hostname=clean_host) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    self._populate_cert_details(result, cert, is_self_signed=False)
                    result["enabled"] = True
                    return result
        except ssl.SSLCertVerificationError as ve:
            # Verification failed (self-signed, expired, or hostname mismatch)
            result["enabled"] = True
            result["error"] = f"SSL Verification Warning: {ve.verify_message}"
            is_self_signed = "self signed" in str(ve).lower() or getattr(ve, "verify_code", 0) in (18, 19)
            result["is_self_signed"] = is_self_signed

            # Inspect certificate details using unverified context
            self._decode_unverified_cert(clean_host, port, result)
            return result
        except Exception as e:
            # Connection failed or port closed
            result["error"] = f"TLS handshake failed: {str(e)}"
            return result

    def _decode_unverified_cert(self, host: str, port: int, result: Dict[str, Any]) -> None:
        """
        Extracts certificate metadata from an unverified TLS peer certificate.
        """
        try:
            unverified_context = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with unverified_context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                    raw_der = ssl_sock.getpeercert(binary_form=True)
                    if raw_der:
                        try:
                            from cryptography import x509
                            cert = x509.load_der_x509_certificate(raw_der)
                            result["issuer"] = cert.issuer.rfc4514_string()
                            result["subject"] = cert.subject.rfc4514_string()
                            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
                            not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
                            
                            result["valid_from"] = not_before.strftime("%b %d %H:%M:%S %Y GMT")
                            result["valid_to"] = not_after.strftime("%b %d %H:%M:%S %Y GMT")

                            now = datetime.datetime.now(datetime.timezone.utc) if hasattr(not_after, "tzinfo") and not_after.tzinfo else datetime.datetime.utcnow()
                            diff = not_after - now
                            result["days_remaining"] = diff.days
                            result["is_expired"] = diff.total_seconds() <= 0
                            if result["issuer"] == result["subject"]:
                                result["is_self_signed"] = True
                        except Exception:
                            # Fallback flag
                            result["is_self_signed"] = True
        except Exception:
            pass

    def _probe_ssl_fallback(self, host: str) -> Dict[str, Any]:
        """
        Checks if host supports HTTPS on port 443 even if the initial URL was HTTP.
        """
        clean_host = host.strip("[]")
        fallback_res = {
            "enabled": False,
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "is_expired": False,
            "is_self_signed": False,
            "sans": [],
            "error": "Target does not use HTTPS and port 443 is not active."
        }
        try:
            with socket.create_connection((clean_host, 443), timeout=2.0):
                return self.inspect_ssl(clean_host, 443)
        except Exception:
            return fallback_res

    def _populate_cert_details(self, result: Dict[str, Any], cert: Dict[str, Any], is_self_signed: bool) -> None:
        """
        Parses certificate dictionary fields returned by getpeercert().
        """
        if not cert:
            return

        issuer_dict = {}
        for rdn in cert.get("issuer", ()):
            for key, val in rdn:
                issuer_dict[key] = val
        result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

        subject_dict = {}
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                subject_dict[key] = val
        result["subject"] = subject_dict.get("commonName") or subject_dict.get("organizationName") or "Unknown Subject"

        if issuer_dict and subject_dict and issuer_dict == subject_dict:
            is_self_signed = True
        result["is_self_signed"] = is_self_signed

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        result["valid_from"] = not_before
        result["valid_to"] = not_after

        if not_after:
            try:
                expire_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                diff = expire_dt - now
                result["days_remaining"] = diff.days
                result["is_expired"] = diff.total_seconds() <= 0
            except Exception:
                pass

        sans = []
        for typ, val in cert.get("subjectAltName", ()):
            if typ.lower() == "dns":
                sans.append(val)
        result["sans"] = sans[:15]

    def lookup_whois(self, domain: str) -> Dict[str, Any]:
        """
        Performs WHOIS / RDAP lookup using RFC 7480/7484 RDAP with fallback to python-whois.
        Accurately extracts registrar, creation date, expiration date, and domain age in days.
        """
        whois_data = {
            "available": False,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "age_days": None,
            "raw_status": None,
            "note": ""
        }

        # Check if domain is an IP address
        try:
            ipaddress.ip_address(domain)
            whois_data["note"] = "Target is a raw IP address; domain WHOIS not applicable."
            return whois_data
        except ValueError:
            pass

        if not domain or domain in ("localhost", "127.0.0.1"):
            whois_data["note"] = "Localhost / loopback address."
            return whois_data

        # 1. Primary Strategy: Fast standard RDAP query
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            res = requests.get(
                rdap_url,
                timeout=3.5,
                headers={"Accept": "application/json", "User-Agent": self.user_agent}
            )
            if res.status_code == 200:
                data = res.json()
                created_str = None
                expires_str = None
                registrar_name = None

                # Extract events
                for event in data.get("events", []):
                    action = event.get("eventAction")
                    date_val = event.get("eventDate")
                    if action == "registration" and not created_str:
                        created_str = date_val
                    elif action == "expiration" and not expires_str:
                        expires_str = date_val

                # Extract registrar entity
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if len(prop) > 3 and prop[0] == "fn":
                                    registrar_name = prop[3]
                                    break
                    if registrar_name:
                        break

                # Calculate domain age in days
                age_days = None
                if created_str:
                    try:
                        clean_dt = created_str.replace("Z", "+00:00")
                        dt = datetime.datetime.fromisoformat(clean_dt)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        age_days = (now - dt).days
                    except Exception:
                        pass

                whois_data["available"] = True
                whois_data["registrar"] = registrar_name or "Listed / Privacy Protected"
                whois_data["creation_date"] = created_str
                whois_data["expiration_date"] = expires_str
                whois_data["age_days"] = age_days
                whois_data["note"] = "RDAP record retrieved successfully."
                return whois_data
        except Exception:
            pass

        # 2. Secondary Strategy: python-whois fallback
        try:
            import whois
            w = whois.whois(domain)
            if w and (w.registrar or w.creation_date):
                registrar = w.registrar
                creation = w.creation_date
                expiration = w.expiration_date

                if isinstance(creation, list): creation = creation[0]
                if isinstance(expiration, list): expiration = expiration[0]

                age_days = None
                if isinstance(creation, (datetime.datetime, datetime.date)):
                    now = datetime.datetime.utcnow()
                    if isinstance(creation, datetime.datetime):
                        age_days = (now - creation).days
                    else:
                        age_days = (now.date() - creation).days

                whois_data["available"] = True
                whois_data["registrar"] = str(registrar) if registrar else "Private / Unlisted"
                whois_data["creation_date"] = creation.isoformat() if creation else None
                whois_data["expiration_date"] = expiration.isoformat() if expiration else None
                whois_data["age_days"] = age_days
                whois_data["note"] = "WHOIS record retrieved via system client."
                return whois_data
        except Exception as e:
            whois_data["note"] = f"WHOIS/RDAP query offline for target: {type(e).__name__}"

        return whois_data

    def trace_redirects(self, start_url: str) -> Dict[str, Any]:
        """
        Passively follows redirect chain up to MAX_REDIRECTS hops,
        inspecting status codes, headers, protocol downgrades, and upgrades.
        Detects redirect loops and tracks response latency per hop (Feature 2).
        """
        chain = []
        current_url = start_url
        initial_parsed = urllib.parse.urlsplit(start_url)
        initial_domain = initial_parsed.netloc.split(":")[0].lower() if initial_parsed.netloc else ""
        initial_scheme = initial_parsed.scheme.lower()

        hop = 0
        is_downgraded = False
        is_upgraded = False
        is_cross_domain = False
        has_loop = False
        visited_urls = set()

        while hop < MAX_REDIRECTS:
            hop += 1
            curr_parsed = urllib.parse.urlsplit(current_url)
            curr_domain = curr_parsed.netloc.split(":")[0].lower() if curr_parsed.netloc else initial_domain

            # Loop detection
            if current_url in visited_urls:
                has_loop = True
                chain.append({
                    "hop": hop,
                    "url": current_url,
                    "domain": curr_domain,
                    "status_code": 310,  # Standard redirect loop code indicator
                    "reason": "Redirect Loop Detected (Looping back to previously visited URL)",
                    "location_header": current_url,
                    "next_url": current_url,
                    "is_cross_domain": False,
                    "is_https_downgrade": False,
                    "response_time_ms": 0.0,
                    "is_loop": True
                })
                break

            visited_urls.add(current_url)

            # Response latency tracking
            t_start = time.perf_counter()
            status_code = 0
            reason_msg = "Unknown"
            next_url = None
            is_downgrade_hop = False
            is_cross_domain_hop = False

            try:
                # Use HEAD first with verify=False for passive resilience
                res = self.session.head(
                    current_url,
                    allow_redirects=False,
                    timeout=self.timeout,
                    verify=False,
                    headers={"User-Agent": self.user_agent}
                )
                if res.status_code in (400, 403, 405, 501):
                    res = self.session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=self.timeout,
                        verify=False,
                        headers={"User-Agent": self.user_agent},
                        stream=True
                    )
                t_end = time.perf_counter()
                response_time_ms = round((t_end - t_start) * 1000, 1)
                status_code = res.status_code
                reason_msg = res.reason or f"Status {status_code}"
                next_url = res.headers.get("Location")
            except RequestException as err:
                t_end = time.perf_counter()
                response_time_ms = round((t_end - t_start) * 1000, 1)
                err_name = type(err).__name__
                reason_msg = f"Connection Error: {err_name}"
                if "NameResolutionError" in str(err) or "gaierror" in str(err) or "MaxRetryError" in str(err):
                    reason_msg = "Connection Error (Domain unresolved / offline)"

                chain.append({
                    "hop": hop,
                    "url": current_url,
                    "domain": curr_domain,
                    "status_code": 0,
                    "reason": reason_msg,
                    "location_header": None,
                    "next_url": None,
                    "is_cross_domain": False,
                    "is_https_downgrade": False,
                    "response_time_ms": response_time_ms,
                    "is_loop": False
                })
                break

            if next_url:
                next_url = urllib.parse.urljoin(current_url, next_url)

            # Check if this hop redirects
            if 300 <= status_code < 400 and next_url:
                parsed_next = urllib.parse.urlsplit(next_url)
                next_scheme = parsed_next.scheme.lower()
                next_domain = parsed_next.netloc.split(":")[0].lower() if parsed_next.netloc else ""

                # Flag downgrade from HTTPS to HTTP
                if current_url.lower().startswith("https://") and next_scheme == "http":
                    is_downgraded = True
                    is_downgrade_hop = True

                # Flag upgrade from HTTP to HTTPS
                if current_url.lower().startswith("http://") and next_scheme == "https":
                    is_upgraded = True

                # Flag cross-domain redirect
                if initial_domain and next_domain and initial_domain != next_domain:
                    if not next_domain.endswith(f".{initial_domain}"):
                        is_cross_domain = True
                        is_cross_domain_hop = True

                chain.append({
                    "hop": hop,
                    "url": current_url,
                    "domain": curr_domain,
                    "status_code": status_code,
                    "reason": reason_msg,
                    "location_header": next_url,
                    "next_url": next_url,
                    "is_cross_domain": is_cross_domain_hop,
                    "is_https_downgrade": is_downgrade_hop,
                    "response_time_ms": response_time_ms,
                    "is_loop": False
                })

                current_url = next_url
            else:
                chain.append({
                    "hop": hop,
                    "url": current_url,
                    "domain": curr_domain,
                    "status_code": status_code,
                    "reason": reason_msg,
                    "location_header": None,
                    "next_url": None,
                    "is_cross_domain": False,
                    "is_https_downgrade": False,
                    "response_time_ms": response_time_ms,
                    "is_loop": False
                })
                break

        # Ensure overall upgrade is detected if final destination is HTTPS
        if start_url.lower().startswith("http://") and current_url.lower().startswith("https://"):
            is_upgraded = True

        return {
            "initial_url": start_url,
            "final_url": current_url,
            "hop_count": len(chain),
            "is_downgraded": is_downgraded,
            "is_upgraded": is_upgraded,
            "is_cross_domain": is_cross_domain,
            "has_loop": has_loop,
            "chain": chain,
            "redirect_chain": chain
        }
