"""
OSINT Query Generator (dork_generator.py)
Generates customized search queries using Google search operators
(site:, inurl:, intitle:, intext:, filetype:, ext:, related:, -exclusion, OR, quotes)
across 9 defensive intelligence categories.
"""

from typing import Dict, List, Any, Optional
from utils import normalize_domain, is_valid_domain, build_search_url
from config import DORK_CATEGORIES


class DorkGenerator:
    """
    Constructs targeted OSINT queries across specialized categories for a validated domain.
    """

    def __init__(self, default_engine: str = "google"):
        self.default_engine = default_engine.lower()

    def generate_all_categories(self, target_input: str, engine: Optional[str] = None, selected_categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Validates target domain and generates dork queries for all or selected categories.
        """
        domain = normalize_domain(target_input)
        if not is_valid_domain(domain):
            raise ValueError(f"Invalid domain provided: '{target_input}'. Please supply a valid domain (e.g., example.com).")

        active_engine = (engine or self.default_engine).lower()
        if not selected_categories:
            selected_categories = list(DORK_CATEGORIES.keys())

        results = {}
        total_queries = 0

        # Mapping generator methods
        generators = {
            "general": self._generate_general,
            "documents": self._generate_documents,
            "login_admin": self._generate_login_admin,
            "directory_listings": self._generate_directory_listings,
            "config_backups": self._generate_config_backups,
            "subdomains": self._generate_subdomains,
            "sensitive_keywords": self._generate_sensitive_keywords,
            "technology_errors": self._generate_technology_errors,
            "public_mentions": self._generate_public_mentions
        }

        for cat_id in selected_categories:
            if cat_id in generators:
                queries = generators[cat_id](domain, active_engine)
                results[cat_id] = {
                    "category_id": cat_id,
                    "name": DORK_CATEGORIES[cat_id]["name"],
                    "description": DORK_CATEGORIES[cat_id]["description"],
                    "icon": DORK_CATEGORIES[cat_id]["icon"],
                    "count": len(queries),
                    "queries": queries
                }
                total_queries += len(queries)

        return {
            "domain": domain,
            "engine": active_engine,
            "total_queries": total_queries,
            "categories": results
        }

    # 1. General Information
    def _generate_general(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "All Indexed Domain Pages",
                "query": f"site:{domain}",
                "description": "Enumerates all search engine indexed pages for the primary domain."
            },
            {
                "label": "Related Competitor / Affiliated Sites",
                "query": f"related:{domain}",
                "description": "Finds domains categorized as similar or associated by the search engine."
            },
            {
                "label": "Domain Name in Page Titles",
                "query": f"site:{domain} intitle:\"{domain.split('.')[0]}\"",
                "description": "Searches for primary brand name in HTML title tags."
            },
            {
                "label": "Copyright & Corporate Notices",
                "query": f"site:{domain} (intext:\"all rights reserved\" OR intext:\"copyright\")",
                "description": "Discovers legal, copyright, and organization ownership statements."
            },
            {
                "label": "About, Contact & Leadership Pages",
                "query": f"site:{domain} (inurl:about OR inurl:contact OR inurl:team OR inurl:careers)",
                "description": "Locates public organizational structure and personnel contact points."
            },
            {
                "label": "Robots.txt & Sitemap Directives",
                "query": f"site:{domain} (inurl:robots.txt OR inurl:sitemap.xml)",
                "description": "Finds indexed crawl policy files and canonical XML sitemaps."
            },
            {
                "label": "Privacy Policies & Terms of Service",
                "query": f"site:{domain} (inurl:privacy OR inurl:terms OR inurl:tos OR inurl:disclaimer)",
                "description": "Discovers data handling policies and terms of service documentation."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 2. Exposed Documents
    def _generate_documents(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "Indexed PDF Documents",
                "query": f"site:{domain} filetype:pdf",
                "description": "Identifies public PDF files such as reports, user manuals, and invoices."
            },
            {
                "label": "Word Processing Documents (DOC / DOCX)",
                "query": f"site:{domain} (filetype:doc OR filetype:docx)",
                "description": "Discovers Microsoft Word files which may contain metadata or revisions."
            },
            {
                "label": "Spreadsheets & Tabular Data (XLS / XLSX)",
                "query": f"site:{domain} (filetype:xls OR filetype:xlsx)",
                "description": "Finds Excel spreadsheets which may disclose financial or client lists."
            },
            {
                "label": "Presentation Slides (PPT / PPTX)",
                "query": f"site:{domain} (filetype:ppt OR filetype:pptx)",
                "description": "Discovers presentation decks with internal roadmaps or company architecture."
            },
            {
                "label": "CSV & Raw Data Exports",
                "query": f"site:{domain} (filetype:csv OR filetype:tsv)",
                "description": "Searches for comma-separated data dumps and raw database exports."
            },
            {
                "label": "Plain Text Notes & Readme Files",
                "query": f"site:{domain} (filetype:txt OR filetype:rtf OR inurl:readme)",
                "description": "Identifies text files that might hold server release notes or credentials."
            },
            {
                "label": "OpenDocument Formats (ODT / ODS)",
                "query": f"site:{domain} (filetype:odt OR filetype:ods OR filetype:odp)",
                "description": "Finds LibreOffice and OpenDocument files on the target domain."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 3. Login & Admin Pages
    def _generate_login_admin(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "Administrative Portals & Control Panels",
                "query": f"site:{domain} (inurl:admin OR inurl:administrator OR inurl:adminportal)",
                "description": "Locates admin dashboards, management consoles, and back-office portals."
            },
            {
                "label": "Authentication & Sign-In Endpoints",
                "query": f"site:{domain} (inurl:login OR inurl:signin OR inurl:auth)",
                "description": "Finds user authentication and single sign-on ingress points."
            },
            {
                "label": "Login Title Tags",
                "query": f"site:{domain} (intitle:\"admin login\" OR intitle:\"control panel\" OR intitle:\"dashboard login\")",
                "description": "Pinpoints pages explicitly bearing administrative titles in page headings."
            },
            {
                "label": "Hosting & Web Panels (cPanel / Webmin)",
                "query": f"site:{domain} (inurl:cpanel OR inurl:webmin OR inurl:kibana OR inurl:grafana)",
                "description": "Discovers exposed server infrastructure and monitoring dashboards."
            },
            {
                "label": "Registration & Password Recovery",
                "query": f"site:{domain} (inurl:register OR inurl:signup OR inurl:forgot-password OR inurl:reset-password)",
                "description": "Identifies account creation and password recovery flows."
            },
            {
                "label": "OAuth / SSO Endpoints",
                "query": f"site:{domain} (inurl:oauth OR inurl:sso OR inurl:saml OR inurl:auth/realms)",
                "description": "Discovers federated identity and OAuth authorization endpoints."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 4. Directory Listings
    def _generate_directory_listings(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "Apache / Nginx Directory Indexes",
                "query": f"site:{domain} intitle:\"index of /\"",
                "description": "Discovers web server directories with automatic indexing enabled."
            },
            {
                "label": "Parent Directory Link References",
                "query": f"site:{domain} intitle:\"index of\" \"parent directory\"",
                "description": "Finds open folder trees allowing hierarchical file browsing."
            },
            {
                "label": "Uploads & User Asset Folders",
                "query": f"site:{domain} intitle:\"index of\" (inurl:uploads OR inurl:assets OR inurl:files)",
                "description": "Detects unindexed or exposed user upload folders."
            },
            {
                "label": "Backup & Database Directories",
                "query": f"site:{domain} intitle:\"index of\" (inurl:backup OR inurl:backups OR inurl:data OR inurl:db)",
                "description": "Searches for open directories labeled as backup storage."
            },
            {
                "label": "Server Software Fingerprint in Index",
                "query": f"site:{domain} intitle:\"index of /\" \"server at\"",
                "description": "Finds directory listings disclosing exact web server software and port."
            },
            {
                "label": "Exposed Shared Drives & Mirrors",
                "query": f"site:{domain} intitle:\"index of\" (inurl:shared OR inurl:mirror OR inurl:pub)",
                "description": "Discovers public file mirrors or shared document drops."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 5. Configuration & Backup Files
    def _generate_config_backups(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "Environment & Setting Files (.env / .ini / .cfg)",
                "query": f"site:{domain} (ext:env OR ext:cfg OR ext:ini OR ext:conf OR ext:config)",
                "description": "Identifies environment variables and configuration files that may leak secrets."
            },
            {
                "label": "Database Dumps & SQL Scripts",
                "query": f"site:{domain} (ext:sql OR ext:db OR ext:sqlite OR ext:dump)",
                "description": "Searches for indexed database tables and exported SQL dumps."
            },
            {
                "label": "Backup File Extensions (.bak / .old / .backup)",
                "query": f"site:{domain} (ext:bak OR ext:old OR ext:backup OR ext:orig OR ext:tmp)",
                "description": "Discovers leftover backup copies of source scripts and server files."
            },
            {
                "label": "Compressed Archives (ZIP / TAR / GZ)",
                "query": f"site:{domain} (ext:zip OR ext:tar OR ext:gz OR ext:rar OR ext:7z)",
                "description": "Finds packaged code releases, site snapshots, or downloaded assets."
            },
            {
                "label": "Server Log Files (.log / .out)",
                "query": f"site:{domain} (ext:log OR ext:out OR inurl:log)",
                "description": "Locates application error logs, access logs, or debug traces."
            },
            {
                "label": "Version Control Artifacts (.git / .svn / .env)",
                "query": f"site:{domain} (inurl:\".git\" OR inurl:\".gitignore\" OR inurl:\".gitlab-ci.yml\" OR inurl:\".env\")",
                "description": "Detects exposed repository meta directories and build scripts."
            },
            {
                "label": "JSON / YAML Configuration Files",
                "query": f"site:{domain} (ext:json OR ext:yaml OR ext:yml) (inurl:config OR inurl:settings)",
                "description": "Discovers configuration files containing operational parameters."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 6. Subdomain Discovery
    def _generate_subdomains(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "Wildcard Subdomain Sweep (Exclude www)",
                "query": f"site:*.{domain} -www",
                "description": "Finds indexed subdomains outside the primary www hostname."
            },
            {
                "label": "Developer, Staging & Test Environments",
                "query": f"site:*.{domain} (inurl:dev OR inurl:staging OR inurl:test OR inurl:sandbox) -www",
                "description": "Discovers non-production environments that may have relaxed security."
            },
            {
                "label": "API, Webhook & Microservices",
                "query": f"site:*.{domain} (inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql OR inurl:rest) -www",
                "description": "Finds API gateways, documentation endpoints, and backend connectors."
            },
            {
                "label": "Mail, VPN & Remote Ingress",
                "query": f"site:*.{domain} (inurl:mail OR inurl:webmail OR inurl:vpn OR inurl:remote) -www",
                "description": "Identifies mail servers and perimeter enterprise gateways."
            },
            {
                "label": "Cloud & Storage Endpoints (S3 / CDN)",
                "query": f"site:*.{domain} (inurl:s3 OR inurl:cdn OR inurl:storage OR inurl:static) -www",
                "description": "Locates cloud-hosted object storage buckets and content delivery nodes."
            },
            {
                "label": "Internal & Staff Portals",
                "query": f"site:*.{domain} (inurl:internal OR inurl:corp OR inurl:intranet OR inurl:staff) -www",
                "description": "Discovers private enterprise intranet portals."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 7. Sensitive Keywords
    def _generate_sensitive_keywords(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "Confidential & Proprietary Markings",
                "query": f"site:{domain} (intext:\"confidential\" OR intext:\"strictly private\" OR intext:\"proprietary\")",
                "description": "Searches for indexed pages tagged with organizational secrecy warnings."
            },
            {
                "label": "Internal Use Only Notices",
                "query": f"site:{domain} (intext:\"internal use only\" OR intext:\"not for distribution\" OR intext:\"do not distribute\")",
                "description": "Finds documents meant exclusively for internal employees."
            },
            {
                "label": "API Keys & Access Tokens",
                "query": f"site:{domain} (intext:\"api_key\" OR intext:\"client_secret\" OR intext:\"bearer token\")",
                "description": "Discovers accidentally committed credentials or documentation examples."
            },
            {
                "label": "Credentials & Password Phrases",
                "query": f"site:{domain} (intext:\"password\" OR intext:\"default password\" OR intext:\"root password\")",
                "description": "Locates mention of passwords and default account credentials."
            },
            {
                "label": "Financial & Payroll References",
                "query": f"site:{domain} (intext:\"salary\" OR intext:\"payroll\" OR intext:\"invoice\" OR intext:\"budget 202\")",
                "description": "Discovers indexed spreadsheets or disclosures relating to financial figures."
            },
            {
                "label": "Security Incident & Vulnerability Reports",
                "query": f"site:{domain} (intext:\"vulnerability\" OR intext:\"incident report\" OR intext:\"CVE-\")",
                "description": "Finds internal security bulletins or vulnerability audit disclosures."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 8. Technology & Error Disclosure
    def _generate_technology_errors(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "SQL Syntax Errors & DB Leaks",
                "query": f"site:{domain} (intext:\"sql syntax near\" OR intext:\"unclosed quotation mark\" OR intext:\"ORA-01756\")",
                "description": "Locates database error strings disclosing query structures and database types."
            },
            {
                "label": "PHP & Web Framework Fatal Errors",
                "query": f"site:{domain} (intext:\"Fatal error:\" OR intext:\"Warning: require_once\" OR intext:\"Parse error:\")",
                "description": "Finds unhandled PHP errors showing local absolute file system paths."
            },
            {
                "label": "Application Stack Traces & Debug Dumps",
                "query": f"site:{domain} (intext:\"stack trace:\" OR intext:\"Traceback (most recent call last)\" OR intext:\"NullPointerException\")",
                "description": "Discovers Python, Java, or Node stack traces revealing source code flow."
            },
            {
                "label": "Web Server Software Signatures",
                "query": f"site:{domain} (intext:\"Apache/\" OR intext:\"nginx/\" OR intext:\"Microsoft-IIS/\")",
                "description": "Searches for default server error pages exposing software version numbers."
            },
            {
                "label": "ASP.NET / Framework Runtime Exceptions",
                "query": f"site:{domain} (intext:\"Server Error in '/' Application\" OR intext:\"Runtime Error\")",
                "description": "Finds Microsoft ASP.NET 'Yellow Screen of Death' debugging pages."
            },
            {
                "label": "WordPress / CMS Debug Notices",
                "query": f"site:{domain} (intext:\"wp-config.php\" OR intext:\"wp-content/debug.log\")",
                "description": "Detects WordPress debug logs or references to key CMS configuration."
            }
        ]
        return self._attach_search_urls(queries, engine)

    # 9. Public Mentions
    def _generate_public_mentions(self, domain: str, engine: str) -> List[Dict[str, str]]:
        queries = [
            {
                "label": "Pastebin & Dump Sites",
                "query": f"site:pastebin.com \"{domain}\"",
                "description": "Identifies public code, password, and credential pastes referencing the domain."
            },
            {
                "label": "GitHub Repositories & Gists",
                "query": f"site:github.com \"{domain}\"",
                "description": "Discovers developer commits, public gists, and source code mentioning the target."
            },
            {
                "label": "GitLab & Bitbucket Projects",
                "query": f"(site:gitlab.com OR site:bitbucket.org) \"{domain}\"",
                "description": "Finds mentions in alternative public git repositories and tickets."
            },
            {
                "label": "Bug Bounty & Security Disclosures",
                "query": f"(site:hackerone.com OR site:bugcrowd.com) \"{domain}\"",
                "description": "Locates public bug bounty programs and resolved vulnerability reports."
            },
            {
                "label": "Community Discussions (Reddit / StackOverflow)",
                "query": f"(site:reddit.com OR site:stackoverflow.com) \"{domain}\"",
                "description": "Searches forum discussions, technical questions, and user discussions."
            },
            {
                "label": "Trello Boards & Public Workspaces",
                "query": f"(site:trello.com OR site:notion.site) \"{domain}\"",
                "description": "Discovers publicly shared task boards, roadmap cards, or customer lists."
            }
        ]
        return self._attach_search_urls(queries, engine)

    def _attach_search_urls(self, queries: List[Dict[str, str]], engine: str) -> List[Dict[str, str]]:
        """
        Attaches the pre-built direct search URL for each query item.
        """
        for item in queries:
            item["search_url"] = build_search_url(item["query"], engine)
        return queries

