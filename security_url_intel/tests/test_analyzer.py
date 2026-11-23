"""
Unit tests for URL Analyzer (url_analyzer.py).
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from url_analyzer import URLAnalyzer


def test_parse_structure_simple_url():
    analyzer = URLAnalyzer()
    struct = analyzer.parse_structure("https://example.com/test?param1=val1&param2=val2#section")

    assert struct["scheme"] == "https"
    assert struct["domain"] == "example.com"
    assert struct["subdomain"] == ""
    assert struct["tld"] == "com"
    assert struct["port"] == 443
    assert struct["path"] == "/test"
    assert struct["query_param_count"] == 2
    assert struct["fragment"] == "section"
    assert struct["is_standard_port"] is True


def test_parse_structure_subdomains_and_ports():
    analyzer = URLAnalyzer()
    struct = analyzer.parse_structure("http://api.dev.portal.example.co.uk:8080/v1/auth")

    assert struct["scheme"] == "http"
    assert struct["port"] == 8080
    assert struct["is_standard_port"] is False
    assert struct["domain"] == "example.co.uk"
    assert struct["subdomain"] == "api.dev.portal"
    assert struct["tld"] == "co.uk"


def test_parse_structure_ip_address():
    analyzer = URLAnalyzer()
    struct = analyzer.parse_structure("http://192.168.1.1:8888/login")

    assert struct["host"] == "192.168.1.1"
    assert struct["domain"] == "192.168.1.1"
    assert struct["port"] == 8888
    assert struct["is_standard_port"] is False


def test_split_domain_parts_multipart_tlds():
    analyzer = URLAnalyzer()
    sub, dom, tld = analyzer._split_domain_parts("admin.staging.site.com.au")
    assert sub == "admin.staging"
    assert dom == "site.com.au"
    assert tld == "com.au"


def test_analyze_empty_raises_value_error():
    analyzer = URLAnalyzer()
    with pytest.raises(ValueError):
        analyzer.analyze("")


def test_lookup_whois_ip_address():
    analyzer = URLAnalyzer()
    res = analyzer.lookup_whois("192.168.1.1")
    assert res["available"] is False
    assert "IP address" in res["note"]


def test_lookup_whois_valid_domain(monkeypatch):
    analyzer = URLAnalyzer()
    # Mock network call to guarantee deterministic offline unit test
    mock_whois = {
        "available": True,
        "registrar": "MarkMonitor, Inc.",
        "creation_date": "2007-10-09",
        "expiration_date": "2028-10-09",
        "age_days": 6000,
        "raw_status": "clientDeleteProhibited",
        "note": "RDAP registry live query"
    }
    monkeypatch.setattr(analyzer, "lookup_whois", lambda d: mock_whois)
    res = analyzer.lookup_whois("github.com")
    assert res["available"] is True
    assert res["registrar"] is not None
    assert res["age_days"] is not None
    assert res["age_days"] > 365

