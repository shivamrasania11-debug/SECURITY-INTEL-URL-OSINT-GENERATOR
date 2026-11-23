"""
Unit tests for Suspicious Pattern Detector (pattern_detector.py).
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pattern_detector import SuspiciousPatternDetector
from url_analyzer import URLAnalyzer


def test_benign_normal_url():
    detector = SuspiciousPatternDetector()
    analyzer = URLAnalyzer()

    data = {
        "url": "https://www.google.com/search?q=cybersecurity",
        "structure": analyzer.parse_structure("https://www.google.com/search?q=cybersecurity"),
        "domain_details": {"ssl": {"enabled": True, "is_expired": False, "is_self_signed": False}},
        "redirects": {"is_downgraded": False, "is_cross_domain": False}
    }

    result = detector.evaluate(data)
    assert result["level"] == "Low"
    assert result["score"] < 30


def test_ip_address_heuristic():
    detector = SuspiciousPatternDetector()
    analyzer = URLAnalyzer()

    data = {
        "url": "http://192.168.1.10/admin",
        "structure": analyzer.parse_structure("http://192.168.1.10/admin"),
        "domain_details": {"ssl": {"enabled": False}},
        "redirects": {"is_downgraded": False, "is_cross_domain": False}
    }

    result = detector.evaluate(data)
    rule_ids = [f["rule_id"] for f in result["flags"]]
    assert "IP_AS_DOMAIN" in rule_ids
    assert "NON_HTTPS_SCHEME" in rule_ids
    assert result["score"] >= 30


def test_userinfo_at_symbol_heuristic():
    detector = SuspiciousPatternDetector()
    analyzer = URLAnalyzer()

    data = {
        "url": "https://google.com@attacker-site.com/login",
        "structure": analyzer.parse_structure("https://google.com@attacker-site.com/login"),
        "domain_details": {"ssl": {"enabled": True}},
        "redirects": {"is_downgraded": False, "is_cross_domain": False}
    }

    result = detector.evaluate(data)
    rule_ids = [f["rule_id"] for f in result["flags"]]
    assert "USERINFO_AT_SYMBOL" in rule_ids
    assert any(f["severity"] == "critical" for f in result["flags"])


def test_punycode_homograph_heuristic():
    detector = SuspiciousPatternDetector()
    analyzer = URLAnalyzer()

    data = {
        "url": "https://xn--pple-43d.com/support",
        "structure": analyzer.parse_structure("https://xn--pple-43d.com/support"),
        "domain_details": {"ssl": {"enabled": True}},
        "redirects": {"is_downgraded": False, "is_cross_domain": False}
    }

    result = detector.evaluate(data)
    rule_ids = [f["rule_id"] for f in result["flags"]]
    assert "PUNYCODE_HOMOGRAPH" in rule_ids


def test_brand_spoofing_heuristic():
    detector = SuspiciousPatternDetector()
    analyzer = URLAnalyzer()

    data = {
        "url": "https://paypal.com.verification-center.xyz/account/login",
        "structure": analyzer.parse_structure("https://paypal.com.verification-center.xyz/account/login"),
        "domain_details": {"ssl": {"enabled": True}},
        "redirects": {"is_downgraded": False, "is_cross_domain": False}
    }

    result = detector.evaluate(data)
    rule_ids = [f["rule_id"] for f in result["flags"]]
    assert "BRAND_SPOOFING" in rule_ids
    assert "SUSPICIOUS_TLD" in rule_ids
    assert result["level"] == "High"
    assert result["score"] >= 70


def test_url_shortener_heuristic():
    detector = SuspiciousPatternDetector()
    analyzer = URLAnalyzer()

    data = {
        "url": "https://bit.ly/3xSample",
        "structure": analyzer.parse_structure("https://bit.ly/3xSample"),
        "domain_details": {"ssl": {"enabled": True}},
        "redirects": {"is_downgraded": False, "is_cross_domain": False}
    }

    result = detector.evaluate(data)
    rule_ids = [f["rule_id"] for f in result["flags"]]
    assert "URL_SHORTENER" in rule_ids

