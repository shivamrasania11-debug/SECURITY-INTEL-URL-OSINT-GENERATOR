"""
Unit tests for domain and URL normalization and validation utilities.
"""

import sys
import os
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils import normalize_domain, is_valid_domain, is_valid_url, build_search_url


def test_normalize_domain_strips_protocols():
    assert normalize_domain("https://example.com") == "example.com"
    assert normalize_domain("http://example.com") == "example.com"
    assert normalize_domain("ftp://example.com") == "example.com"


def test_normalize_domain_strips_www():
    assert normalize_domain("www.example.com") == "example.com"
    assert normalize_domain("https://www.example.com") == "example.com"


def test_normalize_domain_strips_paths_and_queries():
    assert normalize_domain("https://example.com/login?token=123#sec") == "example.com"
    assert normalize_domain("example.com/admin/") == "example.com"


def test_normalize_domain_strips_ports_and_userinfo():
    assert normalize_domain("https://user:pass@example.com:8080/path") == "example.com"
    assert normalize_domain("example.com:8443") == "example.com"


def test_is_valid_domain():
    assert is_valid_domain("example.com") is True
    assert is_valid_domain("sub.test.co.uk") is True
    assert is_valid_domain("my-domain-123.org") is True
    assert is_valid_domain("192.168.1.1") is True

    # Invalid domains
    assert is_valid_domain("") is False
    assert is_valid_domain("invalid_domain") is False
    assert is_valid_domain("example") is False
    assert is_valid_domain("http://") is False


def test_is_valid_url():
    assert is_valid_url("https://example.com") is True
    assert is_valid_url("http://example.com/test?a=1") is True
    assert is_valid_url("https://192.168.1.1:8080") is True

    # Invalid URLs
    assert is_valid_url("example.com") is False
    assert is_valid_url("ftp://example.com") is False
    assert is_valid_url("") is False


def test_build_search_url():
    google_url = build_search_url("site:example.com filetype:pdf", "google")
    assert "google.com/search?q=" in google_url
    assert "site%3Aexample.com" in google_url

    bing_url = build_search_url("site:example.com", "bing")
    assert "bing.com/search?q=" in bing_url

    ddg_url = build_search_url("site:example.com", "duckduckgo")
    assert "duckduckgo.com/?q=" in ddg_url

