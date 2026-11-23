"""
Unit tests for OSINT Query Generator (dork_generator.py).
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dork_generator import DorkGenerator
from config import DORK_CATEGORIES


def test_dork_generator_initialization():
    gen = DorkGenerator()
    assert gen.default_engine == "google"


def test_generate_all_categories_returns_expected_structure():
    gen = DorkGenerator()
    result = gen.generate_all_categories("target.org")

    assert result["domain"] == "target.org"
    assert result["engine"] == "google"
    assert result["total_queries"] >= 50
    assert len(result["categories"]) == len(DORK_CATEGORIES)

    # Check each category has required fields
    for cat_id, cat_data in result["categories"].items():
        assert "name" in cat_data
        assert "description" in cat_data
        assert "icon" in cat_data
        assert "queries" in cat_data
        assert len(cat_data["queries"]) >= 5

        # Check query fields
        for q in cat_data["queries"]:
            assert "label" in q
            assert "query" in q
            assert "description" in q
            assert "search_url" in q
            assert "target.org" in q["query"] or "target" in q["query"]


def test_generate_selected_categories():
    gen = DorkGenerator()
    selected = ["general", "documents", "login_admin"]
    result = gen.generate_all_categories("example.com", selected_categories=selected)

    assert len(result["categories"]) == 3
    assert set(result["categories"].keys()) == set(selected)


def test_custom_search_engine_applied():
    gen = DorkGenerator()
    result = gen.generate_all_categories("example.com", engine="duckduckgo")
    assert result["engine"] == "duckduckgo"

    first_query = result["categories"]["general"]["queries"][0]
    assert "duckduckgo.com" in first_query["search_url"]


def test_invalid_domain_raises_value_error():
    gen = DorkGenerator()
    with pytest.raises(ValueError):
        gen.generate_all_categories("invalid_domain_without_extension")

