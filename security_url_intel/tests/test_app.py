"""
Integration tests for Flask application routes (app.py).
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["status"] == "healthy"


def test_dorks_authorization_required(client):
    # Without authorized: true
    res = client.post("/api/dorks", json={"domain": "example.com"})
    assert res.status_code == 403
    data = res.get_json()
    assert data["success"] is False
    assert "Access Denied" in data["error"]


def test_dorks_generation_success(client):
    res = client.post("/api/dorks", json={
        "domain": "example.com",
        "engine": "google",
        "authorized": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["domain"] == "example.com"
    assert data["data"]["total_queries"] > 0


def test_dorks_invalid_domain(client):
    res = client.post("/api/dorks", json={
        "domain": "invalid_domain_string",
        "authorized": True
    })
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False


def test_analyze_authorization_required(client):
    res = client.post("/api/analyze", json={"url": "https://example.com"})
    assert res.status_code == 403


def test_analyze_invalid_url(client):
    res = client.post("/api/analyze", json={"url": "ftp://bad-scheme", "authorized": True})
    assert res.status_code == 400


def test_export_txt_and_json(client):
    # Test JSON export
    sample_data = {"test_metric": 123, "domain": "example.com"}
    res = client.post("/api/export", json={
        "type": "json",
        "report_type": "dorks",
        "data": sample_data,
        "authorized": True
    })
    assert res.status_code == 200
    assert "application/json" in res.headers["Content-Type"]

    # Test TXT export
    res_txt = client.post("/api/export", json={
        "type": "txt",
        "report_type": "dorks",
        "data": {
            "domain": "example.com",
            "categories": {"general": [{"label": "Test", "query": "site:example.com"}]}
        },
        "authorized": True
    })
    assert res_txt.status_code == 200
    assert "text/plain" in res_txt.headers["Content-Type"]
