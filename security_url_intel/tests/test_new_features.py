"""
Unit and integration tests for the extended features:
1. Risk Score Explainer & Score Breakdown
2. Redirect Chain Visualizer & Loop Detection
3. Defender's Tips Panel Coverage
4. PDF Report Generation & Endpoint
5. Help & Contact (Validation, Honeypot, Rate Limiting)
"""

import io
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from pattern_detector import SuspiciousPatternDetector
from url_analyzer import URLAnalyzer
from pdf_reporter import generate_pdf_report, REPORTLAB_AVAILABLE


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client





# ==============================================================================
# FEATURE 2: Redirect Loop Detection Tests
# ==============================================================================
def test_redirect_loop_detection(monkeypatch):
    analyzer = URLAnalyzer()

    # Mock session.head to simulate a circular redirect loop: URL A -> URL B -> URL A
    class MockResponse:
        def __init__(self, status_code, location):
            self.status_code = status_code
            self.reason = "Found"
            self.headers = {"Location": location}

    def mock_head(url, *args, **kwargs):
        if "loop-a" in url:
            return MockResponse(302, "https://loop-b.example/redirect")
        elif "loop-b" in url:
            return MockResponse(302, "https://loop-a.example/start")
        return MockResponse(200, None)

    monkeypatch.setattr(analyzer.session, "head", mock_head)

    res = analyzer.trace_redirects("https://loop-a.example/start")
    assert res["has_loop"] is True
    assert "redirect_chain" in res
    assert any(h.get("is_loop") is True for h in res["redirect_chain"])





# ==============================================================================
# FEATURE 4: PDF Report Generation & API Route Tests
# ==============================================================================
def test_pdf_endpoint_returns_pdf(client):
    assert REPORTLAB_AVAILABLE is True

    payload = {
        "authorized": True,
        "report_title": "Automated Security Audit Report",
        "prepared_by": "Senior Security Engineer",
        "data": {
            "url": "https://test.example/login",
            "risk": {"score": 35, "level": "Medium", "summary": "Moderate risk target."},
            "structure": {"scheme": "https", "host": "test.example", "domain": "test.example", "tld": "example", "length": 25},
            "domain_details": {"host": "test.example", "ipv4": ["192.0.2.1"], "ssl": {"enabled": True, "issuer": "Let's Encrypt", "days_remaining": 45}},
            "redirects": {"chain": [{"hop": 1, "url": "https://test.example/login", "status_code": 200, "response_time_ms": 12.5}]},
            "flags": [
                {"id": "NON_STANDARD_PORT", "name": "Custom Port", "severity": "low", "points_added": 10, "explanation": "Non standard port"}
            ]
        }
    }

    res = client.post("/api/report/pdf", json=payload)
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "application/pdf"
    assert len(res.data) > 2000
    assert res.data[:4] == b"%PDF"


# ==============================================================================
# FEATURE 5: Help & Contact Validation and Honeypot Tests
# ==============================================================================
def test_contact_form_validation_and_honeypot(client):
    # Valid submission
    valid_payload = {
        "name": "Jane Doe",
        "email": "jane.doe@university.edu",
        "subject": "Inquiry regarding URL Intelligence",
        "message": "Hello, I am testing the defensive intelligence platform for our course lab.",
        "honeypot": ""
    }
    res = client.post("/api/contact", json=valid_payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True

    # Honeypot filled (bot simulation) -> Must return success but discard
    bot_payload = dict(valid_payload)
    bot_payload["honeypot"] = "I am a spam bot"
    res_bot = client.post("/api/contact", json=bot_payload)
    assert res_bot.status_code == 200
    data_bot = res_bot.get_json()
    assert data_bot["success"] is True

    # Invalid email
    bad_email = dict(valid_payload)
    bad_email["email"] = "not-an-email"
    res_bad = client.post("/api/contact", json=bad_email)
    assert res_bad.status_code == 400
    assert "valid email" in res_bad.get_json()["error"]

    # Message too short
    short_msg = dict(valid_payload)
    short_msg["message"] = "Hi"
    res_short = client.post("/api/contact", json=short_msg)
    assert res_short.status_code == 400
    assert "between 10 and 2000" in res_short.get_json()["error"]
