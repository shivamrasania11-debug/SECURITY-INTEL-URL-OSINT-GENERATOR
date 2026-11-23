"""
Security Analysis & URL Intelligence Generator - Main Flask Application (app.py)
Provides RESTful APIs for OSINT query generation, passive URL analysis, and export.
Automatically launches default browser on execution.
"""

import json
import logging
import os
import re
import smtplib
import sys
import threading
import time
import webbrowser
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Any, Optional

from flask import Flask, request, jsonify, render_template, make_response
from flask_cors import CORS

from config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DORK_CATEGORIES,
    SEARCH_ENGINES,
    PROJECT_INFO,
    RISK_THRESHOLDS,
    KOLKATA_TZ
)
from dork_generator import DorkGenerator
from url_analyzer import URLAnalyzer
from pattern_detector import SuspiciousPatternDetector
from pdf_reporter import generate_pdf_report, REPORTLAB_AVAILABLE
from utils import (
    is_valid_domain,
    is_valid_url,
    normalize_domain,
    format_txt_report,
    format_csv_report,
    format_json_report
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("security_url_intel")

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Engine instances
dork_engine = DorkGenerator()
analyzer_engine = URLAnalyzer()
pattern_engine = SuspiciousPatternDetector()

# Contacts storage path
CONTACTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "contacts.json")

# Disable static caching in browser
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response


@app.route("/")
def index():
    """Serves the single-page application interface."""
    return render_template(
        "index.html",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        categories=DORK_CATEGORIES,
        engines=SEARCH_ENGINES,
        project_info=PROJECT_INFO,
        risk_thresholds=RISK_THRESHOLDS
    )


@app.route("/api/health", methods=["GET"])
def health():
    """Returns application health and operational status."""
    return jsonify({
        "success": True,
        "data": {
            "status": "healthy",
            "service": APP_NAME,
            "version": APP_VERSION,
            "timestamp": datetime.now(KOLKATA_TZ).isoformat()
        },
        "error": None
    })


@app.route("/api/dorks", methods=["POST"])
def generate_dorks():
    """
    POST /api/dorks
    Payload: { "domain": str, "categories": list[str], "engine": str, "authorized": bool }
    """
    data = request.get_json(silent=True) or {}

    # Authorization enforcement
    if not data.get("authorized"):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Access Denied: You must acknowledge that you are authorized to assess this target."
        }), 403

    domain_input = data.get("domain", "").strip()
    if not domain_input:
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: Domain field cannot be empty."
        }), 400

    normalized = normalize_domain(domain_input)
    if not is_valid_domain(normalized):
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Invalid domain format: '{domain_input}'. Please supply a standard domain name (e.g., example.com)."
        }), 400

    categories = data.get("categories")
    if categories and not isinstance(categories, list):
        categories = None

    engine = data.get("engine", "google")
    if engine not in SEARCH_ENGINES:
        engine = "google"

    try:
        logger.info("Generating OSINT queries for domain: %s (engine: %s)", normalized, engine)
        result = dork_engine.generate_all_categories(normalized, engine=engine, selected_categories=categories)



        return jsonify({
            "success": True,
            "data": result,
            "error": None
        })
    except Exception as e:
        logger.error("Dork generation failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Error generating queries: {str(e)}"
        }), 500


@app.route("/api/analyze", methods=["POST"])
def analyze_url():
    """
    POST /api/analyze
    Payload: { "url": str, "authorized": bool }
    """
    data = request.get_json(silent=True) or {}

    # Authorization enforcement
    if not data.get("authorized"):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Access Denied: You must acknowledge that you are authorized to assess this target."
        }), 403

    raw_url = data.get("url", "").strip()
    if not raw_url:
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: URL field cannot be empty."
        }), 400

    # Auto-prefix https if scheme omitted for validation
    check_url = raw_url if "://" in raw_url else f"https://{raw_url}"
    if not is_valid_url(check_url):
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Invalid URL format: '{raw_url}'. Please enter a valid URL."
        }), 400

    try:
        logger.info("Performing passive analysis on URL: %s", check_url)
        analysis_data = analyzer_engine.analyze(check_url)
        pattern_data = pattern_engine.evaluate(analysis_data)

        # Merge results into cohesive payload
        redirect_chain = analysis_data["redirects"].get("redirect_chain") or analysis_data["redirects"].get("chain", [])

        response_payload = {
            "url": analysis_data["url"],
            "structure": analysis_data["structure"],
            "domain_details": analysis_data["domain_details"],
            "redirects": analysis_data["redirects"],
            "redirect_chain": redirect_chain,
            "risk": {
                "score": pattern_data["score"],
                "safety_score": pattern_data.get("safety_score", max(0, 100 - pattern_data["score"])),
                "level": pattern_data["level"],
                "summary": pattern_data["summary"]
            },
            "flags": pattern_data["flags"],
            "flag_count": pattern_data["flag_count"],
            "analyzed_at": datetime.now(KOLKATA_TZ).isoformat()
        }

        return jsonify({
            "success": True,
            "data": response_payload,
            "error": None
        })
    except Exception as e:
        logger.error("URL Analysis failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "data": None,
            "error": f"Analysis encountered an error: {str(e)}"
        }), 500


@app.route("/api/export", methods=["POST"])
def export_report():
    """
    POST /api/export
    Payload: { "type": "txt"|"csv"|"json", "data": dict, "report_type": "analysis"|"dorks", "authorized": bool }
    """
    data = request.get_json(silent=True) or {}

    if not data.get("authorized"):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Access Denied: Authorization required."
        }), 403

    export_format = (data.get("type") or "txt").lower()
    report_data = data.get("data")
    report_type = data.get("report_type", "analysis")

    if not report_data or not isinstance(report_data, dict):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: No valid report data provided to export."
        }), 400

    timestamp = datetime.now(KOLKATA_TZ).strftime("%Y%m%d_%H%M%S")

    if export_format == "json":
        content = format_json_report(report_data)
        filename = f"security_intel_{report_type}_{timestamp}.json"
        mimetype = "application/json"
    elif export_format == "csv":
        content = format_csv_report(report_data, report_type=report_type)
        filename = f"security_intel_{report_type}_{timestamp}.csv"
        mimetype = "text/csv"
    else:  # default to txt
        content = format_txt_report(report_data, report_type=report_type)
        filename = f"security_intel_{report_type}_{timestamp}.txt"
        mimetype = "text/plain"

    response = make_response(content)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Content-Type"] = f"{mimetype}; charset=utf-8"
    return response


# ==============================================================================
# FEATURE 4: PDF Report Export Endpoint
# ==============================================================================
@app.route("/api/report/pdf", methods=["POST"])
def export_pdf_report():
    """
    POST /api/report/pdf
    Payload: { "data": dict, "report_title": str, "prepared_by": str, "authorized": bool }
    Compiles a comprehensive PDF report using ReportLab.
    """
    data = request.get_json(silent=True) or {}

    if not data.get("authorized"):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Access Denied: Authorization required."
        }), 403

    if not REPORTLAB_AVAILABLE:
        return jsonify({
            "success": False,
            "data": None,
            "error": "ReportLab library is not installed on this system. Run 'pip install reportlab' to enable PDF exports."
        }), 501

    report_data = data.get("data")
    if not report_data or not isinstance(report_data, dict):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: No valid analysis data provided for PDF generation."
        }), 400

    report_title = data.get("report_title", "URL Security & Threat Assessment Report").strip() or "URL Security Assessment Report"
    prepared_by = data.get("prepared_by", "Cybersecurity Analyst").strip() or "Cybersecurity Analyst"
    dorks_data = data.get("dorks_data") or data.get("dorks")

    try:
        timestamp = datetime.now(KOLKATA_TZ).strftime("%Y%m%d_%H%M%S")
        pdf_buffer = generate_pdf_report(
            analysis_data=report_data,
            report_title=report_title,
            prepared_by=prepared_by,
            dorks_data=dorks_data
        )

        filename = f"security_assessment_report_{timestamp}.pdf"
        response = make_response(pdf_buffer.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        logger.error("PDF generation failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "data": None,
            "error": f"PDF report generation failed: {str(e)}"
        }), 500


# ==============================================================================
# FEATURE 6: Help & Contact Endpoint
# ==============================================================================
# Simple in-memory contact submission rate limiter: {ip: [timestamps]}
_CONTACT_RATE_LIMIT: Dict[str, List[float]] = {}


@app.route("/api/contact", methods=["POST"])
def submit_contact():
    """
    POST /api/contact
    Payload: { "name": str, "email": str, "subject": str, "message": str, "honeypot": str }
    Validates submission, protects with honeypot & rate limiter, and saves to contacts.json.
    """
    data = request.get_json(silent=True) or {}
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()

    # Rate limit: Max 5 contact submissions per 10 minutes per IP
    now = time.time()
    recent = [t for t in _CONTACT_RATE_LIMIT.get(client_ip, []) if now - t < 600]
    if len(recent) >= 5:
        return jsonify({
            "success": False,
            "data": None,
            "error": "Rate Limit Exceeded: Too many message submissions. Please wait a few minutes."
        }), 429
    recent.append(now)
    _CONTACT_RATE_LIMIT[client_ip] = recent

    # Honeypot check: If honeypot is filled, discard silently
    if data.get("honeypot"):
        logger.info("Spam bot trapped by honeypot field from IP %s", client_ip)
        return jsonify({
            "success": True,
            "data": {"message": "Thank you! Your inquiry has been received."},
            "error": None
        })

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    subject = (data.get("subject") or "").strip()
    message = (data.get("message") or "").strip()

    # Server-side validation
    if not (2 <= len(name) <= 100):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: Name must be between 2 and 100 characters."
        }), 400

    email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(email_regex, email) or len(email) > 120:
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: Please provide a valid email address."
        }), 400

    if not (2 <= len(subject) <= 150):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: Subject must be between 2 and 150 characters."
        }), 400

    if not (10 <= len(message) <= 2000):
        return jsonify({
            "success": False,
            "data": None,
            "error": "Validation Error: Message must be between 10 and 2000 characters."
        }), 400

    submission = {
        "timestamp": datetime.now(KOLKATA_TZ).isoformat(),
        "name": name,
        "email": email,
        "subject": subject,
        "message": message,
        "ip": client_ip
    }

    # Save to contacts.json file
    try:
        contacts_list = []
        if os.path.exists(CONTACTS_FILE):
            try:
                with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
                    contacts_list = json.load(f)
                    if not isinstance(contacts_list, list):
                        contacts_list = []
            except Exception:
                contacts_list = []

        contacts_list.append(submission)
        with open(CONTACTS_FILE, "w", encoding="utf-8") as f:
            json.dump(contacts_list, f, indent=2, ensure_ascii=False)
        logger.info("New contact submission saved for %s <%s>", name, email)
    except Exception as e:
        logger.error("Failed writing to contacts.json: %s", str(e))
        # Do not expose disk error to client

    # Optional SMTP dispatch if configured
    smtp_host = os.environ.get("SMTP_HOST")
    if smtp_host:
        try:
            smtp_port = int(os.environ.get("SMTP_PORT", 587))
            smtp_user = os.environ.get("SMTP_USER", "")
            smtp_pass = os.environ.get("SMTP_PASS", "")
            contact_receiver = os.environ.get("CONTACT_RECEIVER", smtp_user)

            msg = MIMEMultipart()
            msg["From"] = smtp_user or "noreply@security-intel.local"
            msg["To"] = contact_receiver
            msg["Subject"] = f"[Security Intel Contact] {subject} (from {name})"
            body_text = f"New inquiry from {name} <{email}>:\n\n{message}\n\nTimestamp: {submission['timestamp']}\nIP: {client_ip}"
            msg.attach(MIMEText(body_text, "plain"))

            with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as server:
                server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            logger.info("SMTP contact email sent successfully.")
        except Exception as smtp_err:
            logger.warning("SMTP email dispatch skipped/failed: %s", str(smtp_err))

    return jsonify({
        "success": True,
        "data": {
            "message": "Thank you for reaching out! Your message has been safely received by our cybersecurity lab."
        },
        "error": None
    })


# Global error handlers
@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"success": False, "data": None, "error": "Bad Request"}), 400


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"success": False, "data": None, "error": "Resource Not Found"}), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({"success": False, "data": None, "error": "Method Not Allowed"}), 405


@app.errorhandler(500)
def handle_server_error(e):
    return jsonify({"success": False, "data": None, "error": "Internal Server Error"}), 500


def open_browser():
    """Background helper to launch browser after short start-up delay."""
    time.sleep(1.2)
    url = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
    logger.info("Opening web browser at %s", url)
    try:
        webbrowser.open(url)
    except Exception as e:
        logger.warning("Could not launch browser automatically: %s", str(e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    host = os.environ.get("HOST", DEFAULT_HOST)

    print("\n" + "=" * 70)
    print(f"  {APP_NAME} v{APP_VERSION}")
    print(f"  Running on: http://{host}:{port}")
    print("  Mode: Authorized Cybersecurity Research & URL Intelligence")
    print("=" * 70 + "\n")

    # Launch browser in a background daemon thread
    if not os.environ.get("WERKZEUG_RUN_MAIN"):  # Avoid duplicate browser tab in Flask reload
        threading.Thread(target=open_browser, daemon=True).start()

    app.run(host=host, port=port, debug=False)

