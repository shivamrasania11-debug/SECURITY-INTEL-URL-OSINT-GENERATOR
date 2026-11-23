"""
PDF Report Generator (pdf_reporter.py)
Generates publication-grade, professionally styled cybersecurity assessment PDF reports
using ReportLab with custom color palettes, executive summaries, breakdown tables,
and defender checklists.
"""

import io
import hashlib
from datetime import datetime
from typing import Dict, Any, List

from config import KOLKATA_TZ

# Python 3.8 OpenSSL compatibility patch for ReportLab 4.x usedforsecurity kwarg
_orig_md5 = hashlib.md5
def _safe_md5(*args, **kwargs):
    kwargs.pop("usedforsecurity", None)
    return _orig_md5(*args, **kwargs)
hashlib.md5 = _safe_md5

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
        HRFlowable
    )
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes total page count dynamically
    and draws running headers and footers on each page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            super().showPage()
        super().save()

    def draw_footer(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running footer line
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, 36, letter[0] - 40, 36)

        # Footer text
        left_text = "Security Analysis & URL Intelligence Generator | For authorized cybersecurity research only."
        right_text = f"Page {self._pageNumber} of {total_pages}"

        self.drawString(40, 24, left_text)
        self.drawRightString(letter[0] - 40, 24, right_text)
        self.restoreState()


def generate_pdf_report(
    analysis_data: Dict[str, Any],
    report_title: str = "URL Security Assessment Report",
    prepared_by: str = "Security Analyst",
    dorks_data: Dict[str, Any] = None
) -> io.BytesIO:
    """
    Constructs a comprehensive PDF report from the analysis payload.
    Returns a BytesIO buffer containing the PDF bytes.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab library is not installed on this system.")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom Cyber/Executive Styles
    style_header_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a")
    )
    style_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0284c7")
    )
    style_meta = ParagraphStyle(
        "ReportMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#475569")
    )
    style_section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=4
    )
    style_body = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155")
    )
    style_body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#0f172a")
    )
    style_mono = ParagraphStyle(
        "ReportMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.8,
        leading=10,
        textColor=colors.HexColor("#0369a1")
    )
    style_table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    story = []

    # 1. Header Banner & Cover Metadata
    story.append(Paragraph("SECURITY ANALYSIS &amp; URL INTELLIGENCE", style_subtitle))
    story.append(Paragraph(report_title, style_header_title))
    story.append(Spacer(1, 4))

    now_str = datetime.now(KOLKATA_TZ).strftime("%Y-%m-%d %H:%M:%S IST (Kolkata)")
    target_url = analysis_data.get("url", "N/A")

    header_meta_data = [
        [
            Paragraph(f"<b>Target URL:</b> <font name='Courier'>{target_url}</font>", style_meta),
            Paragraph(f"<b>Date Generated:</b> {now_str}", style_meta)
        ],
        [
            Paragraph(f"<b>Prepared By:</b> {prepared_by}", style_meta),
            Paragraph("<b>Classification:</b> TLP:AMBER / Security Research", style_meta)
        ]
    ]
    t_header = Table(header_meta_data, colWidths=[330, 202])
    t_header.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 10))

    # 2. Executive Summary & Threat Score
    risk = analysis_data.get("risk", {})
    score = risk.get("score", 0)
    level = risk.get("level", "Low")
    safety = risk.get("safety_score", max(0, 100 - score))
    summary_text = risk.get("summary", "Analysis completed.")

    if level == "High":
        score_badge_bg = colors.HexColor("#e11d48")
    elif level == "Medium":
        score_badge_bg = colors.HexColor("#d97706")
    else:
        score_badge_bg = colors.HexColor("#059669")

    exec_summary_data = [
        [
            Paragraph(f"<font color='white'><b>RISK SCORE: {score}/100</b><br/>{level.upper()} THREAT LEVEL</font>", ParagraphStyle("ScoreBadge", parent=styles["Normal"], alignment=1, fontSize=11, leading=14)),
            Paragraph(f"<b>Executive Summary:</b><br/>{summary_text}<br/><font color='#64748b'><b>Safety Index:</b> {safety}% Safe | <b>Detected Threat Flags:</b> {len(analysis_data.get('flags', []))}</font>", style_body)
        ]
    ]
    t_exec = Table(exec_summary_data, colWidths=[150, 382])
    t_exec.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), score_badge_bg),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor("#f1f5f9")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
    ]))
    story.append(t_exec)
    story.append(Spacer(1, 12))

    # 3. URL Structure Breakdown
    story.append(Paragraph("1. RFC URL Architecture &amp; Component Breakdown", style_section_heading))
    struct = analysis_data.get("structure", {})
    struct_rows = [
        [Paragraph("Component", style_table_header), Paragraph("Extracted Value", style_table_header), Paragraph("Analysis Notes", style_table_header)],
        [Paragraph("Scheme (Protocol)", style_body_bold), Paragraph(str(struct.get("scheme", "-")), style_mono), Paragraph("Encrypted TLS" if struct.get("scheme") == "https" else "Unencrypted Cleartext", style_body)],
        [Paragraph("Host / Netloc", style_body_bold), Paragraph(str(struct.get("host", "-")), style_mono), Paragraph("Destination Network Identity", style_body)],
        [Paragraph("Subdomain", style_body_bold), Paragraph(str(struct.get("subdomain") or "(none)"), style_mono), Paragraph("Subdomain hierarchy levels", style_body)],
        [Paragraph("Registered Domain", style_body_bold), Paragraph(str(struct.get("domain", "-")), style_mono), Paragraph("Primary registered domain", style_body)],
        [Paragraph("Top-Level Domain", style_body_bold), Paragraph(f".{struct.get('tld')}" if struct.get("tld") else "(none)", style_mono), Paragraph("Registry suffix", style_body)],
        [Paragraph("Port", style_body_bold), Paragraph(str(struct.get("port", "-")), style_mono), Paragraph("Standard web port" if struct.get("is_standard_port") else "Non-standard port", style_body)],
        [Paragraph("Path", style_body_bold), Paragraph(str(struct.get("path", "/")), style_mono), Paragraph(f"{struct.get('path_length', 1)} chars", style_body)],
        [Paragraph("Query String", style_body_bold), Paragraph(str(struct.get("query_string") or "(empty)"), style_mono), Paragraph(f"{struct.get('query_param_count', 0)} parameters", style_body)],
        [Paragraph("Total URL Length", style_body_bold), Paragraph(f"{struct.get('length', 0)} characters", style_mono), Paragraph("Elevated length" if (struct.get("length", 0) > 75) else "Normal RFC length", style_body)]
    ]
    t_struct = Table(struct_rows, colWidths=[140, 230, 162])
    t_struct.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_struct)
    story.append(Spacer(1, 12))

    # 4. Domain & SSL/TLS Details
    story.append(Paragraph("2. Domain Intelligence &amp; SSL/TLS Verification", style_section_heading))
    domain_det = analysis_data.get("domain_details", {})
    ssl_info = domain_det.get("ssl", {})
    whois_info = domain_det.get("whois", {})

    ips = ", ".join(domain_det.get("ipv4", [])) or "None / Unresolved"
    domain_table_data = [
        [Paragraph("Target Hostname", style_body_bold), Paragraph(str(domain_det.get("host", "-")), style_mono), Paragraph("Resolved IPv4", style_body_bold), Paragraph(ips, style_mono)],
        [Paragraph("Reverse DNS (PTR)", style_body_bold), Paragraph(str(domain_det.get("reverse_dns") or "N/A"), style_mono), Paragraph("WHOIS Registrar", style_body_bold), Paragraph(str(whois_info.get("registrar") or "N/A"), style_body)],
        [Paragraph("SSL Issuer", style_body_bold), Paragraph(str(ssl_info.get("issuer") or "None / Inactive"), style_body), Paragraph("Certificate Validity", style_body_bold), Paragraph(f"{ssl_info.get('days_remaining', 'N/A')} days remaining", style_body)],
        [Paragraph("Subject CN", style_body_bold), Paragraph(str(ssl_info.get("subject") or "N/A"), style_mono), Paragraph("Self-Signed?", style_body_bold), Paragraph("Yes (Untrusted)" if ssl_info.get("is_self_signed") else "No (Trusted CA)", style_body)]
    ]
    t_domain = Table(domain_table_data, colWidths=[110, 156, 110, 156])
    t_domain.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ('BACKGROUND', (2, 0), (2, -1), colors.HexColor("#f1f5f9")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_domain)
    story.append(Spacer(1, 12))

    # 5. Redirect Chain Table
    story.append(Paragraph("3. Redirect Chain Sequence &amp; Protocol Transitions", style_section_heading))
    redirects = analysis_data.get("redirects", {})
    chain = analysis_data.get("redirect_chain") or redirects.get("chain", [])

    if chain:
        redir_rows = [
            [Paragraph("Hop", style_table_header), Paragraph("URL", style_table_header), Paragraph("Status", style_table_header), Paragraph("Latency", style_table_header), Paragraph("Observations", style_table_header)]
        ]
        for hop in chain:
            obs = []
            if hop.get("is_cross_domain"):
                obs.append("Cross-Domain Jump")
            if hop.get("is_https_downgrade"):
                obs.append("HTTPS->HTTP Downgrade")
            if hop.get("is_loop"):
                obs.append("LOOP DETECTED")
            obs_str = ", ".join(obs) if obs else "Normal transition"

            redir_rows.append([
                Paragraph(str(hop.get("hop", 1)), style_body_bold),
                Paragraph(str(hop.get("url", "-")), style_mono),
                Paragraph(str(hop.get("status_code", 0)), style_body_bold),
                Paragraph(f"{hop.get('response_time_ms', 0)} ms", style_body),
                Paragraph(obs_str, style_body)
            ])
        t_redir = Table(redir_rows, colWidths=[35, 260, 50, 60, 127])
        t_redir.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_redir)
    else:
        story.append(Paragraph("No redirect hops observed (Direct single-hop response).", style_body))

    story.append(Spacer(1, 12))

    # 6. Security Flags & Heuristic Explanations
    story.append(Paragraph("4. Triggered Threat Flags &amp; Heuristics", style_section_heading))
    flags = analysis_data.get("flags", [])
    if flags:
        flag_rows = [
            [Paragraph("Rule ID", style_table_header), Paragraph("Flag Name", style_table_header), Paragraph("Severity", style_table_header), Paragraph("Impact", style_table_header), Paragraph("Explanation", style_table_header)]
        ]
        for f in flags:
            sev = (f.get("severity") or "info").capitalize()
            pts = f.get("points_added", f.get("weight", 0))
            flag_rows.append([
                Paragraph(str(f.get("id") or f.get("rule_id", "-")), style_mono),
                Paragraph(str(f.get("name", "-")), style_body_bold),
                Paragraph(sev, style_body),
                Paragraph(f"+{pts} pts", style_body_bold),
                Paragraph(str(f.get("explanation", "-")), style_body)
            ])
        t_flags = Table(flag_rows, colWidths=[90, 110, 50, 48, 234])
        t_flags.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_flags)
    else:
        story.append(Paragraph("No security threat flags were triggered. The target complies with standard web architecture baseline.", style_body))

    story.append(Spacer(1, 12))



    # 5. OSINT Queries Grouped by Category (if present)
    categories_map = None
    if isinstance(dorks_data, dict):
        if "categories" in dorks_data and isinstance(dorks_data["categories"], dict):
            categories_map = dorks_data["categories"]
        elif any(isinstance(v, dict) and "queries" in v for v in dorks_data.values()):
            categories_map = dorks_data
    elif isinstance(dorks_data, list):
        categories_map = {item.get("id", f"cat_{i}"): item for i, item in enumerate(dorks_data) if isinstance(item, dict)}

    if categories_map:
        story.append(Spacer(1, 12))
        story.append(Paragraph("5. Generated OSINT Queries (Automated Dorks)", style_section_heading))
        for cat_id, cat_info in categories_map.items():
            cat_name = cat_info.get("name", cat_id)
            queries = cat_info.get("queries", [])
            if not queries:
                continue
            story.append(Paragraph(f"<b>{cat_name}</b> ({len(queries)} queries)", style_body_bold))
            q_rows = [[Paragraph("Label", style_table_header), Paragraph("Google Search Operator Query", style_table_header)]]
            for q in queries[:4]:
                q_rows.append([
                    Paragraph(str(q.get("label", "-")), style_body),
                    Paragraph(str(q.get("query", "-")), style_mono)
                ])
            t_q = Table(q_rows, colWidths=[160, 372])
            t_q.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ]))
            story.append(t_q)
            story.append(Spacer(1, 6))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer
