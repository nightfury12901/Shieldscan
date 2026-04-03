"""
PDF report generator using reportlab.
Produces a branded ShieldScan PDF from scan results.
"""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# Brand colors
DARK_NAVY = colors.HexColor("#0f0f1a")
CARD_BG   = colors.HexColor("#1a1a2e")
GOLD      = colors.HexColor("#f5a623")
TEAL      = colors.HexColor("#00b4d8")
RED       = colors.HexColor("#ef4444")
AMBER     = colors.HexColor("#f59e0b")
GREEN     = colors.HexColor("#10b981")
LIGHT     = colors.HexColor("#e8e8e8")

SEVERITY_COLORS = {"critical": RED, "medium": AMBER, "low": GREEN}


def generate_pdf(scan: dict, findings: list[dict]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("title", parent=styles["Title"],
                                 fontSize=28, textColor=GOLD, spaceAfter=4)
    sub_style   = ParagraphStyle("sub", parent=styles["Normal"],
                                 fontSize=12, textColor=TEAL, spaceAfter=12)
    h2_style    = ParagraphStyle("h2", parent=styles["Heading2"],
                                 fontSize=16, textColor=GOLD, spaceBefore=12, spaceAfter=6)
    body_style  = ParagraphStyle("body", parent=styles["Normal"],
                                 fontSize=10, textColor=colors.black, spaceAfter=4)
    small_style = ParagraphStyle("small", parent=styles["Normal"],
                                 fontSize=9, textColor=colors.grey)

    # Header
    story.append(Paragraph("🛡 ShieldScan", title_style))
    story.append(Paragraph("Cybersecurity Audit Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=GOLD))
    story.append(Spacer(1, 8*mm))

    # Scan metadata
    target = scan.get("target", "Unknown")
    scan_type = scan.get("scan_type", "url").upper()
    created = scan.get("created_at", "")[:10]
    score = scan.get("risk_score", "N/A")
    score_color = GREEN if isinstance(score, int) and score >= 70 else AMBER if isinstance(score, int) and score >= 40 else RED

    meta_data = [
        ["Target", target],
        ["Scan Type", scan_type],
        ["Date", created],
        ["Business Risk Score", str(score) + " / 100"],
    ]
    meta_table = Table(meta_data, colWidths=[50*mm, 120*mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (0, 3), (1, 3), score_color),
        ("FONTNAME", (0, 3), (-1, 3), "Helvetica-Bold"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8*mm))

    # Executive Summary
    ai_report = scan.get("ai_report", {}) or {}
    exec_summary = ai_report.get("executive_summary", "No summary available.")
    story.append(Paragraph("Executive Summary", h2_style))
    story.append(Paragraph(exec_summary, body_style))
    story.append(Spacer(1, 6*mm))

    # Findings
    story.append(Paragraph("Security Findings", h2_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    story.append(Spacer(1, 4*mm))

    severity_order = {"critical": 0, "medium": 1, "low": 2}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "low"), 2))

    for i, finding in enumerate(sorted_findings, 1):
        sev = finding.get("severity", "low")
        sev_color = SEVERITY_COLORS.get(sev, GREEN)
        sev_label = sev.upper()

        # Finding header row
        header_data = [[
            Paragraph(f"<b>{i}. {finding.get('title', 'Finding')}</b>", body_style),
            Paragraph(f"<b>{sev_label}</b>", ParagraphStyle("sev", fontSize=9, textColor=sev_color, alignment=1)),
        ]]
        header_table = Table(header_data, colWidths=[140*mm, 30*mm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f8f8")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        story.append(header_table)

        if finding.get("affected_asset"):
            story.append(Paragraph(f"<i>Asset: {finding['affected_asset']}</i>", small_style))
        if finding.get("description"):
            story.append(Paragraph(finding["description"], body_style))
        if finding.get("fix_steps"):
            story.append(Paragraph("<b>How to fix:</b>", body_style))
            story.append(Paragraph(finding["fix_steps"].replace("\n", "<br/>"), body_style))
        story.append(Spacer(1, 4*mm))

    # Footer
    story.append(HRFlowable(width="100%", thickness=0.5, color=GOLD))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"Report generated by ShieldScan on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | shieldscan.app",
        small_style
    ))

    doc.build(story)
    return buf.getvalue()
