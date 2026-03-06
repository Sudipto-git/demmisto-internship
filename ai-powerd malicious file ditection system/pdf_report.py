"""
╔══════════════════════════════════════════╗
║   REPORT: PDF Threat Report Generator  ║
║   Uses ReportLab                        ║
╚══════════════════════════════════════════╝
"""

import os
import json
import logging
from datetime import datetime
from config import REPORTS_DIR

log = logging.getLogger(__name__)


def generate_pdf(report: dict) -> str:
    """Generate a professional PDF threat report. Returns file path."""

    try:
        from reportlab.lib.pagesizes  import A4
        from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units      import cm
        from reportlab.lib            import colors
        from reportlab.platypus       import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable
        )
        from reportlab.lib.enums      import TA_LEFT, TA_CENTER
    except ImportError:
        log.error("[PDF] reportlab not installed. Run: pip3 install reportlab")
        return ""

    scan_id      = report.get("scan_id",      f"DWM-{int(datetime.utcnow().timestamp())}")
    threat_level = report.get("threat_level", "UNKNOWN")
    target_type  = report.get("target_type",  "unknown")
    ai_analysis  = report.get("ai_analysis",  "No analysis available")
    scan_result  = report.get("scan_result",  {})
    completed_at = report.get("completed_at", datetime.utcnow().isoformat())

    filename = os.path.join(REPORTS_DIR, f"threat_report_{scan_id}.pdf")

    # ── Colors ────────────────────────────────────────
    BG_DARK  = colors.HexColor("#0a0a0a")
    GREEN    = colors.HexColor("#00ff41")
    RED      = colors.HexColor("#ff2020")
    ORANGE   = colors.HexColor("#ff8c00")
    YELLOW   = colors.HexColor("#ffe000")
    GRAY     = colors.HexColor("#888888")
    WHITE    = colors.HexColor("#ffffff")
    DARK     = colors.HexColor("#111111")
    BORDER   = colors.HexColor("#1a3320")

    threat_color = {
        "CRITICAL": RED,
        "HIGH":     ORANGE,
        "MEDIUM":   YELLOW,
        "LOW":      GREEN,
        "CLEAN":    GREEN
    }.get(threat_level, GRAY)

    # ── Styles ────────────────────────────────────────
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title", fontName="Courier-Bold",
        fontSize=18, textColor=GREEN,
        spaceAfter=4, alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        "Sub", fontName="Courier",
        fontSize=9, textColor=GRAY,
        spaceAfter=16, alignment=TA_CENTER
    )
    section_style = ParagraphStyle(
        "Section", fontName="Courier-Bold",
        fontSize=11, textColor=GREEN,
        spaceBefore=14, spaceAfter=6
    )
    body_style = ParagraphStyle(
        "Body", fontName="Courier",
        fontSize=9, textColor=WHITE,
        spaceAfter=4, leading=14
    )
    threat_style = ParagraphStyle(
        "Threat", fontName="Courier-Bold",
        fontSize=22, textColor=threat_color,
        alignment=TA_CENTER, spaceAfter=4
    )

    # ── Build document ────────────────────────────────
    doc   = SimpleDocTemplate(
        filename, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm
    )
    story = []

    # ── Header ────────────────────────────────────────
    story.append(Paragraph("DARKWEB MONITOR", title_style))
    story.append(Paragraph("AUTOMATED THREAT INTELLIGENCE REPORT", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN))
    story.append(Spacer(1, 12))

    # ── Threat level banner ───────────────────────────
    story.append(Paragraph(f"THREAT LEVEL: {threat_level}", threat_style))
    story.append(Spacer(1, 8))

    # ── Scan metadata table ───────────────────────────
    story.append(Paragraph("SCAN DETAILS", section_style))
    meta_data = [
        ["Scan ID",      scan_id],
        ["Target Type",  target_type.upper()],
        ["Threat Level", threat_level],
        ["Completed At", completed_at],
        ["Report By",    "DARKWEB MONITOR v1.0"]
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (-1, -1), "Courier"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",   (0, 0), (0, -1), GRAY),
        ("TEXTCOLOR",   (1, 0), (1, -1), WHITE),
        ("BACKGROUND",  (0, 0), (-1, -1), DARK),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [DARK, colors.HexColor("#0d0d0d")]),
        ("GRID",        (0, 0), (-1, -1), 0.5, BORDER),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # ── AI Analysis ───────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Paragraph("AI THREAT ANALYSIS", section_style))

    for line in ai_analysis.split("\n"):
        line = line.strip()
        if not line:
            story.append(Spacer(1, 4))
            continue
        # Bold headers
        if line.startswith("**") and line.endswith("**"):
            s = ParagraphStyle("Bold", fontName="Courier-Bold",
                               fontSize=9, textColor=GREEN, spaceAfter=2)
            story.append(Paragraph(line.replace("**", ""), s))
        else:
            clean = line.replace("**", "")
            story.append(Paragraph(clean, body_style))

    story.append(Spacer(1, 12))

    # ── Raw scan data ─────────────────────────────────
    if scan_result:
        story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        story.append(Paragraph("RAW SCAN DATA", section_style))

        raw_json = json.dumps(scan_result, indent=2)
        # Split into chunks to avoid overflow
        for chunk in [raw_json[i:i+800] for i in range(0, min(len(raw_json), 3200), 800)]:
            raw_style = ParagraphStyle(
                "Raw", fontName="Courier", fontSize=7,
                textColor=GRAY, spaceAfter=2, leading=10
            )
            story.append(Paragraph(chunk.replace("\n", "<br/>"), raw_style))

    # ── Footer ────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    footer = ParagraphStyle("Footer", fontName="Courier", fontSize=7,
                            textColor=GRAY, alignment=TA_CENTER)
    story.append(Paragraph(
        f"Generated by DARKWEB MONITOR | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | CONFIDENTIAL",
        footer
    ))

    # ── Build PDF ─────────────────────────────────────
    doc.build(story)
    log.info(f"[PDF] Report saved: {filename}")
    return filename
