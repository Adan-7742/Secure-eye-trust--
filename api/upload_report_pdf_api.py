"""
api/upload_report_pdf_api.py
============================
Generates a real PDF report using reportlab (pure Python, no external tools).
"""
import io, datetime
from flask import Blueprint, request, Response, jsonify

pdf_report_bp = Blueprint("pdf_report", __name__)


def _build_pdf(d: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, HRFlowable, KeepTogether)
    from reportlab.platypus import BalancedColumns

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm)

    W = A4[0] - 36*mm   # usable width

    # ── Colour palette ──────────────────────────────────────────
    C_BG      = colors.HexColor("#0f172a")
    C_BLUE    = colors.HexColor("#1a8cff")
    C_RED     = colors.HexColor("#ef4444")
    C_ORANGE  = colors.HexColor("#fb923c")
    C_YELLOW  = colors.HexColor("#fbbf24")
    C_GREEN   = colors.HexColor("#10b981")
    C_GREY    = colors.HexColor("#64748b")
    C_LIGHT   = colors.HexColor("#f1f5f9")
    C_WHITE   = colors.white
    C_TEXT    = colors.HexColor("#1e293b")
    C_DIM     = colors.HexColor("#94a3b8")

    RISK_COLORS = {
        "Low": C_GREEN, "Medium": C_YELLOW,
        "High": C_ORANGE, "Critical": C_RED
    }

    styles = getSampleStyleSheet()
    def S(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    s_title    = S("T", fontSize=20, textColor=C_WHITE, fontName="Helvetica-Bold", leading=24)
    s_sub      = S("Su", fontSize=9,  textColor=C_DIM,   fontName="Helvetica")
    s_h2       = S("H2", fontSize=11, textColor=C_TEXT,  fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=4)
    s_body     = S("B",  fontSize=9,  textColor=C_TEXT,  fontName="Helvetica", leading=13)
    s_small    = S("Sm", fontSize=8,  textColor=C_GREY,  fontName="Helvetica")
    s_mono     = S("Mo", fontSize=8,  textColor=C_TEXT,  fontName="Courier",   leading=11)
    s_centered = S("Ce", fontSize=9,  textColor=C_DIM,   fontName="Helvetica", alignment=TA_CENTER)

    lc       = d.get("level_counts", {})
    findings = d.get("findings", [])
    errors   = d.get("top_errors", [])
    sources  = d.get("top_sources", [])
    timeline = d.get("timeline", [])
    risk_lbl = d.get("risk_label", "Low")
    risk_col = RISK_COLORS.get(risk_lbl, C_GREEN)
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = d.get("filename", "unknown")
    category = d.get("category", "—")
    total    = d.get("total", 0)
    raw_lines= d.get("raw_lines", 0)
    score    = d.get("risk_score", 0)

    story = []

    # ══════════════════════════════════════════════════════════
    # HEADER BANNER
    # ══════════════════════════════════════════════════════════
    header_data = [[
        Paragraph("🔐 Secure Eye Trust+", s_title),
        Paragraph(f"<b>Risk: {risk_lbl}</b><br/>{score}/100", ParagraphStyle(
            "RB", fontSize=13, textColor=risk_col, fontName="Helvetica-Bold",
            alignment=TA_RIGHT, leading=18))
    ]]
    header_tbl = Table(header_data, colWidths=[W*0.7, W*0.3])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_BG),
        ("TOPPADDING",   (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
        ("RIGHTPADDING", (0,0), (-1,-1), 14),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [8,8,8,8]),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 4*mm))

    # File info row
    meta_data = [[
        Paragraph(f"<b>File:</b> {filename}", s_body),
        Paragraph(f"<b>Category:</b> {category}", s_body),
        Paragraph(f"<b>Entries:</b> {total:,} / {raw_lines:,} lines", s_body),
        Paragraph(f"<b>Generated:</b> {now}", s_small),
    ]]
    meta_tbl = Table(meta_data, colWidths=[W*0.3, W*0.15, W*0.25, W*0.3])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_LIGHT),
        ("TOPPADDING",   (0,0), (-1,-1), 7),
        ("BOTTOMPADDING",(0,0), (-1,-1), 7),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 5*mm))

    # ══════════════════════════════════════════════════════════
    # STAT CARDS  (4 across)
    # ══════════════════════════════════════════════════════════
    def stat_card(val, label, col):
        return Table(
            [[Paragraph(str(val), ParagraphStyle("SV", fontSize=26, fontName="Helvetica-Bold",
                                                  textColor=col, alignment=TA_CENTER, leading=30))],
             [Paragraph(label,    ParagraphStyle("SL", fontSize=8,  fontName="Helvetica",
                                                  textColor=col, alignment=TA_CENTER, spaceBefore=2))]],
            colWidths=[(W-9*mm)/4]
        )

    n_crit  = lc.get("CRITICAL", 0)
    n_err   = lc.get("ERROR",0) + lc.get("FAILURE",0)
    n_warn  = lc.get("WARNING", 0)
    n_info  = lc.get("INFO",0) + lc.get("SUCCESS",0)

    cards = Table([[
        stat_card(n_crit, "CRITICAL", C_RED),
        stat_card(n_err,  "ERRORS",   C_ORANGE),
        stat_card(n_warn, "WARNINGS", C_YELLOW),
        stat_card(n_info, "INFO",     C_GREEN),
    ]], colWidths=[(W-9*mm)/4]*4, hAlign="LEFT")
    cards.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,0), colors.HexColor("#fef2f2")),
        ("BACKGROUND",   (1,0), (1,0), colors.HexColor("#fff7ed")),
        ("BACKGROUND",   (2,0), (2,0), colors.HexColor("#fffbeb")),
        ("BACKGROUND",   (3,0), (3,0), colors.HexColor("#f0fdf4")),
        ("BOX",          (0,0), (0,0), 0.5, colors.HexColor("#fecaca")),
        ("BOX",          (1,0), (1,0), 0.5, colors.HexColor("#fed7aa")),
        ("BOX",          (2,0), (2,0), 0.5, colors.HexColor("#fde68a")),
        ("BOX",          (3,0), (3,0), 0.5, colors.HexColor("#bbf7d0")),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("COLPADDING",   (0,0), (-1,-1), 3),
    ]))
    story.append(cards)
    story.append(Spacer(1, 5*mm))

    # ══════════════════════════════════════════════════════════
    # KEY FINDINGS
    # ══════════════════════════════════════════════════════════
    story.append(Paragraph("🚨 Key Findings", s_h2))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_LIGHT))
    story.append(Spacer(1, 2*mm))

    if findings:
        f_col = {"critical": C_RED, "error": C_ORANGE, "warning": C_YELLOW, "info": C_BLUE}
        f_bg  = {"critical": "#fef2f2", "error": "#fff7ed", "warning": "#fffbeb", "info": "#eff6ff"}
        rows = []
        for f in findings:
            fc   = f_col.get(f.get("type","info"), C_GREY)
            fbg  = colors.HexColor(f_bg.get(f.get("type","info"), "#f8fafc"))
            rows.append([
                Paragraph(f.get("type","").upper(), ParagraphStyle("FT", fontSize=8, fontName="Helvetica-Bold", textColor=fc, alignment=TA_CENTER)),
                Paragraph(f.get("text",""), s_body)
            ])
        ft = Table(rows, colWidths=[22*mm, W-22*mm])
        ft.setStyle(TableStyle([
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
            ("RIGHTPADDING", (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.HexColor("#f8fafc"), C_WHITE]),
            ("LINEBELOW",    (0,0), (-1,-2), 0.3, C_LIGHT),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("BOX",          (0,0), (-1,-1), 0.5, C_LIGHT),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph("✅ No critical findings detected in this file.", s_body))

    story.append(Spacer(1, 5*mm))

    # ══════════════════════════════════════════════════════════
    # TOP ERRORS TABLE
    # ══════════════════════════════════════════════════════════
    story.append(Paragraph("🔴 Top Errors & Critical Events", s_h2))
    story.append(HRFlowable(width=W, thickness=0.5, color=C_LIGHT))
    story.append(Spacer(1, 2*mm))

    if errors:
        err_rows = [[ Paragraph("Level", ParagraphStyle("EH", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREY)),
                      Paragraph("Timestamp", ParagraphStyle("EH2", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREY)),
                      Paragraph("Message", ParagraphStyle("EH3", fontSize=8, fontName="Helvetica-Bold", textColor=C_GREY)) ]]
        for e in errors[:15]:
            ec = C_RED if e.get("level") == "CRITICAL" else C_ORANGE
            err_rows.append([
                Paragraph(e.get("level",""), ParagraphStyle("EL", fontSize=8, fontName="Helvetica-Bold", textColor=ec)),
                Paragraph(e.get("ts",""),    s_mono),
                Paragraph(e.get("message","")[:120], s_small)
            ])
        et = Table(err_rows, colWidths=[18*mm, 36*mm, W-54*mm])
        et.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), C_LIGHT),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE, colors.HexColor("#f8fafc")]),
            ("LINEBELOW",    (0,0), (-1,-2), 0.3, C_LIGHT),
            ("BOX",          (0,0), (-1,-1), 0.5, C_LIGHT),
            ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ]))
        story.append(et)
    else:
        story.append(Paragraph("No error events found.", s_body))

    story.append(Spacer(1, 5*mm))

    # ══════════════════════════════════════════════════════════
    # SOURCES + TIMELINE  side by side
    # ══════════════════════════════════════════════════════════
    half = (W - 6*mm) / 2

    # Sources
    src_story = [Paragraph("📡 Top Log Sources", s_h2),
                 HRFlowable(width=half, thickness=0.5, color=C_LIGHT),
                 Spacer(1, 2*mm)]
    if sources:
        max_c = sources[0]["count"] if sources else 1
        src_rows = []
        for s in sources[:10]:
            pct = s["count"] / max_c
            bar_w = int(pct * 60)
            bar   = "█" * bar_w + "░" * (60 - bar_w)
            src_rows.append([
                Paragraph(s.get("source","")[:30], s_small),
                Paragraph(str(s["count"]), ParagraphStyle("SC", fontSize=8, fontName="Helvetica-Bold",
                                                           textColor=C_BLUE, alignment=TA_RIGHT)),
            ])
        src_tbl = Table(src_rows, colWidths=[half*0.75, half*0.25])
        src_tbl.setStyle(TableStyle([
            ("TOPPADDING",   (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
            ("LEFTPADDING",  (0,0),(-1,-1), 4),
            ("LINEBELOW",    (0,0),(-1,-2), 0.3, C_LIGHT),
        ]))
        src_story.append(src_tbl)

    # Timeline
    tl_story  = [Paragraph("📅 Activity Timeline", s_h2),
                 HRFlowable(width=half, thickness=0.5, color=C_LIGHT),
                 Spacer(1, 2*mm)]
    if timeline:
        tl_rows = []
        max_t = max(t["count"] for t in timeline) if timeline else 1
        for t in timeline[-14:]:
            pct   = t["count"] / max_t
            bar_w = max(1, int(pct * 40))
            tl_rows.append([
                Paragraph(t.get("date",""), s_small),
                Paragraph(str(t["count"]), ParagraphStyle("TC", fontSize=8, fontName="Helvetica-Bold",
                                                           textColor=C_BLUE, alignment=TA_RIGHT)),
            ])
        tl_tbl = Table(tl_rows, colWidths=[half*0.65, half*0.35])
        tl_tbl.setStyle(TableStyle([
            ("TOPPADDING",   (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
            ("LEFTPADDING",  (0,0),(-1,-1), 4),
            ("LINEBELOW",    (0,0),(-1,-2), 0.3, C_LIGHT),
        ]))
        tl_story.append(tl_tbl)

    # Combine side-by-side
    from reportlab.platypus import Frame, PageTemplate
    two_col = Table([[src_story, tl_story]], colWidths=[half, half])
    two_col.setStyle(TableStyle([
        ("VALIGN",      (0,0),(-1,-1), "TOP"),
        ("LEFTPADDING", (0,0),(-1,-1), 0),
        ("RIGHTPADDING",(0,0),(-1,-1), 0),
        ("COLPADDING",  (0,0),(-1,-1), 6),
    ]))
    story.append(two_col)
    story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════
    # FOOTER
    # ══════════════════════════════════════════════════════════
    story.append(HRFlowable(width=W, thickness=0.5, color=C_LIGHT))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        f"Secure Eye Trust+  ·  Log Scan Report  ·  {now}  ·  This report is confidential",
        s_centered))

    doc.build(story)
    return buf.getvalue()


@pdf_report_bp.route("/upload-report-pdf", methods=["POST"])
def upload_report_pdf():
    d = request.get_json(silent=True) or {}
    if not d:
        return jsonify({"error": "No data"}), 400
    try:
        pdf_bytes = _build_pdf(d)
        fname = (d.get("filename","report") or "report").replace(" ","_")
        fname = fname.rsplit(".",1)[0] + "_scan.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={fname}"}
        )
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500
