import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable,
)
from reportlab.pdfgen import canvas

# ── Palette — near-monochrome; only functional risk indicators use colour ─────
BLACK      = colors.HexColor("#111827")
DARK_GRAY  = colors.HexColor("#374151")
MID_GRAY   = colors.HexColor("#6B7280")
LIGHT_GRAY = colors.HexColor("#9CA3AF")
RULE       = colors.HexColor("#D1D5DB")
BG_GRAY    = colors.HexColor("#F3F4F6")
BG_LIGHT   = colors.HexColor("#F9FAFB")
WHITE      = colors.white

# Functional risk / annotation colours (kept for readability)
C_HIGH   = colors.HexColor("#DC2626")
C_MEDIUM = colors.HexColor("#D97706")
C_LOW    = colors.HexColor("#059669")
C_PURPLE = colors.HexColor("#6366F1")   # MITRE technique IDs
C_BLUE   = colors.HexColor("#1D4ED8")   # compliance text

PW, PH = letter   # 612 × 792 pts

# ── MITRE → Compliance cross-reference ───────────────────────────────────────
MITRE_COMPLIANCE_MAP = {
    "T1195.001": {
        "name": "Compromise Software Dependencies and Development Tools",
        "controls": [
            ("NIST SP 800-161", "SA-12 — Supply Chain Risk Management"),
            ("NIS2 Directive",  "Article 21 — Supply chain security measures"),
            ("DORA",            "Article 5 — ICT risk management framework"),
        ],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "controls": [
            ("NIST SP 800-161", "SA-12 — Supply Chain Risk Management"),
            ("NIS2 Directive",  "Article 21 — Cybersecurity risk management"),
            ("DORA",            "Article 6 — ICT systems protection"),
        ],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "controls": [
            ("NIST SP 800-161", "SA-11 — Developer Security Testing"),
            ("NIS2 Directive",  "Article 21 — Cybersecurity risk management"),
        ],
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "controls": [
            ("NIST SP 800-161", "IA-5 — Authenticator Management"),
            ("NIS2 Directive",  "Article 21 — Access control"),
            ("DORA",            "Article 9 — Protection of ICT systems"),
        ],
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "controls": [
            ("NIST SP 800-161", "SA-12 — Supply Chain Risk Management"),
            ("NIS2 Directive",  "Article 21 — Incident detection"),
            ("DORA",            "Article 6 — ICT threat and vulnerability management"),
        ],
    },
}

# Module-level cover metadata — set before doc.build()
_COVER_META: dict = {}


# ── Canvas: cover page + body chrome ─────────────────────────────────────────
class DepthchargeCanvas(canvas.Canvas):
    """
    Two-pass canvas.
    • Page 1  → professional white/black cover (page de garde)
    • Pages 2+ → minimal header rule + footer rule with page numbers
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            if self._pageNumber == 1:
                self._draw_cover()
            else:
                self._draw_body_chrome(total_pages)
            super().showPage()
        super().save()

    # ── Cover page ────────────────────────────────────────────────────────────
    def _draw_cover(self):
        meta = _COVER_META
        c    = self
        c.saveState()

        # ── Left accent bar (thick black, like the reference) ──
        c.setFillColor(BLACK)
        c.rect(0, 0, 7, PH, fill=1, stroke=0)

        # ── Small-caps classification tag (manual letter-spacing) ──
        c.setFont("Helvetica", 8)
        c.setFillColor(MID_GRAY)
        tag_text = "CONFIDENTIAL SECURITY ASSESSMENT REPORT"
        x_pos = 54
        for ch in tag_text:
            c.drawString(x_pos, PH - 46, ch)
            x_pos += c.stringWidth(ch, "Helvetica", 8) + 1.4

        # Thin rule below tag
        c.setStrokeColor(RULE)
        c.setLineWidth(0.5)
        c.line(54, PH - 60, PW - 54, PH - 60)

        # ── Main title (large Times-Bold serif) ──
        c.setFont("Times-Bold", 34)
        c.setFillColor(BLACK)
        c.drawString(54, PH - 116, "Dependency Supply Chain")
        c.drawString(54, PH - 158, "Security Audit Report")

        # ── Italic subtitle ──
        c.setFont("Times-Italic", 12)
        c.setFillColor(DARK_GRAY)
        c.drawString(54, PH - 184,
                     "Automated Dependency Reputation & Static / Dynamic Threat Analysis")

        # Rule below subtitle
        c.setStrokeColor(BLACK)
        c.setLineWidth(0.75)
        c.line(54, PH - 200, PW - 54, PH - 200)

        # ── Metadata block (lower half of page) ──
        total_pkgs = meta.get("total",  0)
        high       = meta.get("high",   0)
        medium     = meta.get("medium", 0)
        low        = meta.get("low",    0)
        pkgs_str   = meta.get("packages_str", str(total_pkgs))

        rows = [
            ("Date of Report",        datetime.now().strftime("%B %d, %Y")),
            ("Classification",        "Confidential"),
            ("Packages Analyzed",     pkgs_str),
            ("Risk Summary",          f"{high} High  ·  {medium} Medium  ·  {low} Clean"),
            ("Analysis Coverage",     "Reputation  ·  Static AST  ·  Dynamic Sandbox"),
            ("Compliance Frameworks", "NIST SP 800-161  ·  NIS2 Directive  ·  DORA"),
            ("Generated by",          "Depthcharge Dependency Threat Analyzer"),
        ]

        meta_top = 336
        row_h    = 24

        # Light rule above metadata block
        c.setStrokeColor(RULE)
        c.setLineWidth(0.5)
        c.line(54, meta_top + 14, PW - 54, meta_top + 14)

        for i, (label, value) in enumerate(rows):
            y = meta_top - i * row_h

            # Row separator (very light)
            if i > 0:
                c.setStrokeColor(colors.HexColor("#EFEFEF"))
                c.setLineWidth(0.3)
                c.line(54, y + 14, PW - 54, y + 14)

            c.setFont("Helvetica-Bold", 9)
            c.setFillColor(DARK_GRAY)
            c.drawString(54, y, label)

            c.setFont("Times-Roman", 10)
            c.setFillColor(BLACK)
            c.drawString(210, y, value)

        # Bottom rule
        bottom_y = meta_top - len(rows) * row_h - 14
        c.setStrokeColor(BLACK)
        c.setLineWidth(0.75)
        c.line(54, bottom_y, PW - 54, bottom_y)

        # Footer disclaimer
        c.setFont("Helvetica", 7.5)
        c.setFillColor(MID_GRAY)
        c.drawString(
            54, bottom_y - 20,
            "This report was generated automatically by Depthcharge. "
            "Findings should be validated by a qualified security professional.",
        )
        c.drawRightString(
            PW - 54, bottom_y - 20,
            f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        )

        c.restoreState()

    # ── Body page chrome ──────────────────────────────────────────────────────
    def _draw_body_chrome(self, total_pages):
        c = self
        c.saveState()

        # Left accent bar (consistent identity across all pages)
        c.setFillColor(BLACK)
        c.rect(0, 0, 7, PH, fill=1, stroke=0)

        # ── Top rule ──
        c.setStrokeColor(RULE)
        c.setLineWidth(0.5)
        c.line(54, PH - 30, PW - 54, PH - 30)

        # Header text
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(DARK_GRAY)
        c.drawString(54, PH - 22, "DEPTHCHARGE")

        c.setFont("Helvetica", 8)
        c.setFillColor(MID_GRAY)
        c.drawString(54 + 76, PH - 22, "Security Audit Report  ·  Confidential")

        c.setFont("Helvetica", 8)
        c.setFillColor(LIGHT_GRAY)
        c.drawRightString(PW - 54, PH - 22, datetime.now().strftime("%Y-%m-%d"))

        # ── Bottom rule ──
        c.setStrokeColor(RULE)
        c.setLineWidth(0.5)
        c.line(54, 46, PW - 54, 46)

        c.setFont("Helvetica", 7.5)
        c.setFillColor(MID_GRAY)
        c.drawString(54, 33, "Confidential — Depthcharge Dependency Threat Analyzer")

        body_page  = self._pageNumber - 1
        body_total = total_pages - 1
        c.drawRightString(PW - 54, 33, f"Page {body_page} of {body_total}")

        c.restoreState()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _risk_color(level: str):
    l = str(level).lower()
    return C_HIGH if l == "high" else C_MEDIUM if l == "medium" else C_LOW if l == "low" else MID_GRAY


# ── Report entry point ────────────────────────────────────────────────────────
def generate_pdf_report(results: dict, output_path: str):
    """
    Generates a professional LaTeX-style PDF security audit report:
      1. Cover page (page de garde) — white/black, serif, metadata block
      2. Executive Summary with risk metrics
      3. Dependencies Checklist
      4. Detailed per-package findings (MITRE ATT&CK + compliance)
    """
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # ── Cover metadata ────────────────────────────────────────────────────────
    total  = len(results)
    high   = sum(1 for r in results.values() if r.get("risk_level") == "High")
    medium = sum(1 for r in results.values() if r.get("risk_level") == "Medium")
    low    = sum(1 for r in results.values() if r.get("risk_level") == "Low")
    pkg_keys = list(results.keys())
    pkgs_str = ", ".join(pkg_keys[:5])
    if len(pkg_keys) > 5:
        pkgs_str += f"  +{len(pkg_keys) - 5} more"

    global _COVER_META
    _COVER_META = {
        "total":        total,
        "high":         high,
        "medium":       medium,
        "low":          low,
        "packages_str": pkgs_str,
    }

    # topMargin=56 → content frame top at y=736, body header chrome at y=762+
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54, rightMargin=54,
        topMargin=56, bottomMargin=62,
    )

    # ── Styles ────────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    h1 = ParagraphStyle(
        "DC_H1", parent=styles["Normal"],
        fontName="Times-Bold", fontSize=14, leading=19,
        textColor=BLACK,
        spaceBefore=24, spaceAfter=4, keepWithNext=True,
    )
    h2 = ParagraphStyle(
        "DC_H2", parent=styles["Normal"],
        fontName="Times-Bold", fontSize=11, leading=15,
        textColor=BLACK,
        spaceBefore=14, spaceAfter=4, keepWithNext=True,
    )
    body = ParagraphStyle(
        "DC_Body", parent=styles["Normal"],
        fontName="Times-Roman", fontSize=10, leading=14,
        textColor=BLACK, spaceAfter=4,
    )
    bullet_s = ParagraphStyle(
        "DC_Bullet", parent=body,
        leftIndent=16, firstLineIndent=-10, spaceAfter=3,
    )
    tc = ParagraphStyle(
        "DC_TC", parent=styles["Normal"],
        fontName="Times-Roman", fontSize=9, leading=12,
        textColor=BLACK,
    )
    tc_bold = ParagraphStyle(
        "DC_TCBold", parent=tc, fontName="Times-Bold",
    )
    th = ParagraphStyle(
        "DC_TH", parent=styles["Normal"],
        fontName="Helvetica-Bold", fontSize=8.5, leading=12,
        textColor=WHITE,
    )
    small = ParagraphStyle(
        "DC_Small", parent=styles["Normal"],
        fontName="Times-Roman", fontSize=8, leading=11,
        textColor=BLACK,
    )
    small_bold = ParagraphStyle(
        "DC_SmallBold", parent=small, fontName="Times-Bold",
    )

    # ── Section header helper ─────────────────────────────────────────────────
    def section_hdr(number: int, title: str):
        return [
            Paragraph(f"<b>{number}. {title}</b>", h1),
            HRFlowable(width="100%", thickness=0.5, color=RULE, spaceAfter=8),
        ]

    # ── Story ─────────────────────────────────────────────────────────────────
    story = []
    story.append(PageBreak())   # page 1 = cover (drawn by canvas)

    # ╔══════════════════════════╗
    # ║  1. Executive Summary   ║
    # ╚══════════════════════════╝
    story.extend(section_hdr(1, "Executive Summary"))
    story.append(Spacer(1, 4))

    # Risk metrics — one dark header row, one value row (monochrome header, coloured values)
    metrics_data = [
        [Paragraph(lbl, th) for lbl in ["TOTAL", "HIGH RISK", "MEDIUM RISK", "CLEAN"]],
        [
            Paragraph(f"<font size=20><b>{total}</b></font>",                           tc_bold),
            Paragraph(f"<font size=20 color='#DC2626'><b>{high}</b></font>",            tc_bold),
            Paragraph(f"<font size=20 color='#D97706'><b>{medium}</b></font>",          tc_bold),
            Paragraph(f"<font size=20 color='#059669'><b>{low}</b></font>",             tc_bold),
        ],
    ]
    metrics_tbl = Table(metrics_data, colWidths=[126, 126, 126, 126])
    metrics_tbl.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",    (0, 0), (-1, 0),  DARK_GRAY),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("BOX",           (0, 0), (-1, -1), 0.5, RULE),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, RULE),
    ]))
    story.append(metrics_tbl)
    story.append(Spacer(1, 14))

    # Collect all MITRE techniques across results
    all_mitre: dict = {}
    for r in results.values():
        for a in (r.get("static") or {}).get("alerts", []):
            mid = a.get("mitre_id")
            if mid and mid != "T0000":
                all_mitre[mid] = a.get("mitre_technique", "")

    # Executive narrative
    blocked_pkgs  = [p for p, r in results.items() if r.get("risk_level") == "High"]
    changed_pkgs  = [p for p, r in results.items()
                     if (r.get("reputation") or {}).get("maintainer_changed")]
    ioc_pkgs      = [p for p, r in results.items()
                     if (r.get("static") or {}).get("ioc_matches")]
    taint_pkgs    = [p for p, r in results.items()
                     if (r.get("static") or {}).get("taint_flows_detected")]
    remediation_c = sum(1 for r in results.values() if r.get("remediation"))

    exec_lines = [
        f"<b>Packages scanned:</b> {total} dependencies were subjected to automated "
        "reputation, static AST, and dynamic sandbox analysis.",
        f"<b>Risk distribution:</b> {high} high-risk, {medium} medium-risk, {low} clean/low-risk.",
    ]
    if blocked_pkgs:
        names = ", ".join(blocked_pkgs[:5])
        exec_lines.append(f"<b>High-risk packages:</b> {names}"
                          + (" and others." if len(blocked_pkgs) > 5 else "."))
    if remediation_c:
        exec_lines.append(
            f"<b>Remediation guidance</b> is available for {remediation_c} package(s).")
    if changed_pkgs:
        exec_lines.append(
            f"<b>⚠ Maintainer change detected:</b> {', '.join(changed_pkgs)} "
            f"— investigate for account takeover.")
    if ioc_pkgs:
        exec_lines.append(
            f"<b>⚠ Direct IoC matches (C2/token/exfil):</b> {', '.join(ioc_pkgs)} "
            f"— treat as active threat.")
    if taint_pkgs:
        exec_lines.append(
            f"<b>Taint-flow confirmed:</b> external data reaches dangerous sinks "
            f"in {', '.join(taint_pkgs)}.")
    if all_mitre:
        t_str = ", ".join(f"{m} ({n})" for m, n in list(all_mitre.items())[:5])
        exec_lines.append(f"<b>MITRE ATT&amp;CK techniques observed:</b> {t_str}.")

    for line in exec_lines:
        story.append(Paragraph(f"• {line}", bullet_s))
    story.append(Spacer(1, 18))

    # ╔══════════════════════════════════╗
    # ║  2. Dependencies Checklist       ║
    # ╚══════════════════════════════════╝
    story.extend(section_hdr(2, "Dependencies Checklist"))
    story.append(Spacer(1, 4))

    hdr_row = [Paragraph(t, th) for t in
               ["Package", "Ecosystem", "Version", "Score", "Risk Level"]]
    rows_tbl = [hdr_row]
    for pkg, r in results.items():
        rep   = r.get("reputation") or {}
        eco   = str(rep.get("ecosystem", "unknown")).upper()
        ver   = str(rep.get("version",   "Unknown"))
        score = r.get("score", 0)
        level = r.get("risk_level", "Unknown")
        c_hex = "#DC2626" if level == "High" else "#D97706" if level == "Medium" else "#059669"
        rows_tbl.append([
            Paragraph(f"<b>{pkg}</b>", tc),
            Paragraph(eco, tc),
            Paragraph(ver, tc),
            Paragraph(f"<b>{score}/100</b>", tc),
            Paragraph(f"<font color='{c_hex}'><b>{level}</b></font>", tc),
        ])

    cl_s = [
        ("BACKGROUND",    (0, 0), (-1, 0),  DARK_GRAY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("BOX",           (0, 0), (-1, -1), 0.5, RULE),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, RULE),
    ]
    for i in range(1, len(rows_tbl)):
        if i % 2 == 0:
            cl_s.append(("BACKGROUND", (0, i), (-1, i), BG_LIGHT))
    cl_tbl = Table(rows_tbl, colWidths=[174, 80, 80, 80, 90])
    cl_tbl.setStyle(TableStyle(cl_s))
    story.append(cl_tbl)

    # ╔══════════════════════════════════════════════╗
    # ║  3. Detailed Vulnerability & Code Analysis   ║
    # ╚══════════════════════════════════════════════╝
    story.append(PageBreak())
    story.extend(section_hdr(3, "Detailed Vulnerability & Code Analysis"))
    story.append(Spacer(1, 8))

    for pkg, r in results.items():
        pkg_story = []

        rep     = r.get("reputation") or {}
        static  = r.get("static")  or {}
        dynamic = r.get("dynamic") or {}
        eco     = str(rep.get("ecosystem", "unknown")).upper()
        ver     = str(rep.get("version",   "Unknown"))
        score   = r.get("score",      0)
        level   = r.get("risk_level", "Unknown")
        alerts  = static.get("alerts")       or []
        vulns   = rep.get("vulnerabilities") or []
        events  = dynamic.get("events")      or []

        is_typosquat = rep.get("typosquatting_detected") or bool(static.get("typosquatting"))
        typo_target  = (
            rep.get("typosquatting_info") or static.get("typosquatting") or {}
        ).get("target", "a known package")

        rc = _risk_color(level)

        # ── Package header ──
        hdr_data = [[
            Paragraph(
                f"<b>{pkg}</b>  <font color='#6B7280' size=9>({eco} · v{ver})</font>",
                h2,
            ),
            Paragraph(
                f"<font color='white'><b>{score}/100  {level.upper()}</b></font>",
                tc_bold,
            ),
        ]]
        hdr_tbl = Table(hdr_data, colWidths=[370, 134])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (1, 0), (1, 0),   rc),
            ("ALIGN",         (1, 0), (1, 0),   "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("LINEBELOW",     (0, 0), (-1, 0),  1.0, BLACK),
        ]))
        pkg_story.append(hdr_tbl)
        pkg_story.append(Spacer(1, 6))

        # ── Audit evaluation log ──
        pkg_story.append(Paragraph("<b>Audit Evaluation Log</b>", small_bold))
        for reason in (r.get("reasons") or ["No suspicious behaviour detected."]):
            pkg_story.append(Paragraph(f"• {reason}", bullet_s))
        pkg_story.append(Spacer(1, 6))

        # ── Remediation block ──
        remediation = r.get("remediation")
        if remediation:
            rem_rows = [
                [Paragraph("<b>Remediation Guidance</b>", tc_bold)],
                [Paragraph(remediation, tc)],
            ]
            rem_tbl = Table(rem_rows, colWidths=[504])
            rem_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#FEF2F2")),
                ("BACKGROUND",    (0, 1), (-1, 1), colors.HexColor("#FFFAFA")),
                ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#FCA5A5")),
                ("INNERGRID",     (0, 0), (-1, -1), 0.3, colors.HexColor("#FCA5A5")),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ]))
            pkg_story.append(rem_tbl)
            pkg_story.append(Spacer(1, 6))

        # ── Registry metadata + vulnerabilities ──
        created = rep.get("created_at", "Unknown")
        if isinstance(created, str) and "T" in created:
            created = created.split("T")[0]

        maint_note = ""
        if rep.get("maintainer_changed"):
            prev = rep.get("previous_maintainer_email", "?")
            curr = rep.get("author_email", "?")
            maint_note = (
                f"<br/><font color='#DC2626'><b>⚠ Maintainer changed: "
                f"{prev} → {curr}</b></font>"
            )

        meta_html = (
            f"<b>Author:</b> {rep.get('author', 'Unknown')}<br/>"
            f"<b>Email:</b> {rep.get('author_email', 'Unknown')}<br/>"
            f"<b>Created:</b> {created}<br/>"
            f"<b>Releases:</b> {rep.get('releases_count', 0)}{maint_note}"
        )

        if vulns:
            vulns_html = (
                "<br/>".join(
                    f"• <b>{v.get('id')}</b>: {v.get('summary', '')}" for v in vulns[:5]
                )
                + (f"<br/>• <i>…and {len(vulns) - 5} more</i>" if len(vulns) > 5 else "")
            )
        elif is_typosquat:
            vulns_html = (
                f"<font color='#D97706'>⚠ Package does not exist on PyPI — "
                f"CVE lookup not applicable (typosquatting of '{typo_target}').</font>"
            )
        else:
            vulns_html = (
                "<font color='#059669'>✓ No known CVE or GHSA vulnerabilities in OSV.</font>"
            )

        grid_data = [
            [Paragraph("<b>Registry Metadata</b>", tc_bold),
             Paragraph(f"<b>Known Vulnerabilities ({len(vulns)})</b>", tc_bold)],
            [Paragraph(meta_html,  tc),
             Paragraph(vulns_html, tc)],
        ]
        grid_tbl = Table(grid_data, colWidths=[247, 257])
        grid_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), BG_GRAY),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("BOX",           (0, 0), (-1, -1), 0.5, RULE),
            ("INNERGRID",     (0, 0), (-1, -1), 0.3, RULE),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        pkg_story.append(grid_tbl)
        pkg_story.append(Spacer(1, 6))

        # ── Static AST analysis ──
        if alerts:
            alert_cap   = 15
            static_html = ""
            for a in alerts[:alert_cap]:
                sev  = str(a.get("severity", "medium")).upper()
                msg  = a.get("message", "")
                loc  = f"{a.get('file', '?')}:{a.get('line', 0)}"
                mid  = a.get("mitre_id", "")
                conf = a.get("confidence", "")
                tag  = (f" <font color='#6366F1'>[{mid}]</font>"
                        if mid and mid != "T0000" else "")
                ctag = (f" <font color='#9CA3AF'>(conf: {conf})</font>" if conf else "")
                static_html += (
                    f"• <b>[{sev}]</b>{tag}{ctag} "
                    f"<font face='Courier' size=7>{loc}</font>: {msg}<br/>"
                )
            if len(alerts) > alert_cap:
                static_html += (
                    f"• <i>…and {len(alerts) - alert_cap} more alerts (truncated)</i>"
                )
        else:
            static_html = (
                "<font color='#059669'>✓ No suspicious static syntax pattern triggers.</font>"
            )

        # ── Dynamic sandbox events ──
        if events:
            dynamic_html = "<br/>".join(
                f"• <b>{e.get('type', 'EVENT').upper()}</b>: {e.get('details', '')}"
                for e in events[:10]
            )
            if len(events) > 10:
                dynamic_html += f"<br/>• <i>…and {len(events) - 10} more events</i>"
        else:
            if not dynamic.get("docker_available"):
                dynamic_html = (
                    "<font color='#D97706'>⚠ Dynamic scan skipped (Docker unavailable).</font>"
                )
            elif not dynamic.get("installation_success"):
                dynamic_html = (
                    "<font color='#DC2626'>✗ Package installation failed in sandbox.</font>"
                )
            else:
                dynamic_html = (
                    "<font color='#059669'>"
                    "✓ No unexpected filesystem, network, or process-spawning activities."
                    "</font>"
                )

        scan_data = [
            [Paragraph(f"<b>Static AST Analysis ({len(alerts)} alerts)</b>",  tc_bold),
             Paragraph(f"<b>Dynamic Sandbox Events ({len(events)})</b>",       tc_bold)],
            [Paragraph(static_html,  tc),
             Paragraph(dynamic_html, tc)],
        ]
        scan_tbl = Table(scan_data, colWidths=[247, 257])
        scan_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), BG_GRAY),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("BOX",           (0, 0), (-1, -1), 0.5, RULE),
            ("INNERGRID",     (0, 0), (-1, -1), 0.3, RULE),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        pkg_story.append(scan_tbl)
        pkg_story.append(Spacer(1, 6))

        # ── MITRE ATT&CK + compliance cross-reference ──
        pkg_mitre: dict = {}
        for a in alerts:
            mid = a.get("mitre_id")
            if mid and mid != "T0000":
                pkg_mitre[mid] = a.get("mitre_technique", "")

        if pkg_mitre:
            pkg_story.append(
                Paragraph(
                    "<b>MITRE ATT&amp;CK Mapping &amp; Compliance Controls</b>",
                    small_bold,
                )
            )
            pkg_story.append(Spacer(1, 3))

            comp_rows = [[
                Paragraph("<b>Technique</b>",           tc_bold),
                Paragraph("<b>Name</b>",                tc_bold),
                Paragraph("<b>Regulatory Controls</b>", tc_bold),
            ]]
            for mid, tname in pkg_mitre.items():
                mapping  = MITRE_COMPLIANCE_MAP.get(mid, {})
                controls = mapping.get("controls", [])
                ctrl_html = "<br/>".join(
                    f"<font color='#1D4ED8'>{fw}:</font> {ctrl}"
                    for fw, ctrl in controls
                ) if controls else "—"
                comp_rows.append([
                    Paragraph(f"<b><font color='#6366F1'>{mid}</font></b>", small),
                    Paragraph(tname or mapping.get("name", ""), small),
                    Paragraph(ctrl_html, small),
                ])

            comp_tbl = Table(comp_rows, colWidths=[70, 184, 250])
            comp_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), BG_GRAY),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("BOX",           (0, 0), (-1, -1), 0.5, RULE),
                ("INNERGRID",     (0, 0), (-1, -1), 0.3, RULE),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ]))
            pkg_story.append(comp_tbl)
            pkg_story.append(Spacer(1, 6))

        pkg_story.append(Spacer(1, 14))

        try:
            story.append(KeepTogether(pkg_story))
        except Exception:
            story.extend(pkg_story)

    doc.build(story, canvasmaker=DepthchargeCanvas)
    print(f"[depthcharge] PDF report saved → {output_path}")
