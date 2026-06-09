import os
import sys
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.pdfgen import canvas

# ── MITRE → compliance control cross-reference ────────────────────────────────
MITRE_COMPLIANCE_MAP = {
    "T1195.001": {
        "name": "Compromise Software Dependencies and Development Tools",
        "controls": [
            ("NIST SP 800-161", "SA-12 — Supply Chain Risk Management"),
            ("NIS2 Directive", "Article 21 — Supply chain security measures"),
            ("DORA", "Article 5 — ICT risk management framework"),
        ],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "controls": [
            ("NIST SP 800-161", "SA-12 — Supply Chain Risk Management"),
            ("NIS2 Directive", "Article 21 — Cybersecurity risk management"),
            ("DORA", "Article 6 — ICT systems protection"),
        ],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "controls": [
            ("NIST SP 800-161", "SA-11 — Developer Security Testing"),
            ("NIS2 Directive", "Article 21 — Cybersecurity risk management"),
        ],
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "controls": [
            ("NIST SP 800-161", "IA-5 — Authenticator Management"),
            ("NIS2 Directive", "Article 21 — Access control"),
            ("DORA", "Article 9 — Protection of ICT systems"),
        ],
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "controls": [
            ("NIST SP 800-161", "SA-12 — Supply Chain Risk Management"),
            ("NIS2 Directive", "Article 21 — Incident detection"),
            ("DORA", "Article 6 — ICT threat and vulnerability management"),
        ],
    },
}


class NumberedCanvas(canvas.Canvas):
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
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            return
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#4B5563"))
        self.drawString(54, 750, "DEPTHCHARGE SECURITY AUDIT REPORT")
        self.drawRightString(558, 750, f"GENERATED: {datetime.now().strftime('%Y-%m-%d')}")
        self.setStrokeColor(colors.HexColor("#E5E7EB"))
        self.setLineWidth(0.75)
        self.line(54, 742, 558, 742)
        self.line(54, 54, 558, 54)
        self.setFont("Helvetica", 8)
        self.drawString(54, 40, "Confidential – Depthcharge Dependency Threat Analyzer")
        self.drawRightString(558, 40, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def get_risk_color(level):
    level = str(level).lower()
    if level == "high":
        return colors.HexColor("#EF4444")
    elif level == "medium":
        return colors.HexColor("#F59E0B")
    elif level == "low":
        return colors.HexColor("#10B981")
    return colors.HexColor("#6B7280")


def generate_pdf_report(results, output_path):
    """
    Generates a high-quality PDF audit report with:
    - Executive summary page
    - Dependencies checklist
    - Per-package detailed findings
    - MITRE ATT&CK tagging
    - Compliance control mapping (NIS2 / DORA / NIST SP 800-161)
    - Remediation suggestions per blocked verdict
    """
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54, rightMargin=54,
        topMargin=75, bottomMargin=75
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=24, leading=30,
        textColor=colors.HexColor("#1E3A8A"), spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle', parent=styles['Normal'],
        fontName='Helvetica', fontSize=10, leading=14,
        textColor=colors.HexColor("#4B5563"), spaceAfter=25
    )
    h1_style = ParagraphStyle(
        'SectionH1', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=15, leading=20,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=15, spaceAfter=10, keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'PackageH2', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=12, leading=16,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=12, spaceAfter=6, keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyTextCustom', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9, leading=13,
        textColor=colors.HexColor("#1F2937")
    )
    bullet_style = ParagraphStyle(
        'BulletCustom', parent=body_style,
        leftIndent=15, firstLineIndent=-10, spaceAfter=4
    )
    tbl_header_style = ParagraphStyle(
        'TblHeader', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=9, leading=12,
        textColor=colors.white
    )
    tbl_cell_style = ParagraphStyle(
        'TblCell', parent=body_style, fontSize=8, leading=11
    )
    tbl_cell_bold_style = ParagraphStyle(
        'TblCellBold', parent=tbl_cell_style, fontName='Helvetica-Bold'
    )
    code_style = ParagraphStyle(
        'CodeStyleCustom', parent=styles['Normal'],
        fontName='Courier', fontSize=7, leading=9,
        textColor=colors.HexColor("#1F2937")
    )
    small_style = ParagraphStyle(
        'Small', parent=body_style, fontSize=7.5, leading=10,
        textColor=colors.HexColor("#374151")
    )
    compliance_style = ParagraphStyle(
        'Compliance', parent=body_style, fontSize=7.5, leading=10,
        textColor=colors.HexColor("#1D4ED8"), leftIndent=8
    )

    story = []

    # ── COVER / HEADER ────────────────────────────────────────────────────────
    story.append(Paragraph("DEPTHCHARGE SECURITY AUDIT", title_style))
    story.append(Paragraph(
        f"Automated Dependency Reputation &amp; Static/Dynamic Threat Analysis Report<br/>"
        f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style
    ))

    # ── METRICS GRID ─────────────────────────────────────────────────────────
    total = len(results)
    high  = sum(1 for r in results.values() if r.get("risk_level") == "High")
    medium = sum(1 for r in results.values() if r.get("risk_level") == "Medium")
    low   = sum(1 for r in results.values() if r.get("risk_level") == "Low")
    blocked = sum(1 for r in results.values() if r.get("remediation"))

    metrics_data = [
        [Paragraph(f"<b>{lbl}</b>", tbl_header_style) for lbl in
         ["TOTAL", "HIGH RISK", "MEDIUM RISK", "LOW RISK"]],
        [Paragraph(f"<font size=20><b>{v}</b></font>", tbl_header_style)
         for v in [total, high, medium, low]]
    ]
    metrics_table = Table(metrics_data, colWidths=[126, 126, 126, 126])
    metrics_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,0), (0,1), colors.HexColor("#3B82F6")),
        ('BACKGROUND', (1,0), (1,1), colors.HexColor("#EF4444")),
        ('BACKGROUND', (2,0), (2,1), colors.HexColor("#F59E0B")),
        ('BACKGROUND', (3,0), (3,1), colors.HexColor("#10B981")),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('INNERGRID', (0,0), (-1,-1), 1.5, colors.white),
        ('BOX', (0,0), (-1,-1), 1.5, colors.white),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 20))

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_style))

    # Collect unique MITRE techniques across all results
    all_mitre = {}
    for r in results.values():
        static = r.get("static") or {}
        for a in static.get("alerts", []):
            mid = a.get("mitre_id")
            if mid and mid != "T0000":
                all_mitre[mid] = a.get("mitre_technique", "")

    # Build summary prose
    blocked_pkgs = [pkg for pkg, r in results.items() if r.get("risk_level") == "High"]
    changed_pkgs = [
        pkg for pkg, r in results.items()
        if (r.get("reputation") or {}).get("maintainer_changed")
    ]
    ioc_pkgs = [
        pkg for pkg, r in results.items()
        if (r.get("static") or {}).get("ioc_matches")
    ]
    taint_pkgs = [
        pkg for pkg, r in results.items()
        if (r.get("static") or {}).get("taint_flows_detected")
    ]

    exec_lines = [
        f"<b>Total packages scanned:</b> {total}",
        f"<b>High-risk (blocked):</b> {high} package(s)" +
            (f" — {', '.join(blocked_pkgs[:5])}" if blocked_pkgs else ""),
        f"<b>Medium risk:</b> {medium} package(s)",
        f"<b>Low / clean:</b> {low} package(s)",
    ]
    if blocked:
        exec_lines.append(f"<b>Packages with remediation guidance:</b> {blocked}")
    if changed_pkgs:
        exec_lines.append(
            f"<b>⚠ Maintainer change detected:</b> {', '.join(changed_pkgs)} — investigate for account takeover."
        )
    if ioc_pkgs:
        exec_lines.append(
            f"<b>⚠ Direct IoC matches (C2/token/exfil):</b> {', '.join(ioc_pkgs)} — treat as active threat."
        )
    if taint_pkgs:
        exec_lines.append(
            f"<b>Taint-flow confirmed:</b> External data reaches dangerous sinks in: {', '.join(taint_pkgs)}."
        )
    if all_mitre:
        techniques_str = ", ".join(
            f"{mid} ({name})" for mid, name in list(all_mitre.items())[:6]
        )
        exec_lines.append(f"<b>ATT&amp;CK techniques observed:</b> {techniques_str}.")

    for line in exec_lines:
        story.append(Paragraph(f"• {line}", bullet_style))
    story.append(Spacer(1, 12))

    # ── DEPENDENCIES CHECKLIST ────────────────────────────────────────────────
    story.append(Paragraph("Dependencies Checklist Summary", h1_style))

    summary_data = [[
        Paragraph("Package Name", tbl_header_style),
        Paragraph("Ecosystem", tbl_header_style),
        Paragraph("Version", tbl_header_style),
        Paragraph("Score", tbl_header_style),
        Paragraph("Risk Level", tbl_header_style),
    ]]
    for pkg, r in results.items():
        rep = r.get("reputation") or {}
        eco   = str(rep.get("ecosystem", "unknown")).upper()
        ver   = str(rep.get("version", "Unknown"))
        score = r.get("score", 0)
        level = r.get("risk_level", "Unknown")
        risk_color_hex = (
            "#EF4444" if level == "High" else
            "#F59E0B" if level == "Medium" else "#10B981"
        )
        summary_data.append([
            Paragraph(f"<b>{pkg}</b>", tbl_cell_style),
            Paragraph(eco, tbl_cell_style),
            Paragraph(ver, tbl_cell_style),
            Paragraph(f"<b>{score}/100</b>", tbl_cell_style),
            Paragraph(f"<font color='{risk_color_hex}'><b>{level}</b></font>", tbl_cell_style),
        ])

    summary_table = Table(summary_data, colWidths=[174, 80, 80, 80, 90])
    tbl_styles = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
    ]
    for i in range(1, len(summary_data)):
        if i % 2 == 0:
            tbl_styles.append(('BACKGROUND', (0,i), (-1,i), colors.HexColor("#F9FAFB")))
    summary_table.setStyle(TableStyle(tbl_styles))
    story.append(summary_table)

    # ── DETAILED PACKAGE AUDIT ────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Detailed Vulnerability &amp; Code Analysis", h1_style))
    story.append(Spacer(1, 10))

    for pkg, r in results.items():
        pkg_story = []

        rep     = r.get("reputation") or {}
        static  = r.get("static") or {}
        dynamic = r.get("dynamic") or {}
        eco   = str(rep.get("ecosystem", "unknown")).upper()
        ver   = str(rep.get("version", "Unknown"))
        score = r.get("score", 0)
        level = r.get("risk_level", "Unknown")
        alerts = static.get("alerts") or []
        vulns  = rep.get("vulnerabilities") or []
        events = dynamic.get("events") or []

        # Package header
        score_color = get_risk_color(level)
        header_data = [[
            Paragraph(f"{pkg} <font color='#6B7280' size=10>({eco} v{ver})</font>", h2_style),
            Paragraph(f"<font color='white'><b>RISK: {score}/100 ({level})</b></font>", tbl_header_style)
        ]]
        header_table = Table(header_data, colWidths=[360, 144])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (1,0), (1,0), score_color),
            ('ALIGN', (1,0), (1,0), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('LINEBELOW', (0,0), (-1,0), 1.5, colors.HexColor("#1E3A8A")),
        ]))
        pkg_story.append(header_table)
        pkg_story.append(Spacer(1, 6))

        # Evaluation log
        pkg_story.append(Paragraph("<b>Audit Evaluation Log:</b>", body_style))
        reasons = r.get("reasons") or ["No suspicious behaviour detected."]
        for reason in reasons:
            pkg_story.append(Paragraph(f"• {reason}", bullet_style))
        pkg_story.append(Spacer(1, 8))

        # Remediation block (if blocked)
        remediation = r.get("remediation")
        if remediation:
            rem_data = [[Paragraph(f"<b>Remediation Guidance</b>", tbl_cell_bold_style)],
                        [Paragraph(remediation, tbl_cell_style)]]
            rem_table = Table(rem_data, colWidths=[504])
            rem_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#FEF2F2")),
                ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#FFF5F5")),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#FCA5A5")),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            pkg_story.append(rem_table)
            pkg_story.append(Spacer(1, 8))

        # Metadata + vulns grid
        created_date = rep.get("created_at", "Unknown")
        if isinstance(created_date, str) and "T" in created_date:
            created_date = created_date.split("T")[0]

        maintainer_note = ""
        if rep.get("maintainer_changed"):
            prev_email = rep.get("previous_maintainer_email", "unknown")
            curr_email = rep.get("author_email", "unknown")
            maintainer_note = (
                f"<br/><font color='#EF4444'><b>⚠ Maintainer changed: "
                f"{prev_email} → {curr_email}</b></font>"
            )

        meta_html = (
            f"<b>Author:</b> {rep.get('author', 'Unknown')}<br/>"
            f"<b>Email:</b> {rep.get('author_email', 'Unknown')}<br/>"
            f"<b>Created:</b> {created_date}<br/>"
            f"<b>Releases:</b> {rep.get('releases_count', 0)}"
            f"{maintainer_note}"
        )

        is_typosquat = rep.get("typosquatting_detected") or bool(static.get("typosquatting"))
        typo_target  = (rep.get("typosquatting_info") or static.get("typosquatting") or {}).get("target", "a known package")

        vulns_html = (
            "<br/>".join([f"• <b>{v.get('id')}</b>: {v.get('summary', 'No summary')}" for v in vulns[:5]])
            + (f"<br/>• <i>...and {len(vulns)-5} more</i>" if len(vulns) > 5 else "")
        ) if vulns else (
            f"<font color='#F59E0B'>⚠ Package does not exist on PyPI — CVE lookup not applicable (typosquatting of '{typo_target}').</font>"
            if is_typosquat else
            "<font color='#10B981'>✓ No known CVE or GHSA vulnerabilities in OSV.</font>"
        )

        grid_data = [
            [Paragraph("<b>Registry Metadata</b>", tbl_cell_bold_style),
             Paragraph(f"<b>Known Vulnerabilities ({len(vulns)})</b>", tbl_cell_bold_style)],
            [Paragraph(meta_html, tbl_cell_style),
             Paragraph(vulns_html, tbl_cell_style)]
        ]
        grid_table = Table(grid_data, colWidths=[247, 247])
        grid_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (1,0), colors.HexColor("#F3F4F6")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        pkg_story.append(grid_table)
        pkg_story.append(Spacer(1, 8))

        # Static alerts (with MITRE tags inline)
        static_html = ""
        if alerts:
            alert_cap = 15
            for a in alerts[:alert_cap]:
                sev  = str(a.get("severity", "medium")).upper()
                msg  = a.get("message", "")
                loc  = f"{a.get('file', '?')}:{a.get('line', 0)}"
                mid  = a.get("mitre_id", "")
                conf = a.get("confidence", "")
                tag  = f" <font color='#6366F1'>[{mid}]</font>" if mid and mid != "T0000" else ""
                ctag = f" <font color='#9CA3AF'>(confidence: {conf})</font>" if conf else ""
                static_html += f"• <b>[{sev}]</b>{tag}{ctag} <font face='Courier' size=7>{loc}</font>: {msg}<br/>"
            if len(alerts) > alert_cap:
                static_html += f"• <i>...and {len(alerts)-alert_cap} more alerts (truncated)</i>"
        else:
            static_html = "<font color='#10B981'>✓ No suspicious static syntax pattern triggers.</font>"

        # Dynamic events
        dynamic_html = ""
        if events:
            dynamic_html = "<br/>".join(
                [f"• <b>{e.get('type','event').upper()}</b>: {e.get('details','')}" for e in events[:10]]
            )
            if len(events) > 10:
                dynamic_html += f"<br/>• <i>...and {len(events)-10} more events</i>"
        else:
            if not dynamic.get("docker_available"):
                dynamic_html = "<font color='#F59E0B'>⚠ Dynamic scan skipped (Docker unavailable).</font>"
            elif not dynamic.get("installation_success"):
                dynamic_html = "<font color='#EF4444'>❌ Package installation failed in sandbox.</font>"
            else:
                dynamic_html = "<font color='#10B981'>✓ No unexpected filesystem, network, or process spawning activities.</font>"

        scan_grid_data = [
            [Paragraph(f"<b>Static AST Analysis ({len(alerts)} alerts)</b>", tbl_cell_bold_style),
             Paragraph(f"<b>Dynamic Sandbox Events ({len(events)})</b>", tbl_cell_bold_style)],
            [Paragraph(static_html, tbl_cell_style),
             Paragraph(dynamic_html, tbl_cell_style)]
        ]
        scan_grid_table = Table(scan_grid_data, colWidths=[247, 247])
        scan_grid_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (1,0), colors.HexColor("#F3F4F6")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        pkg_story.append(scan_grid_table)
        pkg_story.append(Spacer(1, 8))

        # MITRE ATT&CK + Compliance section
        pkg_mitre = {}
        for a in alerts:
            mid = a.get("mitre_id")
            if mid and mid != "T0000":
                pkg_mitre[mid] = a.get("mitre_technique", "")

        if pkg_mitre:
            pkg_story.append(Paragraph("<b>MITRE ATT&amp;CK Mapping &amp; Compliance Controls</b>", body_style))
            pkg_story.append(Spacer(1, 4))

            compliance_rows = [
                [
                    Paragraph("<b>Technique</b>", tbl_cell_bold_style),
                    Paragraph("<b>Name</b>", tbl_cell_bold_style),
                    Paragraph("<b>Regulatory Controls</b>", tbl_cell_bold_style),
                ]
            ]
            for mid, tname in pkg_mitre.items():
                mapping = MITRE_COMPLIANCE_MAP.get(mid, {})
                controls = mapping.get("controls", [])
                controls_html = "<br/>".join(
                    [f"<font color='#1D4ED8'>{fw}:</font> {ctrl}" for fw, ctrl in controls]
                ) if controls else "—"
                compliance_rows.append([
                    Paragraph(f"<b><font color='#6366F1'>{mid}</font></b>", small_style),
                    Paragraph(tname or mapping.get("name", ""), small_style),
                    Paragraph(controls_html, small_style),
                ])

            comp_table = Table(compliance_rows, colWidths=[70, 180, 254])
            comp_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EEF2FF")),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#C7D2FE")),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            pkg_story.append(comp_table)
            pkg_story.append(Spacer(1, 8))

        pkg_story.append(Spacer(1, 12))

        try:
            story.append(KeepTogether(pkg_story))
        except Exception:
            story.extend(pkg_story)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF report successfully saved to {output_path}")
