import os
import sys
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total page count
    along with headers, footers, and dividing lines.
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
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        # Skip headers and footers on the first page
        if self._pageNumber == 1:
            return
        
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#4B5563")) # gray-600
        
        # Header text
        self.drawString(54, 750, "DEPTHCHARGE SECURITY AUDIT REPORT")
        self.drawRightString(558, 750, f"GENERATED: {datetime.now().strftime('%Y-%m-%d')}")
        
        # Header Line
        self.setStrokeColor(colors.HexColor("#E5E7EB")) # gray-200
        self.setLineWidth(0.75)
        self.line(54, 742, 558, 742)
        
        # Footer Line
        self.line(54, 54, 558, 54)
        
        # Footer Text
        self.setFont("Helvetica", 8)
        self.drawString(54, 40, "Confidential - Depthcharge Dependency Threat Analyzer")
        self.drawRightString(558, 40, f"Page {self._pageNumber} of {page_count}")
        
        self.restoreState()


def get_risk_color(level):
    level = str(level).lower()
    if level == "high":
        return colors.HexColor("#EF4444") # Red
    elif level == "medium":
        return colors.HexColor("#F59E0B") # Amber
    elif level == "low":
        return colors.HexColor("#10B981") # Green
    return colors.HexColor("#6B7280") # Gray


def generate_pdf_report(results, output_path):
    """
    Generates a high-quality PDF report using ReportLab.
    results is a dict: { package_name: scan_result_dict }
    """
    # Create directory if it doesn't exist
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Document setup (Letter, margins 54pt/0.75in)
    # Content area width = 612 - 108 = 504
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=75,
        bottomMargin=75
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=30,
        textColor=colors.HexColor("#1E3A8A"), # Navy
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4B5563"), # Gray 600
        spaceAfter=25
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=20,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'PackageH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1F2937") # Gray 800
    )
    
    bullet_style = ParagraphStyle(
        'BulletCustom',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    tbl_header_style = ParagraphStyle(
        'TblHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.white
    )
    
    tbl_cell_style = ParagraphStyle(
        'TblCell',
        parent=body_style,
        fontSize=8,
        leading=11
    )
    
    tbl_cell_bold_style = ParagraphStyle(
        'TblCellBold',
        parent=tbl_cell_style,
        fontName='Helvetica-Bold'
    )

    code_style = ParagraphStyle(
        'CodeStyleCustom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#1F2937")
    )
    
    code_alert_style = ParagraphStyle(
        'CodeAlertStyleCustom',
        parent=code_style,
        textColor=colors.HexColor("#DC2626") # red-600
    )

    story = []

    # ------------------ COVER PAGE / FIRST PAGE HEADER ------------------
    story.append(Paragraph("DEPTHCHARGE SECURITY AUDIT", title_style))
    story.append(Paragraph(
        f"Automated Dependency Reputation & Static/Dynamic Threat Analysis Report<br/>"
        f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style
    ))
    
    # ------------------ EXECUTIVE METRICS GRID ------------------
    total = len(results)
    high = sum(1 for r in results.values() if r.get("risk_level") == "High")
    medium = sum(1 for r in results.values() if r.get("risk_level") == "Medium")
    low = sum(1 for r in results.values() if r.get("risk_level") == "Low")
    
    metrics_data = [
        [
            Paragraph("<b>TOTAL</b>", tbl_header_style),
            Paragraph("<b>HIGH RISK</b>", tbl_header_style),
            Paragraph("<b>MEDIUM RISK</b>", tbl_header_style),
            Paragraph("<b>LOW RISK</b>", tbl_header_style)
        ],
        [
            Paragraph(f"<font size=20><b>{total}</b></font>", tbl_header_style),
            Paragraph(f"<font size=20><b>{high}</b></font>", tbl_header_style),
            Paragraph(f"<font size=20><b>{medium}</b></font>", tbl_header_style),
            Paragraph(f"<font size=20><b>{low}</b></font>", tbl_header_style)
        ]
    ]
    
    metrics_table = Table(metrics_data, colWidths=[126, 126, 126, 126])
    metrics_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,0), (0,1), colors.HexColor("#3B82F6")), # Blue
        ('BACKGROUND', (1,0), (1,1), colors.HexColor("#EF4444")), # Red
        ('BACKGROUND', (2,0), (2,1), colors.HexColor("#F59E0B")), # Amber
        ('BACKGROUND', (3,0), (3,1), colors.HexColor("#10B981")), # Green
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('INNERGRID', (0,0), (-1,-1), 1.5, colors.white),
        ('BOX', (0,0), (-1,-1), 1.5, colors.white),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 20))
    
    # ------------------ DEPENDENCIES SUMMARY TABLE ------------------
    story.append(Paragraph("Dependencies Checklist Summary", h1_style))
    
    summary_data = [[
        Paragraph("Package Name", tbl_header_style),
        Paragraph("Ecosystem", tbl_header_style),
        Paragraph("Version", tbl_header_style),
        Paragraph("Score", tbl_header_style),
        Paragraph("Risk Level", tbl_header_style)
    ]]
    
    for pkg, r in results.items():
        # Safely handle missing/null data structures
        rep = r.get("reputation") or {}
        eco = str(rep.get("ecosystem", "unknown")).upper()
        ver = str(rep.get("version", "Unknown"))
        score = r.get("score", 0)
        level = r.get("risk_level", "Unknown")
        
        # Risk color
        risk_color_hex = "#10B981" # Green
        if level == "High":
            risk_color_hex = "#EF4444"
        elif level == "Medium":
            risk_color_hex = "#F59E0B"
            
        summary_data.append([
            Paragraph(f"<b>{pkg}</b>", tbl_cell_style),
            Paragraph(eco, tbl_cell_style),
            Paragraph(ver, tbl_cell_style),
            Paragraph(f"<b>{score}/100</b>", tbl_cell_style),
            Paragraph(f"<font color='{risk_color_hex}'><b>{level}</b></font>", tbl_cell_style)
        ])
        
    summary_table = Table(summary_data, colWidths=[174, 80, 80, 80, 90])
    
    # Generate alternating rows styles
    table_styles = [
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
            table_styles.append(('BACKGROUND', (0,i), (-1,i), colors.HexColor("#F9FAFB")))
            
    summary_table.setStyle(TableStyle(table_styles))
    story.append(summary_table)
    
    # ------------------ DETAILED PACKAGE AUDIT SECTION ------------------
    story.append(PageBreak())
    story.append(Paragraph("Detailed Vulnerability & Code Analysis", h1_style))
    story.append(Spacer(1, 10))
    
    for pkg, r in results.items():
        pkg_story = []
        
        rep = r.get("reputation") or {}
        eco = str(rep.get("ecosystem", "unknown")).upper()
        ver = str(rep.get("version", "Unknown"))
        score = r.get("score", 0)
        level = r.get("risk_level", "Unknown")
        
        # Package Title & Score
        score_color = get_risk_color(level)
        pkg_title = f"{pkg} <font color='#6B7280' size=10>({eco} v{ver})</font>"
        
        header_data = [
            [
                Paragraph(pkg_title, h2_style),
                Paragraph(f"<font color='white'><b>RISK: {score}/100 ({level})</b></font>", tbl_header_style)
            ]
        ]
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
        
        # Evaluation Log
        pkg_story.append(Paragraph("<b>Audit Evaluation Log:</b>", body_style))
        reasons = r.get("reasons") or ["No suspicious behavior or vulnerabilities detected."]
        for reason in reasons:
            pkg_story.append(Paragraph(f"• {reason}", bullet_style))
        pkg_story.append(Spacer(1, 8))
        
        # Metadata Grid (Metadata & Vulnerabilities)
        vulns = rep.get("vulnerabilities") or []
        created_date = rep.get("created_at", "Unknown")
        if "T" in created_date:
            created_date = created_date.split("T")[0]
            
        meta_html = (
            f"<b>Author:</b> {rep.get('author', 'Unknown')}<br/>"
            f"<b>Email:</b> {rep.get('author_email', 'Unknown')}<br/>"
            f"<b>Created Date:</b> {created_date}<br/>"
            f"<b>Releases Count:</b> {rep.get('releases_count', 0)}"
        )
        
        vulns_html = ""
        if vulns:
            vulns_html = "<br/>".join([f"• <b>{v.get('id')}</b>: {v.get('summary', 'No summary')}" for v in vulns[:5]])
            if len(vulns) > 5:
                vulns_html += f"<br/>• <i>...and {len(vulns) - 5} more vulnerabilities</i>"
        else:
            vulns_html = "<font color='#10B981'>✓ No known CVE or GHSA vulnerabilities in OSV.</font>"
            
        grid_data = [
            [Paragraph("<b>Registry Metadata</b>", tbl_cell_bold_style), Paragraph(f"<b>Known Vulnerabilities ({len(vulns)})</b>", tbl_cell_bold_style)],
            [Paragraph(meta_html, tbl_cell_style), Paragraph(vulns_html, tbl_cell_style)]
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
        
        # Static & Dynamic Scan Alerts
        static = r.get("static") or {}
        alerts = static.get("alerts") or []
        
        static_html = ""
        if alerts:
            # Cap at 15 items to prevent huge page counts
            alert_cap = 15
            static_html = ""
            for a in alerts[:alert_cap]:
                sev = str(a.get("severity", "medium")).upper()
                msg = a.get("message", "")
                loc = f"{a.get('file', 'file')}:{a.get('line', 0)}"
                static_html += f"• <b>[{sev}]</b> <font face='Courier' size=7>{loc}</font>: {msg}<br/>"
            if len(alerts) > alert_cap:
                static_html += f"• <i>...and {len(alerts) - alert_cap} more alerts (static scan truncated for readability)</i>"
        else:
            static_html = "<font color='#10B981'>✓ No suspicious static syntax pattern triggers.</font>"
            
        dynamic = r.get("dynamic") or {}
        events = dynamic.get("events") or []
        dynamic_html = ""
        if events:
            dynamic_html = "<br/>".join([f"• <b>{e.get('type', 'event').upper()}</b>: {e.get('details', '')}" for e in events[:10]])
            if len(events) > 10:
                dynamic_html += f"<br/>• <i>...and {len(events) - 10} more sandbox runtime events</i>"
        else:
            if not dynamic.get("docker_available"):
                dynamic_html = "<font color='#F59E0B'>⚠ Dynamic scan skipped (Docker unavailable).</font>"
            elif not dynamic.get("installation_success"):
                dynamic_html = "<font color='#EF4444'>❌ Package installation failed in sandbox.</font>"
            else:
                dynamic_html = "<font color='#10B981'>✓ No unexpected filesystem, network, or process spawning activities.</font>"
                
        scan_grid_data = [
            [Paragraph(f"<b>Static AST Analysis ({len(alerts)})</b>", tbl_cell_bold_style), Paragraph(f"<b>Dynamic Sandbox Events ({len(events)})</b>", tbl_cell_bold_style)],
            [Paragraph(static_html, tbl_cell_style), Paragraph(dynamic_html, tbl_cell_style)]
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
        pkg_story.append(Spacer(1, 20))
        
        # We wrap each package audit in KeepTogether to keep it cohesive, or at least major portions of it.
        # Since static scan can be very long (even capped at 15 it could be large), we keep the core info together.
        try:
            story.append(KeepTogether(pkg_story))
        except Exception:
            # Fallback if too large for KeepTogether
            story.extend(pkg_story)
            
    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF report successfully saved to {output_path}")

