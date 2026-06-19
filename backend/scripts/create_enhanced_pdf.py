#!/usr/bin/env python3
"""
Create a professional enhanced PDF with SVG dashboard and report
"""
import os
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image, KeepTogether
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from io import BytesIO
import subprocess

def create_enhanced_pdf():
    """Create enhanced PDF with charts and professional styling"""
    
    pdf_file = "reports/MITRE_ATT_CK_Coverage_Report_DECORATED_20260418.pdf"
    
    # Use landscape for better chart display
    doc = SimpleDocTemplate(
        pdf_file, 
        pagesize=landscape(letter),
        rightMargin=0.4*inch, 
        leftMargin=0.4*inch, 
        topMargin=0.4*inch, 
        bottomMargin=0.4*inch
    )
    
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1565c0'),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#666666'),
        spaceAfter=4,
        alignment=TA_CENTER,
        fontName='Helvetica'
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1565c0'),
        spaceAfter=6,
        spaceBefore=12,
        fontName='Helvetica-Bold',
        borderColor=colors.HexColor('#1565c0'),
        borderWidth=0,
        borderPadding=4,
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=9,
        alignment=TA_JUSTIFY,
        spaceAfter=4
    )
    
    # PAGE 1: Title & Executive Summary
    story.append(Paragraph("MITRE ATT&CK Coverage Analysis", title_style))
    story.append(Paragraph("Infosec-Sentinel-LAW Workspace", subtitle_style))
    story.append(Paragraph("Generated: April 18, 2026 | Analysis Period: Last 90 Days", subtitle_style))
    story.append(Spacer(1, 0.15*inch))
    
    # KPI Summary Table
    kpi_data = [
        [
            Paragraph('<b>Initial Access</b><br/>100% Coverage<br/><font color="green">✓ STRONG</font>', normal_style), 
            Paragraph('<b>Overall Coverage</b><br/>35%<br/><font color="orange">⚠ MODERATE</font>', normal_style), 
            Paragraph('<b>Active Rules</b><br/>27 Rules<br/><font color="blue">→ DEPLOYED</font>', normal_style)
        ],
        [
            Paragraph('<b>Incidents Analyzed</b><br/>2,574 Total<br/><font color="gray">90 days</font>', normal_style), 
            Paragraph('<b>Critical Gaps</b><br/>4 Tactics<br/><font color="red">✗ NO COVERAGE</font>', normal_style), 
            Paragraph('<b>Priority Action</b><br/>Lateral Movement<br/><font color="red">URGENT</font>', normal_style)
        ]
    ]
    
    kpi_table = Table(kpi_data, colWidths=[2.2*inch, 2.2*inch, 2.2*inch])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9f9f9')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#f5f5f5')]),
    ]))
    
    story.append(kpi_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Executive Summary
    story.append(Paragraph("<b>Executive Summary</b>", heading2_style))
    story.append(Paragraph(
        """Your Sentinel workspace demonstrates <b>excellent coverage of Initial Access attacks</b> (99.5% of detections), 
        but has <b>critical gaps in post-breach visibility</b>. An attacker who passes Initial Access defenses would operate 
        with minimal detection risk. The coverage distribution is heavily skewed toward credential-based and phishing attacks, 
        leaving significant blind spots in lateral movement, persistence, command & control, and data exfiltration scenarios.""",
        normal_style
    ))
    story.append(Spacer(1, 0.1*inch))
    
    # Try to embed SVG dashboard as image
    try:
        # Convert SVG to PNG for PDF embedding
        svg_file = "reports/MITRE_Dashboard_20260418.svg"
        png_file = "reports/MITRE_Dashboard_20260418.png"
        
        # Use ImageMagick or similar if available, otherwise just show the SVG
        if os.path.exists(svg_file):
            story.append(Paragraph("<b>Visual Dashboard - Coverage Heatmap & Metrics</b>", heading2_style))
            story.append(Spacer(1, 0.1*inch))
            
            # Add text note about viewing the SVG
            story.append(Paragraph(
                "📊 A visual dashboard with charts and graphs is available in: <b>reports/MITRE_Dashboard_20260418.svg</b><br/>" +
                "Open this file in any web browser or SVG viewer for interactive visualization of coverage metrics, " +
                "tactic distribution charts, and heatmaps.",
                normal_style
            ))
            story.append(Spacer(1, 0.15*inch))
    except:
        pass
    
    # Coverage by Tactic Table
    story.append(Paragraph("<b>Coverage Scorecard by Tactic</b>", heading2_style))
    
    coverage_data = [
        [Paragraph('<b>Tactic</b>', normal_style), Paragraph('<b>Coverage</b>', normal_style), Paragraph('<b>Incidents</b>', normal_style), Paragraph('<b>Status</b>', normal_style), Paragraph('<b>Priority</b>', normal_style)],
        [Paragraph('Initial Access', normal_style), Paragraph('100%', normal_style), Paragraph('2,562', normal_style), Paragraph('✓ STRONG', normal_style), Paragraph('Maintained', normal_style)],
        [Paragraph('Persistence', normal_style), Paragraph('20%', normal_style), Paragraph('4', normal_style), Paragraph('⚠ WEAK', normal_style), Paragraph('🔴 CRITICAL', normal_style)],
        [Paragraph('Privilege Escalation', normal_style), Paragraph('20%', normal_style), Paragraph('4', normal_style), Paragraph('⚠ WEAK', normal_style), Paragraph('🔴 CRITICAL', normal_style)],
        [Paragraph('Discovery', normal_style), Paragraph('20%', normal_style), Paragraph('~2', normal_style), Paragraph('⚠ WEAK', normal_style), Paragraph('🟠 HIGH', normal_style)],
        [Paragraph('Lateral Movement', normal_style), Paragraph('0%', normal_style), Paragraph('0', normal_style), Paragraph('✗ NONE', normal_style), Paragraph('🔴 CRITICAL', normal_style)],
        [Paragraph('Command & Control', normal_style), Paragraph('0%', normal_style), Paragraph('0', normal_style), Paragraph('✗ NONE', normal_style), Paragraph('🔴 CRITICAL', normal_style)],
        [Paragraph('Exfiltration', normal_style), Paragraph('0%', normal_style), Paragraph('0', normal_style), Paragraph('✗ NONE', normal_style), Paragraph('🔴 CRITICAL', normal_style)],
        [Paragraph('Defense Evasion', normal_style), Paragraph('0%', normal_style), Paragraph('0', normal_style), Paragraph('✗ NONE', normal_style), Paragraph('🟠 HIGH', normal_style)],
        [Paragraph('Credential Access', normal_style), Paragraph('0%', normal_style), Paragraph('0', normal_style), Paragraph('✗ NONE', normal_style), Paragraph('🟠 HIGH', normal_style)],
        [Paragraph('Impact', normal_style), Paragraph('0%', normal_style), Paragraph('0', normal_style), Paragraph('✗ NONE', normal_style), Paragraph('🟠 HIGH', normal_style)],
    ]
    
    coverage_table = Table(coverage_data, colWidths=[1.8*inch, 1.2*inch, 1.2*inch, 1.4*inch, 1.2*inch])
    coverage_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1565c0')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#f9f9f9')]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    story.append(coverage_table)
    story.append(Spacer(1, 0.15*inch))
    
    # Page break before recommendations
    story.append(PageBreak())
    
    # PAGE 2: Detailed Findings & Recommendations
    story.append(Paragraph("Detailed Findings & Recommendations", title_style))
    story.append(Spacer(1, 0.15*inch))
    
    # Critical Gaps Section
    story.append(Paragraph("<b>🔴 Critical Coverage Gaps (Immediate Action Required)</b>", heading2_style))
    
    gaps = [
        ("<b>Lateral Movement (T1021)</b><br/>Gap: RDP, SSH, WinRM lateral movement invisible<br/>Impact: Once attackers gain initial access, they spread undetected", 
         "1. Deploy RDP lateral movement detection<br/>2. Monitor WinRM/PSExec execution<br/>3. Track SSH lateral movement patterns"),
        
        ("<b>Persistence Mechanisms (T1098, T1136, T1556)</b><br/>Gap: OAuth permissions, forwarding rules, app registrations not monitored<br/>Impact: Attackers maintain long-term access",
         "1. Monitor Office 365 forwarding rules<br/>2. Track Azure app permission changes<br/>3. Alert on OAuth consent grants"),
        
        ("<b>Command & Control (T1071, T1205)</b><br/>Gap: C2 callbacks and DNS tunneling invisible<br/>Impact: Active breach callbacks undetected",
         "1. Implement DNS query anomaly detection<br/>2. Monitor HTTPS C2 beaconing patterns<br/>3. Track unusual connection volumes"),
    ]
    
    for i, (gap, remediation) in enumerate(gaps):
        story.append(Paragraph(gap, normal_style))
        story.append(Paragraph("<b>Remediation Steps:</b><br/>" + remediation, normal_style))
        story.append(Spacer(1, 0.1*inch))
    
    story.append(Spacer(1, 0.15*inch))
    
    # Implementation Roadmap
    story.append(Paragraph("<b>Implementation Roadmap</b>", heading2_style))
    
    roadmap_data = [
        [Paragraph('<b>Phase</b>', normal_style), Paragraph('<b>Timeline</b>', normal_style), Paragraph('<b>Objective</b>', normal_style), Paragraph('<b>Rules</b>', normal_style), Paragraph('<b>Expected Improvement</b>', normal_style)],
        [Paragraph('Phase 1', normal_style), Paragraph('Week 1-2', normal_style), Paragraph('Lateral Movement', normal_style), Paragraph('2-3 rules', normal_style), Paragraph('35% → 45%', normal_style)],
        [Paragraph('Phase 2', normal_style), Paragraph('Week 3-4', normal_style), Paragraph('Persistence', normal_style), Paragraph('2-3 rules', normal_style), Paragraph('45% → 55%', normal_style)],
        [Paragraph('Phase 3', normal_style), Paragraph('Week 5-6', normal_style), Paragraph('C2 & Exfil', normal_style), Paragraph('2-3 rules', normal_style), Paragraph('55% → 70%', normal_style)],
        [Paragraph('Phase 4', normal_style), Paragraph('Week 7-8', normal_style), Paragraph('Optimization', normal_style), Paragraph('Tune rules', normal_style), Paragraph('70% → 80%+', normal_style)],
    ]
    
    roadmap_table = Table(roadmap_data, colWidths=[1.0*inch, 1.2*inch, 1.4*inch, 1.6*inch, 1.6*inch])
    roadmap_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ff9800')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#fff9e6')]),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
    ]))
    
    story.append(roadmap_table)
    story.append(Spacer(1, 0.15*inch))
    
    # Bottom Assessment Box
    story.append(Paragraph("<b>Overall Security Posture Assessment</b>", heading2_style))
    assessment_data = [[
        Paragraph("""<b>Current Status:</b> MODERATE RISK (35% Coverage)<br/><br/>
        <b>Strengths:</b> Excellent initial access detection with 2,562 incidents captured. Strong credential and phishing monitoring.<br/><br/>
        <b>Weaknesses:</b> Critical blind spots in post-breach visibility. Zero coverage for lateral movement, C2, and exfiltration.<br/><br/>
        <b>Recommendation:</b> Deploy Phase 1 (Lateral Movement) immediately. An attacker with initial access operates undetected in your environment today.<br/><br/>
        <b>Timeline to Acceptable Risk:</b> 4-6 weeks with consistent deployment of recommended rules. Target: 70%+ coverage.
        """, normal_style)
    ]]
    
    assessment_table = Table(assessment_data, colWidths=[6.8*inch])
    assessment_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fce4ec')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 12),
        ('BORDER', (0, 0), (-1, -1), 2, colors.HexColor('#c2185b')),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ('RIGHTPADDING', (0, 0), (-1, -1), 15),
    ]))
    
    story.append(assessment_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Footer
    footer_text = "Report Generated: April 18, 2026 | Workspace: Infosec-Sentinel-LAW | Next Review: May 18, 2026"
    story.append(Paragraph(footer_text, subtitle_style))
    
    # Build PDF
    doc.build(story)
    print(f"✅ Enhanced PDF generated: {pdf_file}")
    print(f"📊 Dashboard SVG available: reports/MITRE_Dashboard_20260418.svg")

if __name__ == "__main__":
    create_enhanced_pdf()
