#!/usr/bin/env python3
"""
Create a professional SVG dashboard for MITRE ATT&CK coverage report
with charts, graphs, and visual elements
"""
import json
from datetime import datetime

def create_mitre_dashboard():
    """Generate SVG dashboard with charts and visual elements"""
    
    # Dashboard configuration
    width = 1400
    height = 1600
    padding = 20
    
    svg_parts = []
    
    # Header
    svg_parts.append(f'''<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <style>
      .title-text {{ font-size: 32px; font-weight: bold; fill: #ffffff; }}
      .subtitle-text {{ font-size: 14px; fill: #b0b0b0; }}
      .label-text {{ font-size: 12px; fill: #ffffff; font-weight: 500; }}
      .value-text {{ font-size: 24px; font-weight: bold; fill: #00b4d8; }}
      .small-text {{ font-size: 11px; fill: #808080; }}
      .chart-axis {{ font-size: 10px; fill: #666666; }}
      .strong {{ font-weight: bold; fill: #ffffff; }}
    </style>
    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#0d47a1;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#1565c0;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="greenGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#4caf50;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#45a049;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="orangeGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#ff9800;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#f57c00;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="redGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#f44336;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#d32f2f;stop-opacity:1" />
    </linearGradient>
  </defs>
  
  <!-- Background -->
  <rect width="{width}" height="{height}" fill="#0f0f0f"/>
  
  <!-- Header Banner -->
  <rect y="0" width="{width}" height="100" fill="url(#headerGrad)"/>
  <text x="40" y="45" class="title-text">MITRE ATT&CK Coverage Analysis</text>
  <text x="40" y="70" class="subtitle-text">Infosec-Sentinel-LAW Workspace | Generated: April 18, 2026</text>
  <text x="40" y="85" class="subtitle-text">Analysis Period: Last 90 Days | 2,574 Incidents Analyzed | 27 Active Rules</text>
''')
    
    # KPI Cards Row
    kpis = [
        ("Initial Access", "100%", "#4caf50", "2,562"),
        ("Persistence", "20%", "#ff9800", "4"),
        ("Privilege Escalation", "20%", "#ff9800", "4"),
        ("Lateral Movement", "0%", "#f44336", "0"),
        ("Overall Coverage", "35%", "#ff9800", "N/A"),
    ]
    
    kpi_width = (width - (padding * 2) - 30) // 5
    y_pos = 130
    
    svg_parts.append(f'<!-- KPI Cards -->\n')
    for i, (name, value, color, detail) in enumerate(kpis):
        x_pos = padding + (i * (kpi_width + 6))
        
        # Card background
        svg_parts.append(f'''  <rect x="{x_pos}" y="{y_pos}" width="{kpi_width}" height="110" 
          rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  <!-- Accent bar -->
  <rect x="{x_pos}" y="{y_pos}" width="{kpi_width}" height="4" 
    rx="6" fill="{color}"/>
  <!-- KPI value -->
  <text x="{x_pos + kpi_width//2}" y="{y_pos + 50}" class="value-text" text-anchor="middle">{value}</text>
  <!-- KPI label -->
  <text x="{x_pos + kpi_width//2}" y="{y_pos + 75}" class="label-text" text-anchor="middle" font-size="11">{name}</text>
  <!-- KPI detail -->
  <text x="{x_pos + kpi_width//2}" y="{y_pos + 95}" class="small-text" text-anchor="middle">Incidents: {detail}</text>
''')
    
    # Tactic Coverage Bar Chart
    y_pos = 270
    chart_height = 200
    
    svg_parts.append(f'''<!-- Tactic Coverage Bar Chart -->
  <g>
    <!-- Chart Title -->
    <text x="40" y="{y_pos - 20}" class="label-text" font-size="16">Tactic Coverage Breakdown</text>
    
    <!-- Y-Axis -->
    <line x1="40" y1="{y_pos}" x2="40" y2="{y_pos + chart_height}" stroke="#333" stroke-width="1"/>
    <!-- X-Axis -->
    <line x1="40" y1="{y_pos + chart_height}" x2="{width - 40}" y2="{y_pos + chart_height}" stroke="#333" stroke-width="1"/>
''')
    
    tactics = [
        ("Initial Access", 100, "#4caf50"),
        ("Discovery", 20, "#ff9800"),
        ("Privilege Esc.", 20, "#ff9800"),
        ("Persistence", 20, "#ff9800"),
        ("Lateral Movement", 0, "#f44336"),
        ("Command & Control", 0, "#f44336"),
        ("Exfiltration", 0, "#f44336"),
        ("Impact", 0, "#f44336"),
    ]
    
    bar_width = (width - 100) / len(tactics)
    for i, (tactic, coverage, color) in enumerate(tactics):
        x_pos = 40 + (i * bar_width) + bar_width * 0.1
        bar_height = (coverage / 100) * chart_height
        
        # Bar
        svg_parts.append(f'''    <rect x="{x_pos}" y="{y_pos + chart_height - bar_height}" 
      width="{bar_width * 0.8}" height="{bar_height}" fill="{color}" rx="2"/>
    <!-- Label -->
    <text x="{x_pos + bar_width * 0.4}" y="{y_pos + chart_height + 20}" 
      class="small-text" text-anchor="middle" font-size="9">{tactic}</text>
    <!-- Percentage -->
    <text x="{x_pos + bar_width * 0.4}" y="{y_pos + chart_height - bar_height - 5}" 
      class="value-text" text-anchor="middle" font-size="12">{coverage}%</text>
''')
    
    svg_parts.append('  </g>')
    
    # Incidents by Tactic - Donut Chart
    y_pos = 520
    chart_x = 100
    chart_y = y_pos + 80
    radius = 60
    
    svg_parts.append(f'''<!-- Incidents by Tactic - Donut Chart -->
  <text x="40" y="{y_pos - 20}" class="label-text" font-size="16">Incident Distribution by Tactic</text>
  
  <!-- Donut Chart -->
  <circle cx="{chart_x}" cy="{chart_y}" r="{radius}" fill="none" stroke="#4caf50" stroke-width="40" stroke-dasharray="226 286" stroke-dashoffset="0" opacity="0.9"/>
  <circle cx="{chart_x}" cy="{chart_y}" r="{radius}" fill="none" stroke="#ff9800" stroke-width="40" stroke-dasharray="8 286" stroke-dashoffset="-226" opacity="0.9"/>
  <circle cx="{chart_x}" cy="{chart_y}" r="{radius}" fill="none" stroke="#ff9800" stroke-width="40" stroke-dasharray="8 286" stroke-dashoffset="-234" opacity="0.9"/>
  <circle cx="{chart_x}" cy="{chart_y}" r="{radius}" fill="none" stroke="#ff9800" stroke-width="40" stroke-dasharray="8 286" stroke-dashoffset="-242" opacity="0.9"/>
  
  <!-- Center label -->
  <circle cx="{chart_x}" cy="{chart_y}" r="30" fill="#0f0f0f"/>
  <text x="{chart_x}" y="{chart_y - 5}" class="value-text" text-anchor="middle" font-size="14">2,574</text>
  <text x="{chart_x}" y="{chart_y + 12}" class="small-text" text-anchor="middle" font-size="11">Total</text>
  
  <!-- Legend -->
  <text x="280" y="{y_pos}" class="label-text" font-size="12">Initial Access</text>
  <rect x="270" y="{y_pos - 12}" width="8" height="8" fill="#4caf50"/>
  <text x="280" y="{y_pos + 25}" class="small-text" font-size="11">2,562 (99.5%)</text>
  
  <text x="280" y="{y_pos + 60}" class="label-text" font-size="12">Other Tactics</text>
  <rect x="270" y="{y_pos + 48}" width="8" height="8" fill="#ff9800"/>
  <text x="280" y="{y_pos + 85}" class="small-text" font-size="11">12 (0.5%)</text>
  
  <text x="280" y="{y_pos + 120}" class="label-text" font-size="12">No Coverage</text>
  <rect x="270" y="{y_pos + 108}" width="8" height="8" fill="#f44336"/>
  <text x="280" y="{y_pos + 145}" class="small-text" font-size="11">4 Tactics</text>
''')
    
    # Coverage Heatmap
    y_pos = 780
    
    svg_parts.append(f'''<!-- Coverage Heatmap -->
  <text x="40" y="{y_pos - 20}" class="label-text" font-size="16">MITRE Framework Coverage Heatmap</text>
''')
    
    heatmap_tactics = [
        ("Recon", 40),
        ("Resource Dev", 0),
        ("Initial Access", 100),
        ("Execution", 0),
        ("Persistence", 20),
        ("Privilege Esc.", 20),
        ("Defense Evasion", 0),
        ("Cred. Access", 0),
        ("Discovery", 20),
        ("Lateral Movement", 0),
        ("Collection", 0),
        ("Command & Control", 0),
        ("Exfiltration", 0),
        ("Impact", 0),
    ]
    
    cell_width = (width - 100) / len(heatmap_tactics)
    for i, (tactic, coverage) in enumerate(heatmap_tactics):
        x_pos = 50 + (i * cell_width)
        
        # Color based on coverage
        if coverage >= 80:
            color = "#4caf50"
        elif coverage >= 40:
            color = "#ff9800"
        else:
            color = "#f44336"
        
        svg_parts.append(f'''  <g>
    <rect x="{x_pos}" y="{y_pos}" width="{cell_width - 2}" height="50" 
      fill="{color}" opacity="0.7" rx="2"/>
    <text x="{x_pos + cell_width/2 - 1}" y="{y_pos + 20}" class="small-text" text-anchor="middle" font-size="9">{tactic}</text>
    <text x="{x_pos + cell_width/2 - 1}" y="{y_pos + 35}" class="value-text" text-anchor="middle" font-size="12">{coverage}%</text>
  </g>
''')
    
    # Legend for heatmap
    svg_parts.append(f'''  <!-- Legend -->
  <text x="50" y="{y_pos + 80}" class="small-text" font-size="11">Coverage Legend:</text>
  <rect x="50" y="{y_pos + 95}" width="12" height="12" fill="#4caf50"/>
  <text x="70" y="{y_pos + 104}" class="small-text" font-size="10">Strong (≥80%)</text>
  
  <rect x="200" y="{y_pos + 95}" width="12" height="12" fill="#ff9800"/>
  <text x="220" y="{y_pos + 104}" class="small-text" font-size="10">Weak (20-79%)</text>
  
  <rect x="350" y="{y_pos + 95}" width="12" height="12" fill="#f44336"/>
  <text x="370" y="{y_pos + 104}" class="small-text" font-size="10">No Coverage (0%)</text>
''')
    
    # Key Findings Section
    y_pos = 1020
    
    svg_parts.append(f'''<!-- Key Findings -->
  <rect x="30" y="{y_pos}" width="{width - 60}" height="200" 
    rx="6" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  
  <text x="50" y="{y_pos + 25}" class="label-text" font-size="14">Key Findings & Recommendations</text>
  
  <!-- Finding 1 - Strong -->
  <rect x="50" y="{y_pos + 40}" width="6" height="6" fill="#4caf50"/>
  <text x="65" y="{y_pos + 44}" class="strong" font-size="11">Strong Initial Access Detection (100%)</text>
  <text x="65" y="{y_pos + 60}" class="small-text" font-size="10">2,562 incidents detected through credential and phishing monitoring</text>
  
  <!-- Finding 2 - Critical Gap -->
  <rect x="50" y="{y_pos + 85}" width="6" height="6" fill="#f44336"/>
  <text x="65" y="{y_pos + 89}" class="strong" font-size="11">CRITICAL GAP: Lateral Movement (0%)</text>
  <text x="65" y="{y_pos + 105}" class="small-text" font-size="10">No detection for RDP, SSH, WinRM lateral moves - once attackers gain access, they operate undetected</text>
  
  <!-- Finding 3 - High Priority -->
  <rect x="50" y="{y_pos + 130}" width="6" height="6" fill="#ff9800"/>
  <text x="65" y="{y_pos + 134}" class="strong" font-size="11">HIGH PRIORITY: Persistence & C2/Exfiltration Gaps</text>
  <text x="65" y="{y_pos + 150}" class="small-text" font-size="10">Missing detection for OAuth consent abuse, forwarding rules, DNS tunneling, and data exfiltration</text>
  
  <!-- Recommendation -->
  <rect x="50" y="{y_pos + 170}" width="6" height="6" fill="#00b4d8"/>
  <text x="65" y="{y_pos + 174}" class="strong" font-size="11">RECOMMENDATION: Deploy 8+ new analytic rules to reach 70% coverage in 4-6 weeks</text>
''')
    
    # Footer
    y_pos = 1250
    svg_parts.append(f'''<!-- Footer -->
  <line x1="30" y1="{y_pos}" x2="{width - 30}" y2="{y_pos}" stroke="#333" stroke-width="1"/>
  <text x="40" y="{y_pos + 25}" class="small-text" font-size="10">Report Generated: April 18, 2026 | Workspace: Infosec-Sentinel-LAW | Next Review: May 18, 2026</text>
  <text x="40" y="{y_pos + 45}" class="small-text" font-size="10">Coverage Analysis based on 2,574 incidents over 90-day period | 27 active analytic rules deployed</text>
  
  <!-- Overall Assessment -->
  <rect x="40" y="{y_pos + 70}" width="{width - 80}" height="80" 
    rx="4" fill="#1a2a3a" stroke="#1565c0" stroke-width="2"/>
  <text x="60" y="{y_pos + 95}" class="label-text" font-size="12">OVERALL SECURITY POSTURE</text>
  <text x="60" y="{y_pos + 115}" class="value-text" font-size="18" fill="#ff9800">MODERATE RISK - 35% Coverage</text>
  <text x="60" y="{y_pos + 130}" class="small-text" font-size="11">Strong initial access controls, but critical blind spots in post-breach detection. Immediate action required for lateral movement monitoring.</text>
</svg>
''')
    
    return ''.join(svg_parts)

if __name__ == "__main__":
    svg_content = create_mitre_dashboard()
    
    with open('reports/MITRE_Dashboard_20260418.svg', 'w', encoding='utf-8') as f:
        f.write(svg_content)
    
    print("✅ SVG Dashboard created: reports/MITRE_Dashboard_20260418.svg")
