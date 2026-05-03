#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Heatmap SVG Generator

Creates an interactive heatmap visualization showing:
- Coverage intensity by tactic
- Technique-level drill-down data
- Color-coded risk assessment
- Statistical overlays
"""

from datetime import datetime
from pathlib import Path

def generate_mitre_heatmap_svg() -> str:
    """Generate SVG heatmap for MITRE ATT&CK coverage."""
    
    # MITRE Framework Data
    tactics_data = [
        ("TA0001", "Initial Access", 95, "#10b981"),
        ("TA0002", "Execution", 45, "#f59e0b"),
        ("TA0003", "Persistence", 38, "#f59e0b"),
        ("TA0004", "Privilege Escalation", 32, "#f59e0b"),
        ("TA0005", "Defense Evasion", 28, "#ef4444"),
        ("TA0006", "Credential Access", 52, "#f59e0b"),
        ("TA0007", "Discovery", 35, "#f59e0b"),
        ("TA0008", "Lateral Movement", 0, "#ef4444"),
        ("TA0009", "Collection", 22, "#ef4444"),
        ("TA0010", "Exfiltration", 8, "#ef4444"),
        ("TA0011", "Command & Control", 5, "#ef4444"),
        ("TA0040", "Impact", 12, "#ef4444"),
    ]
    
    # Canvas settings
    width = 1600
    height = 900
    padding = 60
    cell_width = (width - padding * 2) / len(tactics_data)
    cell_height = 200
    
    svg_parts = []
    
    # SVG header and styles
    svg_parts.append(f'''<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <style>
      .title {{ font-size: 28px; font-weight: bold; fill: #ffffff; }}
      .subtitle {{ font-size: 14px; fill: #b0b0b0; }}
      .label {{ font-size: 12px; fill: #ffffff; font-weight: 500; }}
      .value {{ font-size: 20px; font-weight: bold; fill: #00d4ff; }}
      .small {{ font-size: 10px; fill: #808080; }}
      .legend-text {{ font-size: 11px; fill: #999999; }}
      
      .heatmap-cell:hover {{
        filter: brightness(1.3);
        stroke-width: 3;
      }}
    </style>
    
    <linearGradient id="headerGradient" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#667eea;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#764ba2;stop-opacity:1" />
    </linearGradient>
    
    <linearGradient id="greenGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#34d399;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#10b981;stop-opacity:1" />
    </linearGradient>
    
    <linearGradient id="yellowGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#fbbf24;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#f59e0b;stop-opacity:1" />
    </linearGradient>
    
    <linearGradient id="redGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#f87171;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#ef4444;stop-opacity:1" />
    </linearGradient>
  </defs>
  
  <!-- Background -->
  <rect width="{width}" height="{height}" fill="#0f0f1e"/>
  
  <!-- Header Banner -->
  <rect y="0" width="{width}" height="70" fill="url(#headerGradient)"/>
  <text x="40" y="40" class="title">MITRE ATT&CK Coverage Heatmap</text>
  <text x="40" y="60" class="subtitle">Interactive coverage analysis by tactic | April 18, 2026</text>
''')
    
    # Draw heatmap cells
    y_pos = 100
    
    for i, (tactic_id, tactic_name, coverage, color) in enumerate(tactics_data):
        x_pos = padding + (i * cell_width)
        
        # Select gradient based on coverage
        if coverage >= 70:
            gradient_url = "url(#greenGradient)"
            intensity = 1.0
        elif coverage >= 40:
            gradient_url = "url(#yellowGradient)"
            intensity = 0.8
        else:
            gradient_url = "url(#redGradient)"
            intensity = 0.6
        
        # Cell background with gradient
        svg_parts.append(f'''  <g class="heatmap-cell">
    <rect x="{x_pos}" y="{y_pos}" width="{cell_width - 2}" height="{cell_height}"
          fill="{gradient_url}" opacity="{intensity}" rx="4" stroke="{color}" stroke-width="2"/>
    
    <!-- Tactic name -->
    <text x="{x_pos + cell_width/2}" y="{y_pos + 30}" class="label" text-anchor="middle">
      {tactic_name.split()[0]}
    </text>
    
    <!-- Coverage percentage -->
    <text x="{x_pos + cell_width/2}" y="{y_pos + 80}" class="value" text-anchor="middle" font-size="32">
      {coverage}%
    </text>
    
    <!-- Coverage bar -->
    <rect x="{x_pos + 10}" y="{y_pos + 110}" width="{cell_width - 22}" height="8"
          fill="#333333" rx="2"/>
    <rect x="{x_pos + 10}" y="{y_pos + 110}" width="{(cell_width - 22) * (coverage/100)}" height="8"
          fill="{color}" rx="2"/>
    
    <!-- Full tactic name tooltip background (hidden on hover) -->
    <rect x="{x_pos}" y="{y_pos + 150}" width="{cell_width - 2}" height="35"
          fill="#1a1a2e" opacity="0.95" rx="2" stroke="#667eea" stroke-width="1"/>
    <text x="{x_pos + cell_width/2}" y="{y_pos + 170}" class="small" text-anchor="middle" font-size="9">
      {tactic_name}
    </text>
  </g>
''')
    
    # Legend
    legend_y = y_pos + cell_height + 40
    
    svg_parts.append(f'''  <!-- Legend -->
  <text x="40" y="{legend_y + 20}" class="label" font-size="14">Coverage Legend:</text>
  
  <!-- Strong Coverage -->
  <rect x="40" y="{legend_y + 35}" width="20" height="20" fill="url(#greenGradient)" rx="2"/>
  <text x="70" y="{legend_y + 50}" class="legend-text">Strong Coverage (≥70%)</text>
  
  <!-- Moderate Coverage -->
  <rect x="320" y="{legend_y + 35}" width="20" height="20" fill="url(#yellowGradient)" rx="2"/>
  <text x="350" y="{legend_y + 50}" class="legend-text">Moderate Coverage (40-70%)</text>
  
  <!-- Weak Coverage -->
  <rect x="700" y="{legend_y + 35}" width="20" height="20" fill="url(#redGradient)" rx="2"/>
  <text x="730" y="{legend_y + 50}" class="legend-text">Weak/No Coverage (<40%)</text>
  
  <!-- Risk Assessment -->
  <rect x="1100" y="{legend_y + 35}" width="20" height="20" fill="#10b981" rx="2"/>
  <text x="1130" y="{legend_y + 50}" class="legend-text">Low Risk</text>
  
  <rect x="1280" y="{legend_y + 35}" width="20" height="20" fill="#f59e0b" rx="2"/>
  <text x="1310" y="{legend_y + 50}" class="legend-text">Medium Risk</text>
  
  <rect x="1460" y="{legend_y + 35}" width="20" height="20" fill="#ef4444" rx="2"/>
  <text x="1490" y="{legend_y + 50}" class="legend-text">High Risk</text>
  
  <!-- Summary Stats -->
  <rect x="40" y="{legend_y + 90}" width="{width - 80}" height="60"
        fill="#1a1a2e" stroke="#667eea" stroke-width="2" rx="4"/>
  
  <text x="60" y="{legend_y + 110}" class="label">Coverage Summary:</text>
  <text x="60" y="{legend_y + 135}" class="legend-text" font-size="12">
    Overall: <tspan fill="#00d4ff" font-weight="bold">38%</tspan> | 
    Strong: <tspan fill="#10b981" font-weight="bold">1 tactic</tspan> | 
    Moderate: <tspan fill="#f59e0b" font-weight="bold">6 tactics</tspan> | 
    Weak: <tspan fill="#ef4444" font-weight="bold">5 tactics</tspan> | 
    Detected Incidents: <tspan fill="#00d4ff" font-weight="bold">3,640</tspan>
  </text>
</svg>
''')
    
    return ''.join(svg_parts)

def generate_technique_heatmap_svg() -> str:
    """Generate detailed technique-level heatmap."""
    
    # High-impact techniques
    techniques_matrix = [
        # Initial Access
        ("T1566 - Phishing", "Initial Access", 100),
        ("T1195 - Supply Chain", "Initial Access", 85),
        ("T1199 - Trusted Relationship", "Initial Access", 92),
        
        # Execution
        ("T1059 - Command Interpreter", "Execution", 78),
        ("T1204 - User Execution", "Execution", 82),
        ("T1053 - Scheduled Task", "Execution", 72),
        
        # Persistence
        ("T1098 - Account Manipulation", "Persistence", 75),
        ("T1547 - Autostart Execution", "Persistence", 62),
        
        # Lateral Movement (GAPS)
        ("T1021.001 - RDP", "Lateral Movement", 0),
        ("T1021.005 - WinRM", "Lateral Movement", 0),
        ("T1021.003 - DCOM", "Lateral Movement", 0),
        
        # Exfiltration (GAPS)
        ("T1048 - Alt Protocol", "Exfiltration", 0),
        ("T1020 - Automated Exfil", "Exfiltration", 35),
        
        # C2 (GAPS)
        ("T1071 - App Layer Protocol", "Command & Control", 0),
        ("T1571 - Non-Standard Port", "Command & Control", 0),
    ]
    
    width = 1400
    height = 800
    padding = 50
    cell_size = 60
    
    svg_parts = []
    
    svg_parts.append(f'''<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <style>
      .tech-label {{ font-size: 11px; fill: #ffffff; }}
      .tech-category {{ font-size: 13px; font-weight: bold; fill: #667eea; }}
    </style>
  </defs>
  
  <!-- Background -->
  <rect width="{width}" height="{height}" fill="#0f0f1e"/>
  
  <!-- Title -->
  <text x="40" y="40" class="tech-category" font-size="24">Technique-Level Coverage Matrix</text>
  <text x="40" y="60" font-size="12" fill="#999999">Top 16 techniques ranked by MITRE priority and risk</text>
''')
    
    # Organize by tactic
    tactics = {}
    for tech, tactic, coverage in techniques_matrix:
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append((tech, coverage))
    
    y_offset = 100
    
    for tactic, techniques in tactics.items():
        # Tactic header
        svg_parts.append(f'''  <text x="40" y="{y_offset}" class="tech-category">{tactic}</text>
''')
        
        y_offset += 30
        x_offset = 40
        
        for tech, coverage in techniques:
            # Color based on coverage
            if coverage >= 70:
                color = "#10b981"
                text_color = "white"
            elif coverage > 0:
                color = "#f59e0b"
                text_color = "white"
            else:
                color = "#ef4444"
                text_color = "white"
            
            # Cell
            svg_parts.append(f'''  <g>
    <rect x="{x_offset}" y="{y_offset}" width="{cell_size}" height="{cell_size}"
          fill="{color}" opacity="0.8" rx="3" stroke="#333" stroke-width="1"/>
    <text x="{x_offset + cell_size/2}" y="{y_offset + cell_size/2 + 5}" font-size="18"
          fill="{text_color}" text-anchor="middle" font-weight="bold">{coverage}%</text>
    
    <!-- Technique name (tooltip) -->
    <title>{tech}</title>
  </g>
''')
            
            x_offset += cell_size + 8
            
            if x_offset > width - 100:
                x_offset = 40
                y_offset += cell_size + 20
        
        y_offset += cell_size + 40
    
    svg_parts.append('''
</svg>
''')
    
    return ''.join(svg_parts)

def main():
    """Generate MITRE heatmap visualizations."""
    import sys
    
    # Handle dynamic output path
    output_dir_str = "reports"
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        output_dir_str = sys.argv[1]
        
    output_dir = Path(output_dir_str)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d")
    
    print("\n" + "=" * 80)
    print("[FLAME] Generating MITRE Coverage Heatmaps")
    print("=" * 80)
    
    # Generate tactic-level heatmap
    print("\n[CHART] Generating tactic-level heatmap...")
    heatmap_svg = generate_mitre_heatmap_svg()
    heatmap_path = output_dir / f"MITRE_Coverage_Heatmap_Tactics_{timestamp}.svg"
    
    with open(heatmap_path, 'w', encoding='utf-8') as f:
        f.write(heatmap_svg)
    
    print(f"[OK] Tactic heatmap saved: {heatmap_path}")
    
    # Generate technique-level heatmap
    print("\n[CHART] Generating technique-level heatmap...")
    tech_heatmap_svg = generate_technique_heatmap_svg()
    tech_heatmap_path = output_dir / f"MITRE_Coverage_Heatmap_Techniques_{timestamp}.svg"
    
    with open(tech_heatmap_path, 'w', encoding='utf-8') as f:
        f.write(tech_heatmap_svg)
    
    print(f"[OK] Technique heatmap saved: {tech_heatmap_path}")
    
    print("\n" + "=" * 80)
    print("Heatmap generation complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()
