#!/usr/bin/env python3
"""
Generate executive summary presentation HTML
Optimized for printing as slides or one-page executive brief
"""

from datetime import datetime
from pathlib import Path

def generate_executive_summary():
    """Create executive summary HTML."""
    
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MITRE ATT&CK Coverage - Executive Summary</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .page {
            background: white;
            width: 8.5in;
            height: 11in;
            margin: 0 auto 20px;
            padding: 0.5in;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            overflow: hidden;
            position: relative;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 24px;
            margin-bottom: 5px;
        }
        
        .header p {
            font-size: 11px;
            opacity: 0.9;
        }
        
        .metric-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .metric {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        
        .metric.critical {
            border-left-color: #ef4444;
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        }
        
        .metric-number {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        
        .metric-label {
            font-size: 10px;
            color: #666;
            margin-top: 5px;
        }
        
        .section {
            margin-bottom: 15px;
        }
        
        .section h2 {
            font-size: 14px;
            color: #667eea;
            margin-bottom: 8px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 5px;
        }
        
        .finding {
            background: #f9fafb;
            padding: 8px 12px;
            margin: 5px 0;
            border-left: 3px solid #667eea;
            font-size: 10px;
            line-height: 1.4;
        }
        
        .finding.critical {
            border-left-color: #ef4444;
            background: #fef2f2;
        }
        
        .finding.positive {
            border-left-color: #10b981;
            background: #f0fdf4;
        }
        
        .finding strong {
            color: #333;
        }
        
        .chart {
            display: flex;
            gap: 4px;
            align-items: flex-end;
            height: 40px;
            margin: 10px 0;
        }
        
        .bar {
            flex: 1;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
            border-radius: 2px;
            min-height: 3px;
            position: relative;
            font-size: 8px;
            display: flex;
            align-items: flex-end;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        
        .bar.green { background: linear-gradient(180deg, #10b981 0%, #059669 100%); }
        .bar.yellow { background: linear-gradient(180deg, #f59e0b 0%, #d97706 100%); }
        .bar.red { background: linear-gradient(180deg, #ef4444 0%, #dc2626 100%); }
        
        .roadmap {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 8px;
            font-size: 9px;
        }
        
        .phase {
            background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #667eea;
        }
        
        .phase strong {
            display: block;
            margin-bottom: 5px;
            color: #333;
        }
        
        .phase p {
            font-size: 8px;
            color: #666;
            line-height: 1.3;
            margin: 3px 0;
        }
        
        .footer {
            position: absolute;
            bottom: 20px;
            left: 20px;
            right: 20px;
            font-size: 9px;
            color: #999;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            display: flex;
            justify-content: space-between;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .page {
                margin-bottom: 0;
                box-shadow: none;
                page-break-after: always;
            }
        }
    </style>
</head>
<body>

<div class="page">
    <div class="header">
        <h1>🛡️ MITRE ATT&CK Coverage Analysis</h1>
        <p>Executive Summary | Infosec-Sentinel-LAW | April 18, 2026</p>
    </div>
    
    <div class="metric-grid">
        <div class="metric">
            <div class="metric-number" style="color: #f59e0b;">38%</div>
            <div class="metric-label">Current Coverage</div>
        </div>
        <div class="metric">
            <div class="metric-number" style="color: #10b981;">70%</div>
            <div class="metric-label">Target (4-6 wks)</div>
        </div>
        <div class="metric critical">
            <div class="metric-number">0%</div>
            <div class="metric-label">Lateral Movement</div>
        </div>
        <div class="metric">
            <div class="metric-number" style="color: #667eea;">8</div>
            <div class="metric-label">Rules to Deploy</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Coverage by Tactic</h2>
        <div style="display: grid; grid-template-columns: auto 1fr auto; gap: 10px; font-size: 9px; max-height: 100px; overflow-y: auto;">
            <span style="font-weight: bold;">Initial Access</span>
            <div class="chart" style="flex: 1;">
                <div class="bar green" style="height: 95%; width: 1px;"></div>
            </div>
            <span style="text-align: right;">95%</span>
            
            <span style="font-weight: bold;">Credential Access</span>
            <div class="chart" style="flex: 1;">
                <div class="bar green" style="height: 52%;"></div>
            </div>
            <span style="text-align: right;">52%</span>
            
            <span style="font-weight: bold;">Execution</span>
            <div class="chart" style="flex: 1;">
                <div class="bar yellow" style="height: 45%;"></div>
            </div>
            <span style="text-align: right;">45%</span>
            
            <span style="font-weight: bold; color: #ef4444;">Lateral Movement</span>
            <div class="chart" style="flex: 1;">
                <div class="bar red" style="height: 5%;"></div>
            </div>
            <span style="text-align: right; color: #ef4444;"><strong>0%</strong></span>
        </div>
    </div>
    
    <div class="section">
        <h2>Key Findings</h2>
        <div class="finding positive">
            <strong>✅ Strength:</strong> Initial Access (95%) - 2,562 incidents detected. Strong phishing & credential monitoring.
        </div>
        <div class="finding critical">
            <strong>🔴 Critical:</strong> Lateral Movement (0%) - Attackers move undetected. RDP/WinRM/DCOM completely blind.
        </div>
        <div class="finding critical">
            <strong>🔴 Critical:</strong> C2 (5%) & Exfiltration (8%) - Command communication & data theft unmonitored.
        </div>
        <div class="finding">
            <strong>Impact:</strong> ~1,450+ incidents/quarter operating undetected in post-breach phase.
        </div>
    </div>
    
    <div class="section">
        <h2>Implementation Plan</h2>
        <div class="roadmap">
            <div class="phase">
                <strong style="color: #ef4444;">Phase 1: Critical</strong>
                <p>Deploy 3 lateral movement rules</p>
                <p>+910 incidents detected</p>
                <p>Effort: Medium</p>
                <p><strong>Timeline: Week 1-2</strong></p>
            </div>
            <div class="phase">
                <strong style="color: #f59e0b;">Phase 2: High-Priority</strong>
                <p>Deploy 3 persistence/exfil rules</p>
                <p>+735 incidents detected</p>
                <p>Effort: High</p>
                <p><strong>Timeline: Week 2-3</strong></p>
            </div>
            <div class="phase">
                <strong style="color: #667eea;">Phase 3: Secondary</strong>
                <p>Deploy 2 masquerading/collection</p>
                <p>+275 incidents detected</p>
                <p>Effort: Medium-Low</p>
                <p><strong>Timeline: Week 4-6</strong></p>
            </div>
        </div>
        <div style="background: #f0fdf4; border: 1px solid #86efac; border-radius: 4px; padding: 8px; margin-top: 8px; font-size: 9px;">
            <strong style="color: #166534;">Total Impact:</strong> +1,920 incidents/quarter | Coverage 38% → 70% | 4-6 week timeline
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div style="font-size: 9px; line-height: 1.4;">
            1. <strong>Immediate:</strong> Deploy Phase 1 rules for lateral movement detection<br>
            2. <strong>Weeks 2-3:</strong> Add persistence and data exfiltration monitoring<br>
            3. <strong>Weeks 4-6:</strong> Complete Phase 3 for comprehensive coverage<br>
            4. <strong>Ongoing:</strong> Monthly coverage reviews and rule tuning
        </div>
    </div>
    
    <div class="footer">
        <span>Infosec-Sentinel-LAW | April 18, 2026</span>
        <span>Full report: MITRE_ATT_CK_Coverage_Report_20260418.html</span>
    </div>
</div>

</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    output_path = Path("reports/MITRE_Executive_Summary_20260418.html")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(generate_executive_summary())
    
    print(f"✅ Executive summary created: {output_path}")
