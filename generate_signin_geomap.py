#!/usr/bin/env python3
"""
Generate geomap visualization from sign-in logs pattern analysis
Extracts geographic data from SigninLogs and creates world map visualization
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timedelta

def load_config():
    """Load workspace configuration."""
    config_path = Path('config.json')
    if not config_path.exists():
        print("❌ config.json not found")
        return None
    
    with open(config_path, 'r') as f:
        return json.load(f)

def get_kql_queries():
    """Return KQL query templates for sign-in pattern analysis."""
    
    queries = {
        'failed_signin_geographic': '''
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| where IPAddress != "127.0.0.1"
| summarize 
    value = count(),
    success_count = dcountif(ResultType, ResultType == 0),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated)
    by ip = IPAddress
| order by value desc
| take 100
''',
        
        'all_signin_geographic': '''
SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress != "127.0.0.1"
| summarize 
    value = count(),
    success_count = dcountif(ResultType, ResultType == 0),
    failed_count = dcountif(ResultType, ResultType != 0),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated)
    by ip = IPAddress
| where value > 5
| order by value desc
| take 100
''',
        
        'risky_signin_geographic': '''
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskState in ("atRisk", "confirmedCompromised")
| summarize 
    value = count(),
    risk_state = take_any(RiskState),
    unique_users = dcount(UserPrincipalName)
    by ip = IPAddress
| order by value desc
| take 50
''',
        
        'mfa_failures_geographic': '''
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 500127
| where IPAddress != "127.0.0.1"
| summarize 
    value = count(),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated)
    by ip = IPAddress
| order by value desc
| take 100
'''
    }
    
    return queries

def create_geomap_template():
    """Create template HTML for geomap generation."""
    
    template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign-in Logs Geographic Pattern Analysis</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .metric {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .metric-value {
            font-size: 20px;
            font-weight: bold;
        }
        
        .metric-label {
            font-size: 12px;
            opacity: 0.9;
            margin-top: 5px;
        }
        
        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .card h2 {
            font-size: 18px;
            color: #667eea;
            margin-bottom: 15px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .map-container {
            width: 100%;
            height: 500px;
            border-radius: 8px;
            overflow: hidden;
            background: #f9fafb;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            color: #999;
        }
        
        .query-guide {
            background: #f9fafb;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            margin-bottom: 15px;
        }
        
        .query-guide h3 {
            font-size: 13px;
            color: #667eea;
            margin-bottom: 8px;
        }
        
        .query-code {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            overflow-x: auto;
            line-height: 1.4;
        }
        
        .steps {
            list-style: none;
        }
        
        .steps li {
            padding: 10px 0;
            border-bottom: 1px solid #eee;
            font-size: 13px;
            color: #666;
        }
        
        .steps li:last-child {
            border-bottom: none;
        }
        
        .steps strong {
            color: #333;
        }
        
        .note {
            background: #fffbeb;
            border: 1px solid #fbbf24;
            border-radius: 8px;
            padding: 12px;
            margin-top: 15px;
            font-size: 12px;
            color: #666;
        }
        
        .note strong {
            color: #d97706;
        }
    </style>
</head>
<body>

<div class="container">
    <div class="header">
        <h1>🗺️ Sign-in Logs Geographic Pattern Analysis</h1>
        <p>Visualize global sign-in distribution and identify unusual geographic patterns</p>
        
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">7 days</div>
                <div class="metric-label">Analysis Period</div>
            </div>
            <div class="metric">
                <div class="metric-value">100+</div>
                <div class="metric-label">Top IPs by Activity</div>
            </div>
            <div class="metric">
                <div class="metric-value">Interactive</div>
                <div class="metric-label">World Map</div>
            </div>
            <div class="metric">
                <div class="metric-value">Drill-Down</div>
                <div class="metric-label">Threat Intelligence</div>
            </div>
        </div>
    </div>
    
    <div class="main-grid">
        <div class="card">
            <h2>🗺️ Geographic Heat Map</h2>
            <div class="map-container">
                <div style="text-align: center;">
                    <p>📊 Map visualization will appear here</p>
                    <p style="font-size: 12px; margin-top: 10px; color: #bbb;">Complete the steps below to generate the geomap</p>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📋 How to Generate This Geomap</h2>
            <ol class="steps">
                <li><strong>Step 1:</strong> Choose a query pattern (see below)</li>
                <li><strong>Step 2:</strong> Query your Sentinel workspace using KQL</li>
                <li><strong>Step 3:</strong> Extract IP addresses and counts</li>
                <li><strong>Step 4:</strong> Enrich IPs with geographic data using <code>enrich_ips.py</code></li>
                <li><strong>Step 5:</strong> Call the geomap MCP to visualize</li>
            </ol>
            
            <div class="note">
                <strong>📌 Note:</strong> Sign-in logs don't include native latitude/longitude. You must enrich IPs with geographic coordinates using the IP enrichment tool.
            </div>
        </div>
    </div>
    
    <div class="card">
        <h2>🔧 Query Patterns for Sign-in Analysis</h2>
        
        <div class="query-guide">
            <h3>1️⃣ Failed Sign-ins by Geographic Location</h3>
            <p style="font-size: 12px; color: #666; margin-bottom: 10px;">
                Shows only failed authentication attempts, useful for identifying attack origins and brute-force patterns.
            </p>
            <div class="query-code">
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| where IPAddress != "127.0.0.1"
| summarize 
    value = count(),
    unique_users = dcount(UserPrincipalName)
    by ip = IPAddress
| order by value desc
| take 100
            </div>
            <p style="font-size: 11px; color: #999; margin-top: 8px;">
                ✓ Use for: Attack origin mapping | ✓ Best for: Honeypot/brute-force analysis
            </p>
        </div>
        
        <div class="query-guide">
            <h3>2️⃣ All Sign-ins by Geographic Location</h3>
            <p style="font-size: 12px; color: #666; margin-bottom: 10px;">
                Shows successful and failed sign-ins combined, revealing global usage patterns.
            </p>
            <div class="query-code">
SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress != "127.0.0.1"
| summarize 
    value = count(),
    success_count = dcountif(ResultType, ResultType == 0),
    failed_count = dcountif(ResultType, ResultType != 0)
    by ip = IPAddress
| where value > 5
| order by value desc
| take 100
            </div>
            <p style="font-size: 11px; color: #999; margin-top: 8px;">
                ✓ Use for: Global usage visualization | ✓ Best for: Baseline establishment
            </p>
        </div>
        
        <div class="query-guide">
            <h3>3️⃣ Risky Sign-ins by Geographic Location</h3>
            <p style="font-size: 12px; color: #666; margin-bottom: 10px;">
                Highlights IP addresses flagged by Azure AD risk detection (atRisk or confirmedCompromised).
            </p>
            <div class="query-code">
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskState in ("atRisk", "confirmedCompromised")
| summarize 
    value = count(),
    risk_state = take_any(RiskState),
    unique_users = dcount(UserPrincipalName)
    by ip = IPAddress
| order by value desc
| take 50
            </div>
            <p style="font-size: 11px; color: #999; margin-top: 8px;">
                ✓ Use for: Risk visualization | ✓ Best for: Identity Protection analysis
            </p>
        </div>
        
        <div class="query-guide">
            <h3>4️⃣ MFA Failures by Geographic Location</h3>
            <p style="font-size: 12px; color: #666; margin-bottom: 10px;">
                Shows IPs where MFA authentication failed, potentially indicating account compromise or policy bypasses.
            </p>
            <div class="query-code">
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 500127
| where IPAddress != "127.0.0.1"
| summarize 
    value = count(),
    unique_users = dcount(UserPrincipalName)
    by ip = IPAddress
| order by value desc
| take 100
            </div>
            <p style="font-size: 11px; color: #999; margin-top: 8px;">
                ✓ Use for: MFA attack detection | ✓ Best for: Anomaly investigation
            </p>
        </div>
    </div>
    
    <div class="card">
        <h2>🚀 Step-by-Step: Generate Your Sign-in Geomap</h2>
        
        <div style="background: #f9fafb; padding: 20px; border-radius: 8px;">
            <h3 style="color: #667eea; margin-bottom: 15px; font-size: 14px;">📌 Complete Workflow</h3>
            
            <div style="display: grid; gap: 15px;">
                <div style="border-left: 4px solid #10b981; padding-left: 15px;">
                    <strong style="color: #10b981;">Step 1: Choose Query Pattern</strong>
                    <p style="font-size: 12px; color: #666; margin-top: 5px;">
                        Select one of the 4 query patterns above (Failed, All, Risky, or MFA Failures)
                    </p>
                </div>
                
                <div style="border-left: 4px solid #667eea; padding-left: 15px;">
                    <strong style="color: #667eea;">Step 2: Query Sentinel</strong>
                    <p style="font-size: 12px; color: #666; margin-top: 5px;">
                        Execute the KQL query in Azure Sentinel to extract IP addresses and counts
                    </p>
                </div>
                
                <div style="border-left: 4px solid #f59e0b; padding-left: 15px;">
                    <strong style="color: #f59e0b;">Step 3: Save IPs to File</strong>
                    <p style="font-size: 12px; color: #666; margin-top: 5px;">
                        Export results as JSON with format: <code>{"IpAddress": "x.x.x.x", "value": N}</code>
                    </p>
                </div>
                
                <div style="border-left: 4px solid #ef4444; padding-left: 15px;">
                    <strong style="color: #ef4444;">Step 4: Enrich IPs</strong>
                    <div style="font-size: 12px; color: #666; margin-top: 5px; font-family: monospace; background: #2d2d2d; color: #f8f8f2; padding: 10px; border-radius: 4px;">
python enrich_ips.py --file temp/signin_ips.json
                    </div>
                </div>
                
                <div style="border-left: 4px solid #06b6d4; padding-left: 15px;">
                    <strong style="color: #06b6d4;">Step 5: Generate Geomap</strong>
                    <p style="font-size: 12px; color: #666; margin-top: 5px;">
                        Use the Sentinel geomap MCP with enriched data to create the world map visualization
                    </p>
                </div>
            </div>
        </div>
        
        <div class="note" style="margin-top: 20px;">
            <strong>💡 Pro Tips:</strong><br>
            • Filter by <code>value > 10</code> to focus on high-volume IPs<br>
            • Use the "Risky" query to identify suspected compromised accounts<br>
            • Compare geographic baselines (weekday vs weekend) for anomalies<br>
            • Click markers on the map for threat intelligence drill-down
        </div>
    </div>
    
    <div class="card">
        <h2>📊 Output Format for Geomap</h2>
        
        <p style="font-size: 13px; color: #666; margin-bottom: 15px;">
            Once IPs are enriched with latitude/longitude, format data as:
        </p>
        
        <div class="query-code" style="margin-bottom: 15px;">
{
  "data": [
    {
      "ip": "203.0.113.42",
      "lat": 22.25,
      "lon": 114.15,
      "value": 127
    },
    {
      "ip": "198.51.100.10",
      "lat": 52.35,
      "lon": 4.92,
      "value": 85
    }
  ],
  "title": "Failed Sign-in Origins (Last 7 Days)",
  "valueLabel": "Failed Attempts",
  "colorScale": "blue-red"
}
        </div>
        
        <p style="font-size: 12px; background: #fef3c7; border-left: 3px solid #f59e0b; padding: 10px; border-radius: 4px; color: #92400e;">
            <strong>Required Fields:</strong> Each entry must have <code>ip</code>, <code>lat</code>, <code>lon</code>, <code>value</code>
        </p>
    </div>
</div>

</body>
</html>
'''
    
    return template

def main():
    """Main execution."""
    
    print("\n" + "="*70)
    print("🗺️ SIGN-IN LOGS GEOGRAPHIC PATTERN ANALYSIS - SETUP GUIDE")
    print("="*70 + "\n")
    
    config = load_config()
    if config:
        print("✓ Configuration loaded successfully")
        print(f"  • Workspace: {config.get('sentinel_workspace_id', 'N/A')[:8]}...")
        print(f"  • Tenant: {config.get('tenant_id', 'N/A')[:8]}...")
    
    # Create guide HTML
    output_path = Path('reports/SigninLogs_Geomap_Guide.html')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(create_geomap_template())
    
    print(f"\n✓ Guide created: {output_path}")
    
    # Print summary
    print("\n" + "="*70)
    print("📋 RECOMMENDED NEXT STEPS:")
    print("="*70)
    print("""
1. Open the guide (SigninLogs_Geomap_Guide.html) to review query patterns

2. Choose your analysis type:
   • Failed sign-ins (attack origins)
   • All sign-ins (global usage patterns)
   • Risky sign-ins (identity protection alerts)
   • MFA failures (account compromise indicators)

3. Execute the KQL query in your Sentinel workspace:
   Go to Azure Sentinel → Logs → Paste query → Run

4. Save results as JSON with IP, count, and location data

5. Enrich IPs with geographic coordinates:
   python enrich_ips.py --file <your_results.json>

6. Generate the geomap visualization with the enriched data

7. Click markers on the map to drill into threat intelligence
    """)
    
    print("="*70)
    print("✨ Guide ready at: reports/SigninLogs_Geomap_Guide.html\n")

if __name__ == "__main__":
    main()
