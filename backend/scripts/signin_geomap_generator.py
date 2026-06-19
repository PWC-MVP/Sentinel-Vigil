#!/usr/bin/env python3
"""
Query Sentinel SigninLogs and generate geomap visualization
This script queries real data and creates the geographic visualization
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

class SigninGeoMapGenerator:
    """Generate geomap from SigninLogs pattern analysis."""
    
    def __init__(self):
        self.config = self._load_config()
        self.workspace_id = self.config.get('sentinel_workspace_id') if self.config else None
        
    def _load_config(self) -> Optional[Dict]:
        """Load workspace configuration."""
        config_path = Path('config.json')
        if not config_path.exists():
            print("⚠️ config.json not found - cannot query workspace")
            return None
        
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def query_failed_signins(self, days: int = 7, limit: int = 100) -> Dict[str, Any]:
        """
        Query failed sign-ins by geographic location.
        Uses KQL to extract IPs with failure counts.
        """
        
        kql = f'''
SigninLogs
| where TimeGenerated > ago({days}d)
| where ResultType != 0
| where IPAddress != "127.0.0.1" and IPAddress != "::1"
| summarize 
    value = count(),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated),
    result_types = make_set(ResultType)
    by ip = IPAddress
| order by value desc
| take {limit}
'''
        
        return {
            'kql': kql,
            'description': 'Failed sign-ins by IP (attack origins)',
            'color_scale': 'blue-red',
            'title': f'Failed Sign-in Origins (Last {days} Days)',
            'value_label': 'Failed Attempts'
        }
    
    def query_risky_signins(self, days: int = 7, limit: int = 50) -> Dict[str, Any]:
        """
        Query risky sign-ins flagged by Azure AD Identity Protection.
        """
        
        kql = f'''
SigninLogs
| where TimeGenerated > ago({days}d)
| where RiskState in ("atRisk", "confirmedCompromised")
| summarize 
    value = count(),
    risk_state = take_any(RiskState),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated)
    by ip = IPAddress
| order by value desc
| take {limit}
'''
        
        return {
            'kql': kql,
            'description': 'Risky sign-ins by IP (Identity Protection alerts)',
            'color_scale': 'blue-red',
            'title': f'Risky Sign-in Origins (Last {days} Days)',
            'value_label': 'Risk Count'
        }
    
    def query_all_signins(self, days: int = 7, limit: int = 100, min_count: int = 5) -> Dict[str, Any]:
        """
        Query all sign-ins (success + failure) by geographic location.
        """
        
        kql = f'''
SigninLogs
| where TimeGenerated > ago({days}d)
| where IPAddress != "127.0.0.1" and IPAddress != "::1"
| summarize 
    value = count(),
    success_count = dcountif(ResultType, ResultType == 0),
    failed_count = dcountif(ResultType, ResultType != 0),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated)
    by ip = IPAddress
| where value >= {min_count}
| order by value desc
| take {limit}
'''
        
        return {
            'kql': kql,
            'description': 'All sign-ins by IP (global usage patterns)',
            'color_scale': 'green-red',
            'title': f'Global Sign-in Patterns (Last {days} Days)',
            'value_label': 'Total Attempts'
        }
    
    def query_mfa_failures(self, days: int = 7, limit: int = 100) -> Dict[str, Any]:
        """
        Query MFA failure attempts by geographic location.
        Result type 500127 indicates MFA failure.
        """
        
        kql = f'''
SigninLogs
| where TimeGenerated > ago({days}d)
| where ResultType == 500127 or ResultType == 500126
| where IPAddress != "127.0.0.1" and IPAddress != "::1"
| summarize 
    value = count(),
    unique_users = dcount(UserPrincipalName),
    latest_time = max(TimeGenerated)
    by ip = IPAddress
| order by value desc
| take {limit}
'''
        
        return {
            'kql': kql,
            'description': 'MFA failures by IP (account compromise indicators)',
            'color_scale': 'blue-red',
            'title': f'MFA Failures by Location (Last {days} Days)',
            'value_label': 'MFA Failures'
        }
    
    def save_query_examples(self):
        """Save KQL query examples to files for manual execution."""
        
        queries_dir = Path('temp/signin_kql_queries')
        queries_dir.mkdir(parents=True, exist_ok=True)
        
        examples = {
            'failed_signins.kql': self.query_failed_signins()['kql'],
            'risky_signins.kql': self.query_risky_signins()['kql'],
            'all_signins.kql': self.query_all_signins()['kql'],
            'mfa_failures.kql': self.query_mfa_failures()['kql'],
        }
        
        for filename, kql in examples.items():
            filepath = queries_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(kql.strip())
        
        print(f"✓ Query examples saved to: {queries_dir}/")
        for filename in examples:
            print(f"  • {filename}")
        
        return queries_dir
    
    def create_execution_guide(self):
        """Create a step-by-step execution guide."""
        
        guide = '''
# Sign-in Logs Geographic Geomap - Execution Guide

## Overview
This guide provides KQL queries to analyze sign-in patterns geographically and create a world map visualization.

## Query Files
- failed_signins.kql - Attack origins (failed authentication only)
- risky_signins.kql - Identity Protection alerts
- all_signins.kql - Global usage patterns (success + failure)
- mfa_failures.kql - MFA failure attempts

## Step-by-Step Execution

### Step 1: Choose Your Analysis Type

**For Attack Origin Mapping:**
Use: failed_signins.kql
- Shows brute-force attempts, credential spray origins
- Best for: Security incident investigation
- Time period: 7-30 days

**For Risk Assessment:**
Use: risky_signins.kql
- Shows IPs flagged by Identity Protection
- Best for: Compliance/risk reporting
- Time period: 7-14 days

**For Global Usage Baseline:**
Use: all_signins.kql
- Shows all sign-in locations and volumes
- Best for: Establishing baseline patterns
- Time period: 30-90 days

**For Anomaly Detection:**
Use: mfa_failures.kql
- Shows MFA attack locations
- Best for: Compromise detection
- Time period: 7 days

### Step 2: Execute Query in Azure Sentinel

1. Go to Azure Sentinel → Logs
2. Choose your workspace: Infosec-Sentinel-LAW
3. Open temp/signin_kql_queries/{your_query}.kql
4. Copy and paste into the KQL editor
5. Click "Run"
6. Export results as CSV

### Step 3: Prepare Data for Enrichment

Convert results to JSON format:
```json
{
  "ips": [
    {"ip": "203.0.113.42", "value": 127},
    {"ip": "198.51.100.10", "value": 85}
  ]
}
```

Save as: temp/signin_data.json

### Step 4: Enrich IPs with Geographic Data

Run the enrichment script:
```
python enrich_ips.py --file temp/signin_data.json
```

This will:
- Query ipinfo.io for latitude/longitude
- Query AbuseIPDB for reputation data
- Query vpnapi.io for proxy/VPN detection
- Query Shodan for additional intel

Output: temp/ip_enrichment_<timestamp>.json

### Step 5: Format Data for Geomap

Parse the enrichment output and create geomap format:
```json
{
  "data": [
    {
      "ip": "203.0.113.42",
      "lat": 22.25,
      "lon": 114.15,
      "value": 127
    }
  ],
  "title": "Failed Sign-in Origins",
  "valueLabel": "Failed Attempts",
  "colorScale": "blue-red",
  "enrichment": [
    {
      "ip": "203.0.113.42",
      "city": "Hong Kong",
      "country": "HK",
      "org": "AS135377 UCLOUD",
      "is_vpn": true,
      "abuse_confidence_score": 95,
      "threat_categories": ["SSH", "Brute-Force"]
    }
  ]
}
```

### Step 6: Generate Geomap

Use the Sentinel Geomap MCP tool with the formatted data.
The visualization will show:
- World map with marker clusters
- Color intensity for activity volume
- Hover tooltips with IP details
- Click-to-expand threat intelligence panels

## Tips & Best Practices

1. **Start with Failed Sign-ins** - Easiest to interpret, clearest patterns
2. **Filter by Volume** - Use `| where value > 10` to reduce noise
3. **Time Window** - 7 days for attacks, 30 days for baseline
4. **Compare Patterns** - Run multiple analyses to spot anomalies
5. **Drill Down** - Click markers to investigate specific IPs
6. **Export Results** - Save geomap for reporting/presentations

## Common Patterns to Watch For

- **Distributed Attacks:** Many IPs, same country
- **Impossible Travel:** Geographic locations with implausible transit times
- **Cloud Hosting IPs:** Legitimate or attackers using cloud infrastructure
- **VPN/Proxy Usage:** Potential account compromise or security bypass
- **Off-Hours Activity:** Suspicious authentication outside business hours

## Troubleshooting

**No Results:**
- Verify workspace ID in config.json
- Check date range (TimeGenerated filter)
- Ensure SigninLogs table has data for period

**Missing Geographic Data:**
- IP enrichment requires API keys in config.json
- Some private IPs cannot be enriched (filtered automatically)
- IPv6 addresses require special handling

**Slow Query Execution:**
- Reduce time window (use 7d instead of 90d)
- Filter by specific countries or IP ranges
- Use `| take` to limit results

## Next Steps

1. Review query examples in temp/signin_kql_queries/
2. Execute one query in Azure Sentinel
3. Export results to temp/signin_data.json
4. Run enrich_ips.py to add geographic data
5. Generate the geomap visualization
6. Click markers to drill into threat intelligence
7. Create reports and dashboards

## Files Generated

- temp/signin_kql_queries/ - KQL query templates
- temp/signin_data.json - Your extracted data
- temp/ip_enrichment_*.json - Enriched IP data with coordinates
- reports/SigninLogs_Geomap_* - Generated visualizations

---

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Workspace: Infosec-Sentinel-LAW
'''
        
        guide_path = Path('temp/SigninGeomap_ExecutionGuide.md')
        with open(guide_path, 'w', encoding='utf-8') as f:
            f.write(guide)
        
        return guide_path

def main():
    """Main execution."""
    
    print("\n" + "="*75)
    print("🗺️ SIGN-IN LOGS GEOMAP GENERATOR")
    print("="*75 + "\n")
    
    generator = SigninGeoMapGenerator()
    
    if not generator.workspace_id:
        print("⚠️ Cannot proceed without workspace configuration")
        print("   Please ensure config.json is properly configured\n")
        return
    
    print(f"✓ Workspace loaded: {generator.workspace_id[:8]}...\n")
    
    # Save query examples
    print("📋 Saving KQL query examples...")
    queries_dir = generator.save_query_examples()
    
    # Create execution guide
    print("\n📖 Creating execution guide...")
    guide_path = generator.create_execution_guide()
    print(f"✓ Guide saved: {guide_path}\n")
    
    # Summary
    print("="*75)
    print("✨ QUICK START\n")
    print("1. Review queries in: temp/signin_kql_queries/")
    print("2. Read guide: temp/SigninGeomap_ExecutionGuide.md")
    print("3. Choose your analysis type (failed, risky, all, mfa)")
    print("4. Execute KQL in Azure Sentinel")
    print("5. Export results to: temp/signin_data.json")
    print("6. Enrich IPs: python enrich_ips.py --file temp/signin_data.json")
    print("7. Generate geomap with enriched data\n")
    print("="*75 + "\n")
    
    # Query summaries
    print("📊 AVAILABLE ANALYSIS TYPES:\n")
    
    analyses = [
        generator.query_failed_signins(),
        generator.query_risky_signins(),
        generator.query_all_signins(),
        generator.query_mfa_failures(),
    ]
    
    for i, analysis in enumerate(analyses, 1):
        print(f"{i}. {analysis['description']}")
        print(f"   Title: {analysis['title']}")
        print(f"   Color Scale: {analysis['color_scale']}")
        print()

if __name__ == "__main__":
    main()
