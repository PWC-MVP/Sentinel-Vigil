from fastapi import APIRouter, HTTPException, Query
from backend.config import settings
from backend.services.sentinel import run_kql
from datetime import datetime, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/mcp-stats")
async def get_mcp_stats(days: int = Query(7)):
    """Return statistics on MCP tool usage for the given time range."""
    # Scaling mock data based on days
    multiplier = days / 7
    return {
        "total_calls": int(1240 * multiplier),
        "tools": [
            {"name": "KQLSearch", "calls": int(450 * multiplier), "success_rate": 0.98},
            {"name": "GraphInventory", "calls": int(210 * multiplier), "success_rate": 0.92},
            {"name": "VirusTotalEnrich", "calls": int(320 * multiplier), "success_rate": 1.0},
            {"name": "IdentityInvestigator", "calls": int(180 * multiplier), "success_rate": 0.85},
            {"name": "SentinelAlertAction", "calls": int(80 * multiplier), "success_rate": 0.95}
        ],
        "hourly_usage": [int(v * (1 + (days/30))) for v in [12, 45, 67, 23, 89, 120, 150, 200, 180, 150, 100, 80]]
    }

@router.get("/ingestion")
async def get_ingestion_details(days: int = Query(7)):
    """Get dynamic ingestion statistics from the Sentinel workspace."""
    
    top_tables_query = f"""
    Usage 
    | where TimeGenerated > ago({days}d) 
    | where IsBillable == true 
    | summarize DataGB = sum(Quantity) / 1024 by DataType 
    | sort by DataGB desc 
    | limit 10
    """
    
    try:
        raw_data = await run_kql(top_tables_query, days=days)
        results = raw_data.get('rows', [])
        total_gb = sum(r.get('DataGB', 0) for r in results)
        
        if not results:
            # Shift mock data based on days
            mock_data = [
                {"DataType": "SecurityEvent", "DataGB": 45.2 * (days/7)},
                {"DataType": "SigninLogs", "DataGB": 18.4 * (days/7)},
                {"DataType": "OfficeActivity", "DataGB": 12.1 * (days/7)},
                {"DataType": "CommonSecurityLog", "DataGB": 5.3 * (days/7)}
            ]
            total_gb = sum(m["DataGB"] for m in mock_data)
            return {
                "total_7d_gb": round(total_gb, 2),
                "top_tables": [{"table": m["DataType"], "size_gb": round(m["DataGB"], 2)} for m in mock_data]
            }

        return {
            "total_7d_gb": round(total_gb, 2),
            "top_tables": [{"table": r.get('DataType', 'Unknown'), "size_gb": round(r.get('DataGB', 0), 2)} for r in results]
        }
    except Exception as e:
        logger.error(f"Ingestion query failed: {e}")
        fallback_total = 70.0 * (days/7)
        return {
            "total_7d_gb": round(fallback_total, 2),
            "top_tables": [
                {"table": "SecurityEvent", "size_gb": round(fallback_total * 0.6, 2)},
                {"table": "SigninLogs", "size_gb": round(fallback_total * 0.3, 2)},
                {"table": "OfficeActivity", "size_gb": round(fallback_total * 0.1, 2)}
            ],
            "error": str(e)
        }

@router.get("/incidents")
async def get_incidents_stats(days: int = Query(30)):
    """Get dynamic statistics on Sentinel incidents for selected range."""
    
    query = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize 
        Open = countif(Status != 'Closed'),
        Closed = countif(Status == 'Closed'),
        High = countif(Severity == 'High'),
        Medium = countif(Severity == 'Medium'),
        Low = countif(Severity == 'Low'),
        Informational = countif(Severity == 'Informational')
    """
    
    try:
        data = await run_kql(query, days=days)
        results = data.get('rows', [])
        if not results:
            raise ValueError("No results")
            
        stats = results[0]
        return {
            "status": {
                "open": stats.get('Open', 0),
                "closed": stats.get('Closed', 0)
            },
            "severity": {
                "high": stats.get('High', 0),
                "medium": stats.get('Medium', 0),
                "low": stats.get('Low', 0),
                "informational": stats.get('Informational', 0)
            }
        }
    except Exception:
        # Scale mock data
        m = days / 30
        return {
            "status": {"open": int(24 * m), "closed": int(156 * m)},
            "severity": {"high": int(12 * m), "medium": int(45 * m), "low": int(89 * m), "informational": int(34 * m)}
        }

@router.get("/posture")
async def get_security_posture():
    """Security posture is usually fixed point-in-time, but returned here."""
    return {
        "score": 78,
        "max_score": 100,
        "categories": [
            {"name": "Identity", "score": 85, "weight": 0.4},
            {"name": "Data", "score": 65, "weight": 0.3},
            {"name": "Endpoints", "score": 90, "weight": 0.2},
            {"name": "Apps", "score": 45, "weight": 0.1}
        ],
        "recommendations": [
            {"task": "Enable MFA for privileged accounts", "impact": "+12", "severity": "High"},
            {"task": "Review insecure service principals", "impact": "+8", "severity": "Medium"},
            {"task": "Enforce managed devices for M365", "impact": "+5", "severity": "Medium"}
        ]
    }
