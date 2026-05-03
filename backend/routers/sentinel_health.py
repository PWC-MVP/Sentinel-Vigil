from fastapi import APIRouter, Query
from backend.services.sentinel import run_kql
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/sentinel-health", tags=["sentinel-health"])


@router.get("/overview")
async def get_health_overview(days: int = Query(7)):
    """High-level workspace health: table count, connector freshness, agent status."""
    usage_q = f"""
    Usage
    | where TimeGenerated > ago({days}d)
    | where IsBillable == true
    | summarize TotalGB = sum(Quantity) / 1024, TableCount = dcount(DataType)
    """
    freshness_q = """
    Usage
    | where TimeGenerated > ago(3d)
    | summarize LastReceived = max(TimeGenerated) by DataType
    | extend FreshHours = datetime_diff('hour', now(), LastReceived)
    | summarize
        HealthyCount  = countif(FreshHours < 2),
        StaleCount    = countif(FreshHours between (2 .. 24)),
        CriticalCount = countif(FreshHours > 24)
    """
    heartbeat_q = """
    Heartbeat
    | where TimeGenerated > ago(1d)
    | summarize LastHB = max(TimeGenerated) by Computer
    | extend StaleMin = datetime_diff('minute', now(), LastHB)
    | summarize
        OnlineCount   = countif(StaleMin < 10),
        DegradedCount = countif(StaleMin between (10 .. 60)),
        OfflineCount  = countif(StaleMin > 60)
    """

    try:
        ur = (await run_kql(usage_q, days=days)).get("rows", [{}])
        u = ur[0] if ur else {}
    except Exception:
        u = {}

    try:
        fr = (await run_kql(freshness_q, days=3)).get("rows", [{}])
        f = fr[0] if fr else {}
    except Exception:
        f = {}

    try:
        hr = (await run_kql(heartbeat_q, days=1)).get("rows", [{}])
        h = hr[0] if hr else {}
    except Exception:
        h = {}

    return {
        "total_gb": round(float(u.get("TotalGB", 0)), 2),
        "table_count": int(u.get("TableCount", 0)),
        "healthy_connectors": int(f.get("HealthyCount", 0)),
        "stale_connectors": int(f.get("StaleCount", 0)),
        "critical_connectors": int(f.get("CriticalCount", 0)),
        "agents_online": int(h.get("OnlineCount", 0)),
        "agents_degraded": int(h.get("DegradedCount", 0)),
        "agents_offline": int(h.get("OfflineCount", 0)),
    }


@router.get("/connectors")
async def get_connector_health():
    """Per-table freshness status derived from the Usage table."""
    q = """
    Usage
    | where TimeGenerated > ago(3d)
    | where IsBillable == true
    | summarize
        LastReceived  = max(TimeGenerated),
        DataVolumeMB  = round(sum(Quantity), 2)
      by DataType
    | extend FreshHours = round(
        todouble(datetime_diff('minute', now(), LastReceived)) / 60.0, 1)
    | extend Status = iff(FreshHours < 2, 'Healthy',
                     iff(FreshHours < 24, 'Stale', 'Critical'))
    | sort by FreshHours asc
    | limit 60
    """
    try:
        rows = (await run_kql(q, days=3)).get("rows", [])
        return {
            "connectors": [
                {
                    "table": r.get("DataType", "Unknown"),
                    "last_received": r.get("LastReceived", ""),
                    "freshness_hours": float(r.get("FreshHours", 0)),
                    "volume_mb": float(r.get("DataVolumeMB", 0)),
                    "status": r.get("Status", "Unknown"),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Connector health query failed: %s", e)
        return {"connectors": [], "error": str(e)}


@router.get("/agents")
async def get_agent_health():
    """Connected MMA/AMA agent health from the Heartbeat table."""
    q = """
    Heartbeat
    | where TimeGenerated > ago(2d)
    | summarize
        LastHeartbeat = max(TimeGenerated),
        BeatCount     = count()
      by Computer, OSType
    | extend StaleMin = round(
        todouble(datetime_diff('second', now(), LastHeartbeat)) / 60.0, 1)
    | extend Status = iff(StaleMin < 10, 'Online',
                     iff(StaleMin < 60, 'Degraded', 'Offline'))
    | sort by StaleMin asc
    | limit 60
    """
    try:
        rows = (await run_kql(q, days=2)).get("rows", [])
        return {
            "agents": [
                {
                    "name": r.get("Computer", "Unknown"),
                    "os": r.get("OSType", "Unknown"),
                    "last_heartbeat": r.get("LastHeartbeat", ""),
                    "stale_minutes": float(r.get("StaleMin", 0)),
                    "status": r.get("Status", "Unknown"),
                    "beat_count": int(r.get("BeatCount", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Agent health query failed: %s", e)
        return {"agents": [], "error": str(e)}


@router.get("/data-gaps")
async def get_data_gaps(days: int = Query(7)):
    """Tables that received data on fewer days than expected — possible ingestion gaps."""
    q = f"""
    Usage
    | where TimeGenerated > ago({days}d)
    | where IsBillable == true
    | summarize DailyGB = sum(Quantity) / 1024
        by bin(TimeGenerated, 1d), DataType
    | where DailyGB > 0
    | summarize
        DaysWithData = dcount(bin(TimeGenerated, 1d)),
        TotalGB      = round(sum(DailyGB), 3),
        AvgDailyGB   = round(avg(DailyGB), 3)
      by DataType
    | where DaysWithData < {days}
    | extend GapDays = {days} - DaysWithData
    | sort by GapDays desc
    | limit 25
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "gaps": [
                {
                    "table": r.get("DataType", "Unknown"),
                    "days_with_data": int(r.get("DaysWithData", 0)),
                    "gap_days": int(r.get("GapDays", 0)),
                    "total_gb": float(r.get("TotalGB", 0)),
                    "avg_daily_gb": float(r.get("AvgDailyGB", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Data gaps query failed: %s", e)
        return {"gaps": [], "error": str(e)}


@router.get("/ingestion-trend")
async def get_ingestion_trend(days: int = Query(14)):
    """Daily ingestion volume trend for the workspace."""
    q = f"""
    Usage
    | where TimeGenerated > ago({days}d)
    | where IsBillable == true
    | summarize DailyGB = round(sum(Quantity) / 1024, 2)
        by bin(TimeGenerated, 1d)
    | sort by TimeGenerated asc
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "trend": [
                {
                    "date": r.get("TimeGenerated", "")[:10],
                    "gb": float(r.get("DailyGB", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Ingestion trend query failed: %s", e)
        return {"trend": [], "error": str(e)}
