from collections import defaultdict
from fastapi import APIRouter, Query
from backend.services.sentinel import run_kql
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analytics-rules", tags=["analytics-rules"])


@router.get("/overview")
async def get_rules_overview(days: int = Query(30)):
    """Aggregate SecurityAlert counts across all active detection rules."""
    q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | summarize
        TotalAlerts   = count(),
        UniqueRules   = dcount(AlertName),
        HighAlerts    = countif(AlertSeverity =~ "High"),
        MediumAlerts  = countif(AlertSeverity =~ "Medium"),
        LowAlerts     = countif(AlertSeverity =~ "Low")
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [{}])
        r = rows[0] if rows else {}
        return {
            "total_alerts": int(r.get("TotalAlerts", 0)),
            "unique_rules": int(r.get("UniqueRules", 0)),
            "high_alerts": int(r.get("HighAlerts", 0)),
            "medium_alerts": int(r.get("MediumAlerts", 0)),
            "low_alerts": int(r.get("LowAlerts", 0)),
        }
    except Exception as e:
        logger.error("Rules overview failed: %s", e)
        return {
            "total_alerts": 0, "unique_rules": 0,
            "high_alerts": 0, "medium_alerts": 0, "low_alerts": 0,
            "error": str(e),
        }


@router.get("/activity")
async def get_rule_activity(days: int = Query(30)):
    """Per-rule alert firing statistics, sorted by volume."""
    q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | summarize
        AlertCount      = count(),
        LastFired       = max(TimeGenerated),
        FirstFired      = min(TimeGenerated),
        LinkedIncidents = dcount(SystemAlertId)
      by AlertName, ProductName, AlertSeverity
    | sort by AlertCount desc
    | limit 40
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "rules": [
                {
                    "name": r.get("AlertName", "Unknown"),
                    "product": r.get("ProductName", ""),
                    "severity": r.get("AlertSeverity", "Unknown"),
                    "alert_count": int(r.get("AlertCount", 0)),
                    "last_fired": r.get("LastFired", ""),
                    "first_fired": r.get("FirstFired", ""),
                    "linked_incidents": int(r.get("LinkedIncidents", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Rule activity failed: %s", e)
        return {"rules": [], "error": str(e)}


@router.get("/by-tactic")
async def get_alerts_by_tactic(days: int = Query(30)):
    """Alerts grouped by MITRE ATT&CK tactic."""
    q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | where isnotempty(Tactics)
    | summarize
        AlertCount  = count(),
        UniqueRules = dcount(AlertName)
      by Tactics
    | sort by AlertCount desc
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "tactics": [
                {
                    "tactic": r.get("Tactics", "Unknown"),
                    "alert_count": int(r.get("AlertCount", 0)),
                    "unique_rules": int(r.get("UniqueRules", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Alerts by tactic failed: %s", e)
        return {"tactics": [], "error": str(e)}


@router.get("/trend")
async def get_alert_trend(days: int = Query(30)):
    """Daily alert counts broken down by severity."""
    q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | summarize Count = count() by bin(TimeGenerated, 1d), AlertSeverity
    | sort by TimeGenerated asc
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        by_date: dict = defaultdict(lambda: {"High": 0, "Medium": 0, "Low": 0, "Informational": 0})
        for r in rows:
            date = (r.get("TimeGenerated") or "")[:10]
            sev = r.get("AlertSeverity", "Informational")
            if sev in by_date[date]:
                by_date[date][sev] += int(r.get("Count", 0))
            else:
                by_date[date][sev] = int(r.get("Count", 0))
        return {
            "trend": [{"date": d, **counts} for d, counts in sorted(by_date.items())]
        }
    except Exception as e:
        logger.error("Alert trend failed: %s", e)
        return {"trend": [], "error": str(e)}


@router.get("/silent-rules")
async def get_silent_rules(days: int = Query(30)):
    """Rules that fired previously but have gone silent in the last period — possible broken detections."""
    # Rules that fired > 30 days ago but not in the last `days`
    q = f"""
    SecurityAlert
    | where TimeGenerated > ago(90d)
    | summarize
        LastFired   = max(TimeGenerated),
        TotalAlerts = count()
      by AlertName, ProductName, AlertSeverity
    | where LastFired < ago({days}d)
    | sort by LastFired asc
    | limit 20
    """
    try:
        rows = (await run_kql(q, days=90)).get("rows", [])
        return {
            "silent_rules": [
                {
                    "name": r.get("AlertName", "Unknown"),
                    "product": r.get("ProductName", ""),
                    "severity": r.get("AlertSeverity", "Unknown"),
                    "last_fired": r.get("LastFired", ""),
                    "total_alerts": int(r.get("TotalAlerts", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Silent rules query failed: %s", e)
        return {"silent_rules": [], "error": str(e)}
