from collections import defaultdict
from fastapi import APIRouter, Query
from backend.services.sentinel import run_kql
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incident-analytics", tags=["incident-analytics"])


@router.get("/mttr")
async def get_mttr(days: int = Query(30)):
    """Mean / median / P90 / P95 time-to-resolve metrics, overall and by severity."""
    overall_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed"
        and isnotempty(ClosedTime) and isnotempty(CreatedTime)
    | extend MTTR_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
    | where MTTR_Hours >= 0 and MTTR_Hours < 8760
    | summarize
        AvgMTTR    = round(avg(MTTR_Hours),            1),
        MedianMTTR = round(percentile(MTTR_Hours, 50), 1),
        P90MTTR    = round(percentile(MTTR_Hours, 90), 1),
        P95MTTR    = round(percentile(MTTR_Hours, 95), 1),
        MinMTTR    = min(MTTR_Hours),
        MaxMTTR    = max(MTTR_Hours),
        TotalClosed= count()
    """
    sev_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed"
        and isnotempty(ClosedTime) and isnotempty(CreatedTime)
    | extend MTTR_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
    | where MTTR_Hours >= 0 and MTTR_Hours < 8760
    | summarize
        AvgMTTR = round(avg(MTTR_Hours), 1),
        Count   = count()
      by Severity
    | sort by AvgMTTR asc
    """

    try:
        r = ((await run_kql(overall_q, days=days)).get("rows", [{}]) or [{}])[0]
    except Exception as e:
        logger.error("MTTR overall failed: %s", e)
        r = {}

    try:
        sev_rows = (await run_kql(sev_q, days=days)).get("rows", [])
    except Exception:
        sev_rows = []

    return {
        "avg_hours": float(r.get("AvgMTTR", 0)),
        "median_hours": float(r.get("MedianMTTR", 0)),
        "p90_hours": float(r.get("P90MTTR", 0)),
        "p95_hours": float(r.get("P95MTTR", 0)),
        "min_hours": float(r.get("MinMTTR", 0)),
        "max_hours": float(r.get("MaxMTTR", 0)),
        "total_closed": int(r.get("TotalClosed", 0)),
        "by_severity": [
            {
                "severity": row.get("Severity", "Unknown"),
                "avg_hours": float(row.get("AvgMTTR", 0)),
                "count": int(row.get("Count", 0)),
            }
            for row in sev_rows
        ],
    }


@router.get("/trends")
async def get_incident_trends(days: int = Query(30)):
    """Daily incident creation counts by severity."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize Count = count()
        by bin(CreatedTime, 1d), Severity
    | sort by CreatedTime asc
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        by_date: dict = defaultdict(lambda: {"High": 0, "Medium": 0, "Low": 0, "Informational": 0})
        for r in rows:
            date = (r.get("CreatedTime") or "")[:10]
            sev = r.get("Severity", "Informational")
            if sev in by_date[date]:
                by_date[date][sev] += int(r.get("Count", 0))
        return {"daily": [{"date": d, **c} for d, c in sorted(by_date.items())]}
    except Exception as e:
        logger.error("Trends query failed: %s", e)
        return {"daily": [], "error": str(e)}


@router.get("/owners")
async def get_incident_owners(days: int = Query(30)):
    """Incident distribution by assigned owner."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | extend OwnerName = iff(
        isempty(Owner) or Owner == "null" or Owner == "{{}}",
        "Unassigned",
        coalesce(
            tostring(todynamic(Owner).userPrincipalName),
            tostring(todynamic(Owner).assignedTo),
            "Unassigned"
        )
      )
    | extend OwnerName = iff(OwnerName == "null" or OwnerName == "", "Unassigned", OwnerName)
    | summarize
        Total  = count(),
        Open   = countif(Status in ("Active", "New")),
        Closed = countif(Status =~ "Closed")
      by OwnerName
    | sort by Total desc
    | limit 15
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "owners": [
                {
                    "name": r.get("OwnerName", "Unknown"),
                    "total": int(r.get("Total", 0)),
                    "open": int(r.get("Open", 0)),
                    "closed": int(r.get("Closed", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Owners query failed: %s", e)
        return {"owners": [], "error": str(e)}


@router.get("/sla")
async def get_sla_compliance(days: int = Query(30)):
    """SLA compliance per severity tier (High=4h, Medium=8h, Low=24h, Info=72h)."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed" and isnotempty(ClosedTime)
    | extend MTTR_Hours = datetime_diff('hour', ClosedTime, CreatedTime)
    | extend SLATarget = case(
        Severity =~ "High",          4,
        Severity =~ "Medium",        8,
        Severity =~ "Low",          24,
        72
    )
    | extend SLAMet = MTTR_Hours <= SLATarget
    | summarize
        Total          = count(),
        SLAMet         = countif(SLAMet),
        SLABreached    = countif(not(SLAMet)),
        AvgMTTR        = round(avg(MTTR_Hours), 1)
      by Severity, SLATarget
    | extend ComplianceRate = round(100.0 * SLAMet / Total, 1)
    | sort by SLATarget asc
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "sla": [
                {
                    "severity": r.get("Severity", "Unknown"),
                    "sla_target_hours": int(r.get("SLATarget", 0)),
                    "total": int(r.get("Total", 0)),
                    "sla_met": int(r.get("SLAMet", 0)),
                    "sla_breached": int(r.get("SLABreached", 0)),
                    "compliance_rate": float(r.get("ComplianceRate", 0)),
                    "avg_mttr": float(r.get("AvgMTTR", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("SLA query failed: %s", e)
        return {"sla": [], "error": str(e)}


@router.get("/summary")
async def get_incident_summary(days: int = Query(30)):
    """Quick counts for the stat tile row."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        Total         = count(),
        Open          = countif(Status in ("Active", "New")),
        Closed        = countif(Status =~ "Closed"),
        HighCount     = countif(Severity =~ "High"),
        AvgFirstResp  = round(avg(
            datetime_diff('hour', FirstActivityTime, CreatedTime)
        ), 1)
    """
    try:
        r = ((await run_kql(q, days=days)).get("rows", [{}]) or [{}])[0]
        return {
            "total": int(r.get("Total", 0)),
            "open": int(r.get("Open", 0)),
            "closed": int(r.get("Closed", 0)),
            "high_count": int(r.get("HighCount", 0)),
            "avg_first_resp_hours": float(r.get("AvgFirstResp", 0)),
        }
    except Exception as e:
        logger.error("Incident summary failed: %s", e)
        return {"total": 0, "open": 0, "closed": 0, "high_count": 0, "avg_first_resp_hours": 0}
