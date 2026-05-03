from fastapi import APIRouter, Query
from backend.services.sentinel import run_kql
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/entity-exposure", tags=["entity-exposure"])


@router.get("/risky-users")
async def get_risky_users(days: int = Query(7)):
    """Risky users from IdentityInfo; falls back to SigninLogs risk signals."""
    id_q = f"""
    IdentityInfo
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | where RiskState =~ "atRisk" or RiskLevel in ("high", "medium")
    | project AccountUPN, RiskLevel, RiskState, Department, JobTitle, IsAdministrative
    | extend RiskOrder = case(RiskLevel =~ "high", 1, RiskLevel =~ "medium", 2, 3)
    | sort by RiskOrder asc
    | limit 30
    """
    signin_q = f"""
    SigninLogs
    | where TimeGenerated > ago({days}d)
    | where RiskLevelDuringSignIn in ("high", "medium")
    | summarize
        RiskySignIns     = count(),
        LastRiskySignIn  = max(TimeGenerated),
        Apps             = make_set(AppDisplayName, 5)
      by UserPrincipalName, RiskLevelDuringSignIn
    | sort by RiskySignIns desc
    | limit 30
    """

    try:
        rows = (await run_kql(id_q, days=days)).get("rows", [])
        if rows:
            return {
                "source": "IdentityInfo",
                "users": [
                    {
                        "upn": r.get("AccountUPN", "Unknown"),
                        "risk_level": r.get("RiskLevel", "Unknown"),
                        "risk_state": r.get("RiskState", ""),
                        "department": r.get("Department", ""),
                        "job_title": r.get("JobTitle", ""),
                        "is_admin": bool(r.get("IsAdministrative", False)),
                    }
                    for r in rows
                ],
            }
    except Exception:
        pass

    try:
        rows = (await run_kql(signin_q, days=days)).get("rows", [])
        return {
            "source": "SigninLogs",
            "users": [
                {
                    "upn": r.get("UserPrincipalName", "Unknown"),
                    "risk_level": r.get("RiskLevelDuringSignIn", "Unknown"),
                    "risk_state": "atRisk",
                    "department": "",
                    "job_title": "",
                    "is_admin": False,
                    "risky_signins": int(r.get("RiskySignIns", 0)),
                }
                for r in rows
            ],
        }
    except Exception as e:
        logger.error("Risky users query failed: %s", e)
        return {"source": "error", "users": [], "error": str(e)}


@router.get("/anomalous-behavior")
async def get_anomalous_behavior(days: int = Query(7)):
    """Behavioral anomalies from the BehaviorAnalytics table."""
    q = f"""
    BehaviorAnalytics
    | where TimeGenerated > ago({days}d)
    | where isnotempty(ActivityInsights)
    | summarize
        AnomalyCount  = count(),
        LastAnomaly   = max(TimeGenerated),
        ActivityTypes = make_set(ActivityType, 5)
      by UserName, UserPrincipalName, DeviceName
    | sort by AnomalyCount desc
    | limit 25
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "anomalies": [
                {
                    "user": r.get("UserPrincipalName") or r.get("UserName", "Unknown"),
                    "device": r.get("DeviceName", ""),
                    "anomaly_count": int(r.get("AnomalyCount", 0)),
                    "last_anomaly": r.get("LastAnomaly", ""),
                    "activity_types": r.get("ActivityTypes") or [],
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Anomalous behavior query failed: %s", e)
        return {"anomalies": [], "error": str(e)}


@router.get("/alert-entities")
async def get_top_alert_entities(days: int = Query(30)):
    """Top entities (accounts, hosts, IPs) appearing across SecurityAlerts."""
    q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | where isnotempty(Entities)
    | mv-expand Entity = todynamic(Entities)
    | extend EntityType = tostring(Entity.Type)
    | extend EntityName = coalesce(
        tostring(Entity.HostName),
        tostring(Entity.Address),
        tostring(Entity.Name),
        tostring(Entity.AccountName)
    )
    | where EntityType in ("account", "host", "ip", "url", "file-hash")
    | where isnotempty(EntityName) and EntityName != "null"
    | summarize
        AlertCount  = count(),
        Severities  = make_set(AlertSeverity, 4),
        AlertTypes  = make_set(AlertName, 3),
        LastSeen    = max(TimeGenerated)
      by EntityType, EntityName
    | sort by AlertCount desc
    | limit 35
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "entities": [
                {
                    "type": r.get("EntityType", "Unknown"),
                    "name": r.get("EntityName", "Unknown"),
                    "alert_count": int(r.get("AlertCount", 0)),
                    "severities": r.get("Severities") or [],
                    "alert_types": r.get("AlertTypes") or [],
                    "last_seen": r.get("LastSeen", ""),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Alert entities query failed: %s", e)
        return {"entities": [], "error": str(e)}


@router.get("/risky-hosts")
async def get_risky_hosts(days: int = Query(7)):
    """Hosts with suspicious Windows Security Event activity."""
    q = f"""
    SecurityEvent
    | where TimeGenerated > ago({days}d)
    | where EventID in (4625, 4648, 4728, 4732, 4756, 1102, 4720, 4722, 4724, 4726, 4756)
    | summarize
        EventCount     = count(),
        EventTypes     = make_set(EventID, 8),
        LastSeen       = max(TimeGenerated),
        UniqueAccounts = dcount(Account)
      by Computer
    | sort by EventCount desc
    | limit 25
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "hosts": [
                {
                    "name": r.get("Computer", "Unknown"),
                    "event_count": int(r.get("EventCount", 0)),
                    "event_types": [str(e) for e in (r.get("EventTypes") or [])],
                    "last_seen": r.get("LastSeen", ""),
                    "unique_accounts": int(r.get("UniqueAccounts", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Risky hosts query failed: %s", e)
        return {"hosts": [], "error": str(e)}


@router.get("/overview")
async def get_exposure_overview(days: int = Query(7)):
    """Aggregate counts for the stat tile row."""
    risky_q = f"""
    IdentityInfo
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | where RiskState =~ "atRisk" or RiskLevel in ("high", "medium")
    | count
    """
    ba_q = f"""
    BehaviorAnalytics
    | where TimeGenerated > ago({days}d)
    | where isnotempty(ActivityInsights)
    | summarize dcount(UserPrincipalName)
    """
    host_q = f"""
    SecurityEvent
    | where TimeGenerated > ago({days}d)
    | where EventID in (4625, 1102, 4726)
    | summarize dcount(Computer)
    """
    entity_q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | where isnotempty(Entities)
    | count
    """

    def _safe_int(rows, key):
        if not rows:
            return 0
        r = rows[0]
        for v in r.values():
            try:
                return int(v)
            except Exception:
                pass
        return 0

    results = {}
    for label, q, d in [
        ("risky_users", risky_q, days),
        ("anomalous_users", ba_q, days),
        ("risky_hosts", host_q, days),
        ("alert_entities", entity_q, days),
    ]:
        try:
            rows = (await run_kql(q, days=d)).get("rows", [])
            results[label] = _safe_int(rows, "")
        except Exception:
            results[label] = 0

    return results
