"""
Investigation orchestration service.
Replaces the Copilot + MCP workflow for running user security investigations.
Uses the existing Python code (investigator.py, enrich_ips.py, etc.) directly.
"""
import sys
import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Awaitable

# Add project root to sys.path so we can import investigator.py
ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from investigator import (
    InvestigationResult, AnomalyFinding, IPIntelligence,
    UserProfile, MFAStatus, DeviceInfo, RiskDetection,
    RiskySignIn, UserRiskProfile, DLPEvent, InvestigationConfig,
)
from report_generator import CompactReportGenerator

from backend.config import settings
from backend.services import sentinel as sentinel_svc
from backend.services import graph as graph_svc
from backend.services import jobs as job_svc
from backend.services.investigation_cache import get_cached, set_cached

logger = logging.getLogger(__name__)

# ── KQL Templates (from user-investigation/SKILL.md) ───────────────────────

_KQL_ANOMALIES = """
Signinlogs_Anomalies_KQL_CL
| where DetectedDateTime between (datetime({start}) .. datetime({end}))
| where UserPrincipalName =~ '{upn}'
| extend Severity = case(
    BaselineSize < 3 and AnomalyType startswith "NewNonInteractive", "Informational",
    CountryNovelty and CityNovelty and ArtifactHits >= 20, "High",
    ArtifactHits >= 10, "Medium",
    (CountryNovelty or CityNovelty or StateNovelty), "Medium",
    ArtifactHits >= 5, "Low",
    "Informational")
| project DetectedDateTime, UserPrincipalName, AnomalyType, Value, Severity,
    Country, City, State, CountryNovelty, CityNovelty, StateNovelty,
    ArtifactHits, FirstSeenRecent, BaselineSize, OS, BrowserFamily, RawBrowser
| order by Severity asc, DetectedDateTime desc
| take 20
"""

_KQL_SIGNIN_APPS = """
let start = datetime({start});
let end = datetime({end});
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '{upn}'
| summarize
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    IPAddresses=make_set(IPAddress),
    UniqueLocations=dcount(Location)
    by AppDisplayName
| order by SignInCount desc
| take 10
"""

_KQL_SIGNIN_LOCATIONS = """
let start = datetime({start});
let end = datetime({end});
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '{upn}'
| where isnotempty(Location)
| summarize
    SignInCount=count(),
    SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'),
    IPAddresses=make_set(IPAddress),
    Applications=make_set(AppDisplayName, 5)
    by Location
| order by SignInCount desc
| take 10
"""

_KQL_SIGNIN_FAILURES = """
let start = datetime({start});
let end = datetime({end});
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '{upn}'
| where ResultType != '0'
| summarize
    FailureCount=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Applications=make_set(AppDisplayName, 3),
    Locations=make_set(Location, 3)
    by ResultType, ResultDescription
| order by FailureCount desc
| take 10
"""

_KQL_AUDIT_LOGS = """
AuditLogs
| where TimeGenerated between (datetime({start}) .. datetime({end}))
| where Identity =~ '{upn}' or tostring(InitiatedBy) has '{upn}'
| summarize
    Count=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Operations=make_set(OperationName, 10)
    by Category, Result
| order by Count desc
| take 10
"""

_KQL_OFFICE_ACTIVITY = """
OfficeActivity
| where TimeGenerated between (datetime({start}) .. datetime({end}))
| where UserId =~ '{upn}'
| summarize ActivityCount = count() by RecordType, Operation
| order by ActivityCount desc
| take 10
"""

_KQL_CLOUD_APP_EVENTS = """
CloudAppEvents
| where TimeGenerated between (datetime({start}) .. datetime({end}))
| where AccountDisplayName =~ '{upn}' or AccountObjectId == '{user_id}'
| summarize
    Count = count(),
    IsAdmin = max(tostring(IsAdminOperation)),
    IsExternal = max(tostring(IsExternalUser))
    by ActionType, Application
| order by Count desc
| take 12
"""

_KQL_SECURITY_INCIDENTS = """
let targetUPN = "{upn}";
let targetUserId = "{user_id}";
let start = datetime({start});
let end = datetime({end});
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetUPN or Entities has targetUserId
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where not(tostring(Labels) has "Redirected")
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend ProviderIncidentUrl = tostring(AdditionalData.providerIncidentUrl)
| extend OwnerUPN = tostring(Owner.userPrincipalName)
| summarize
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime),
    LastModifiedTime = any(LastModifiedTime),
    OwnerUPN = any(OwnerUPN),
    ProviderIncidentUrl = any(ProviderIncidentUrl),
    AlertCount = count()
    by ProviderIncidentId
| order by LastModifiedTime desc
| take 10
"""

_KQL_IP_SELECTION = """
let start = datetime({start});
let end = datetime({end});
let upn = '{upn}';
let anomaly_ips =
    Signinlogs_Anomalies_KQL_CL
    | where DetectedDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where AnomalyType endswith "IP"
    | summarize AnomalyCount = count(), FirstSeen = min(DetectedDateTime) by IPAddress = Value
    | order by AnomalyCount desc, FirstSeen asc
    | take 8
    | extend Priority = 1, Source = "Anomaly";
let frequent_ips =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ upn
    | summarize SignInCount = count(), FirstSeen = min(TimeGenerated) by IPAddress
    | order by SignInCount desc, FirstSeen asc
    | take 7
    | extend Priority = 3, Source = "Frequent";
let anomaly_ip_list = anomaly_ips | project IPAddress;
let frequent_slot = frequent_ips
    | join kind=anti anomaly_ip_list on IPAddress
    | take 7;
union anomaly_ips, frequent_slot
| project IPAddress, Priority, Source
| order by Priority asc
| project IPAddress
"""

_KQL_THREAT_INTEL = """
let target_ips = dynamic({ips_json});
ThreatIntelIndicators
| extend IndicatorType = replace_string(replace_string(replace_string(tostring(split(ObservableKey, ":", 0)), "[", ""), "]", ""), "\\"", "")
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| extend NetworkSourceIP = toupper(ObservableValue)
| where NetworkSourceIP in (target_ips)
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| summarize arg_max(TimeGenerated, *) by NetworkSourceIP
| project IPAddress = NetworkSourceIP, ThreatDescription = Description, Confidence, IsActive
| order by Confidence desc
"""


# ── Investigation runner ────────────────────────────────────────────────────

async def run_investigation(
    job_id: str,
    upn: str,
    start_date: str,
    end_date: str,
    output_mode: str = "inline",
    include_cloud: bool = True,
    include_office: bool = True,
    include_audit: bool = True,
    include_identity: bool = True,
    generate_summary: bool = False,
) -> dict[str, Any]:
    """
    Full investigation workflow — runs all data collection phases in parallel,
    then assembles the result and optionally generates an HTML report.

    Emits progress updates to the job queue for WebSocket streaming.
    """

    async def emit(phase: str, message: str, data: Any = None):
        await job_svc.emit(job_id, phase, message, data)

    # Compute days_back for cache key
    try:
        _start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        _end   = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        _days_back = max(1, (_end - _start).days)
    except Exception:
        _days_back = 0

    if _days_back:
        cached = await get_cached(upn, _days_back)
        if cached:
            await emit("start", f"⚡ Returning cached investigation for {upn}")
            return cached

    await emit("start", f"🔍 Starting investigation for {upn}")
    await emit("start", f"📅 Date range: {start_date} → {end_date}")

    fmt = dict(upn=upn, start=start_date, end=end_date, user_id="")

    # ── Phase 1: Get User Object ID ──────────────────────────────────────
    await emit("identity", "👤 Fetching user profile + identity data from Graph API...")
    try:
        user_data = await graph_svc.get_user(upn)
        user_id = user_data.get("id", "")
        fmt["user_id"] = user_id
    except Exception as e:
        await emit("identity", f"⚠️ Graph API user fetch failed: {e}")
        user_data = {}
        user_id = ""

    # ── Phase 2: Parallel data collection ───────────────────────────────
    await emit("queries", "⚡ Running parallel data collection (Sentinel + Graph)...")

    async def safe_kql(name: str, query: str) -> list[dict]:
        try:
            result = await sentinel_svc.run_kql(query.format(**fmt))
            await emit("queries", f"  ✓ {name}: {result['row_count']} rows")
            return result["rows"]
        except Exception as e:
            await emit("queries", f"  ⚠️ {name} failed: {e}")
            return []

    # Run Sentinel queries in parallel
    sentinel_tasks = [
        safe_kql("Anomalies", _KQL_ANOMALIES),
        safe_kql("Sign-in by app", _KQL_SIGNIN_APPS),
        safe_kql("Sign-in by location", _KQL_SIGNIN_LOCATIONS),
        safe_kql("Sign-in failures", _KQL_SIGNIN_FAILURES),
    ]
    
    if include_audit: sentinel_tasks.append(safe_kql("Audit logs", _KQL_AUDIT_LOGS))
    else: sentinel_tasks.append(asyncio.sleep(0, result=[])) # dummy
    
    if include_office: sentinel_tasks.append(safe_kql("Office 365 activity", _KQL_OFFICE_ACTIVITY))
    else: sentinel_tasks.append(asyncio.sleep(0, result=[]))
    
    if include_cloud: sentinel_tasks.append(safe_kql("Cloud app events", _KQL_CLOUD_APP_EVENTS))
    else: sentinel_tasks.append(asyncio.sleep(0, result=[]))
    
    sentinel_tasks.extend([
        safe_kql("IP selection", _KQL_IP_SELECTION),
        safe_kql("Security incidents", _KQL_SECURITY_INCIDENTS),
    ])

    results = await asyncio.gather(*sentinel_tasks)
    (
        anomaly_rows,
        signin_app_rows,
        signin_loc_rows,
        signin_fail_rows,
        audit_rows,
        office_rows,
        cloud_app_rows,
        ip_rows,
        incident_rows,
    ) = results

    # ── Phase 3: Graph identity data in parallel ──────────────────────
    await emit("identity", "🔐 Fetching MFA, devices, and Identity Protection data...")

    graph_tasks = []
    if user_id and include_identity:
        graph_tasks = await asyncio.gather(
            _safe_graph("MFA methods", graph_svc.get_mfa_methods, user_id),
            _safe_graph("Devices", graph_svc.get_user_devices, user_id),
            _safe_graph("Risk profile", graph_svc.get_user_risk_profile, user_id),
            _safe_graph("Risk detections", graph_svc.get_risk_detections, user_id),
            _safe_graph("Risky sign-ins", graph_svc.get_risky_signins, user_id),
            return_exceptions=True,
        )
        mfa_raw, devices_raw, risk_profile_raw, risk_detections_raw, risky_signins_raw = graph_tasks
    else:
        mfa_raw = {} if user_id else []
        devices_raw = risk_profile_raw = risk_detections_raw = risky_signins_raw = []

    # ── Phase 4: Threat intel IP lookup ──────────────────────────────────
    collected_ips = [r.get("IPAddress", "") for r in ip_rows if r.get("IPAddress")]
    threat_rows: list[dict] = []
    if collected_ips:
        await emit("threat_intel", f"🛡️ Checking {len(collected_ips)} IPs against Threat Intelligence...")
        try:
            ips_json = json.dumps(collected_ips)
            threat_result = await sentinel_svc.run_kql(
                _KQL_THREAT_INTEL.format(ips_json=ips_json)
            )
            threat_rows = threat_result["rows"]
            await emit("threat_intel", f"  ✓ Threat intel: {len(threat_rows)} matches")
        except Exception as e:
            await emit("threat_intel", f"  ⚠️ Threat intel failed: {e}")

    # ── Phase 5: IP enrichment ────────────────────────────────────────────
    await emit("enrichment", f"🌐 Enriching {len(collected_ips)} IPs via threat intelligence APIs...")
    ip_intelligence = await _enrich_ips(collected_ips, threat_rows, anomaly_rows, emit)

    # ── Phase 6: Build result dict ────────────────────────────────────────
    await emit("assembly", "📊 Assembling investigation results...")

    # Build user profile
    user_profile = None
    if user_data:
        user_profile = {
            "display_name": user_data.get("displayName", upn.split("@")[0]),
            "upn": user_data.get("userPrincipalName", upn),
            "job_title": user_data.get("jobTitle") or "Unknown",
            "department": user_data.get("department") or "Unknown",
            "office_location": user_data.get("officeLocation") or "Unknown",
            "account_enabled": user_data.get("accountEnabled", True),
            "user_type": user_data.get("userType", "Member"),
        }

    # Build MFA status
    mfa_status = None
    if isinstance(mfa_raw, list) and mfa_raw:
        methods = [m.get("@odata.type", "").split(".")[-1] for m in mfa_raw]
        mfa_status = {
            "mfa_enabled": len(methods) > 1,
            "methods_count": len(methods),
            "methods": methods,
            "has_fido2": any("fido2" in m.lower() for m in methods),
            "has_authenticator": any("authenticator" in m.lower() for m in methods),
        }

    # Compute risk assessment
    risk_level, risk_factors, mitigating_factors = _compute_risk(
        anomaly_rows, ip_intelligence, incident_rows,
        risk_detections_raw if isinstance(risk_detections_raw, list) else [],
        risk_profile_raw if isinstance(risk_profile_raw, dict) else {},
        mfa_status,
    )

    result = {
        "upn": upn,
        "user_id": user_id,
        "investigation_date": datetime.utcnow().isoformat() + "Z",
        "start_date": start_date,
        "end_date": end_date,
        "user_profile": user_profile,
        "mfa_status": mfa_status,
        "devices": devices_raw if isinstance(devices_raw, list) else [],
        "risk_profile": risk_profile_raw if isinstance(risk_profile_raw, dict) else None,
        "risk_detections": risk_detections_raw if isinstance(risk_detections_raw, list) else [],
        "risky_signins": risky_signins_raw if isinstance(risky_signins_raw, list) else [],
        "anomalies": anomaly_rows,
        "signin_events": {
            "applications": signin_app_rows,
            "locations": signin_loc_rows,
            "failures": signin_fail_rows,
            "total_signins": sum(r.get("SignInCount", 0) for r in signin_app_rows),
            "total_failures": sum(r.get("FailureCount", 0) for r in signin_fail_rows),
        },
        "audit_events": audit_rows,
        "office_events": office_rows,
        "cloud_app_events": cloud_app_rows,
        "incidents": incident_rows,
        "ip_intelligence": ip_intelligence,
        "threat_intel": threat_rows,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "mitigating_factors": mitigating_factors,
    }

    # ── Phase 7: AI Executive Summary (Optional) ──────────────────────
    if generate_summary:
        await emit("ai", "🤖 Generating AI executive summary...")
        try:
            from backend.services import llm as llm_svc
            # Clean up result for LLM (reduce size)
            llm_input = {
                "upn": upn,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "mitigating_factors": mitigating_factors,
                "anomalies_count": len(anomaly_rows),
                "incident_count": len(incident_rows),
                "total_signins": result["signin_events"]["total_signins"],
                "total_failures": result["signin_events"]["total_failures"],
            }
            # Only include top items to stay within token limits
            llm_input["top_anomalies"] = anomaly_rows[:5]
            llm_input["top_ips"] = ip_intelligence[:5]
            
            ai_summary = await llm_svc.summarize_investigation(llm_input)
            result["ai_summary"] = ai_summary
            await emit("ai", "  ✓ AI summary generated")
        except Exception as e:
            await emit("ai", f"  ⚠️ AI summary failed: {e}")

    # ── Phase 8: Generate HTML report if requested ─────────────────────
    report_path = None
    if output_mode in ("html", "both"):
        await emit("report", "📄 Generating HTML report...")
        try:
            report_path = await asyncio.get_event_loop().run_in_executor(
                None, generate_html_report, result, upn
            )
            result["report_path"] = str(report_path)
            await emit("report", f"  ✓ Report saved: {report_path.name}")
        except Exception as e:
            await emit("report", f"  ⚠️ Report generation failed: {e}")

    await emit("complete", f"✅ Investigation complete! Risk: {risk_level}")

    if _days_back:
        await set_cached(upn, _days_back, result)

    return result


# ── Helpers ─────────────────────────────────────────────────────────────────

async def _safe_graph(name: str, fn, *args):
    try:
        return await fn(*args)
    except Exception as e:
        logger.warning("Graph call '%s' failed: %s", name, e)
        return [] if name != "Risk profile" else {}


async def _enrich_ips(
    ips: list[str],
    threat_rows: list[dict],
    anomaly_rows: list[dict],
    emit,
) -> list[dict]:
    """Enrich IPs using the existing enrich_ips.py logic (run in executor)."""
    if not ips:
        return []
    try:
        import enrich_ips as enrich_module
        config = {
            "ipinfo_token": settings.IPINFO_TOKEN,
            "abuseipdb_token": settings.ABUSEIPDB_TOKEN,
            "vpnapi_token": settings.VPNAPI_TOKEN,
            "shodan_token": settings.SHODAN_TOKEN,
        }

        loop = asyncio.get_event_loop()
        raw_results = await loop.run_in_executor(
            None, lambda: enrich_module.enrich_ips(ips, max_workers=5)
        )

        # Merge threat intel data
        threat_map = {r.get("IPAddress", "").upper(): r for r in threat_rows}
        anomaly_map = {r.get("Value", ""): r for r in anomaly_rows if r.get("AnomalyType", "").endswith("IP")}

        enriched = []
        for item in raw_results:
            ip = item.get("ip", "")
            threat = threat_map.get(ip.upper(), {})
            anomaly = anomaly_map.get(ip, {})

            enriched.append({
                **item,
                "threat_detected": bool(threat),
                "threat_description": threat.get("ThreatDescription", ""),
                "threat_confidence": threat.get("Confidence", 0),
                "anomaly_type": anomaly.get("AnomalyType", ""),
                "anomaly_severity": anomaly.get("Severity", ""),
            })

        await emit("enrichment", f"  ✓ Enriched {len(enriched)} IPs")
        return enriched
    except Exception as e:
        await emit("enrichment", f"  ⚠️ IP enrichment failed: {e}")
        return [{"ip": ip, "city": "Unknown", "country": "Unknown", "org": "Unknown",
                 "asn": "Unknown", "risk_level": "Unknown"} for ip in ips]


def _compute_risk(
    anomalies: list[dict],
    ip_intel: list[dict],
    incidents: list[dict],
    risk_detections: list[dict],
    risk_profile: dict,
    mfa_status: dict | None,
) -> tuple[str, list[str], list[str]]:
    score = 0
    risk_factors = []
    mitigating = []

    # Anomaly-based
    new_countries = {a["Country"] for a in anomalies if a.get("CountryNovelty") and a.get("Country")}
    if new_countries:
        risk_factors.append(f"🌍 New country access: {', '.join(new_countries)}")
        score += 3 * len(new_countries)

    # Threat intel
    threat_ips = [ip for ip in ip_intel if ip.get("threat_detected")]
    if threat_ips:
        risk_factors.append(f"🚨 Threat intel match: {', '.join(i['ip'] for i in threat_ips)}")
        score += 5 * len(threat_ips)

    # Incidents
    high_incidents = [i for i in incidents if i.get("Severity") == "High"]
    if high_incidents:
        risk_factors.append(f"⚠️ {len(high_incidents)} High-severity security incident(s)")
        score += 3

    # Identity Protection
    if risk_profile.get("riskState") == "confirmedCompromised":
        risk_factors.append("🔴 Account confirmed compromised (Identity Protection)")
        score += 10
    elif risk_profile.get("riskState") == "atRisk":
        risk_factors.append(f"🟠 Account at risk (Identity Protection: {risk_profile.get('riskLevel', 'unknown')})")
        score += 3

    active_detections = [d for d in risk_detections if d.get("riskState") in ("atRisk", "confirmedCompromised")]
    if active_detections:
        risk_factors.append(f"🟠 {len(active_detections)} active Identity Protection detections")
        score += 2 * len(active_detections)

    # Mitigating
    if mfa_status and mfa_status.get("mfa_enabled"):
        mitigating.append("🟢 MFA enabled")
        score -= 2
    if mfa_status and mfa_status.get("has_fido2"):
        mitigating.append("🟢 FIDO2 / phishing-resistant auth registered")
        score -= 1

    level = (
        "CRITICAL" if score >= 8 else
        "HIGH" if score >= 5 else
        "MEDIUM" if score >= 3 else
        "LOW" if score >= 1 else
        "INFO"
    )
    return level, risk_factors, mitigating


def generate_html_report(result_dict: dict, upn: str) -> Path:
    """Generate an HTML report using the existing report_generator.py."""
    from investigator import (
        InvestigationResult, AnomalyFinding, IPIntelligence,
        UserProfile, MFAStatus, DeviceInfo, UserRiskProfile, RiskDetection,
    )
    # Build InvestigationResult from dict
    inv = InvestigationResult(
        upn=upn,
        user_id=result_dict.get("user_id"),
        investigation_date=result_dict["investigation_date"],
        start_date=result_dict["start_date"],
        end_date=result_dict["end_date"],
        anomalies=[
            AnomalyFinding(
                detected_date=a.get("DetectedDateTime", ""),
                upn=a.get("UserPrincipalName", upn),
                anomaly_type=a.get("AnomalyType", ""),
                value=a.get("Value", ""),
                severity=a.get("Severity", "Informational"),
                country=a.get("Country", ""),
                city=a.get("City", ""),
                country_novelty=a.get("CountryNovelty", False),
                city_novelty=a.get("CityNovelty", False),
                artifact_hits=a.get("ArtifactHits", 0),
                first_seen=a.get("FirstSeenRecent", ""),
            ) for a in result_dict.get("anomalies", [])
        ],
        ip_intelligence=[
            IPIntelligence(
                ip=ip.get("ip", ""),
                city=ip.get("city", "Unknown"),
                region=ip.get("region", "Unknown"),
                country=ip.get("country", "Unknown"),
                org=ip.get("org", "Unknown"),
                asn=ip.get("asn", "Unknown"),
                timezone=ip.get("timezone", "Unknown"),
                risk_level="HIGH" if ip.get("threat_detected") else ip.get("risk_level", "LOW"),
                assessment=ip.get("threat_description") or ip.get("assessment", ""),
                abuse_confidence_score=ip.get("abuse_confidence_score", 0),
                is_vpn=ip.get("is_vpn", False) or ip.get("vpnapi_security_vpn", False),
                is_whitelisted=ip.get("is_whitelisted", False),
                total_reports=ip.get("total_reports", 0),
                threat_detected=ip.get("threat_detected", False),
            ) for ip in result_dict.get("ip_intelligence", [])
        ],
        user_profile=None,
        mfa_status=None,
        devices=[],
        user_risk_profile=None,
        risk_detections=[],
        risky_signins=[],
        signin_events=result_dict.get("signin_events", {}),
        audit_events=result_dict.get("audit_events", []),
        office_events=result_dict.get("office_events", []),
        security_alerts=result_dict.get("incidents", []),
        dlp_events=[],
        risk_level=result_dict.get("risk_level", "INFO"),
        risk_factors=result_dict.get("risk_factors", []),
        mitigating_factors=result_dict.get("mitigating_factors", []),
        critical_actions=[],
        high_priority_actions=[],
        monitoring_actions=[f"Monitor {upn} for 14 days"],
    )

    gen = CompactReportGenerator()
    report_path = gen.generate(inv)
    return Path(report_path)
