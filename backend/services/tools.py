"""
Tool definitions exposed to the LLM (OpenAI function-calling format).
Each tool maps to an existing backend service.
"""
import json
import logging
from typing import Any

from backend.services import sentinel as sentinel_svc
from backend.services import graph as graph_svc
from backend.services import jobs as job_svc
from backend.services import investigation as inv_svc

logger = logging.getLogger(__name__)

# ── Tool Schema Definitions ───────────────────────────────────────────────────
TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "run_kql_query",
            "description": (
                "Execute a KQL (Kusto Query Language) query against Microsoft Sentinel / Azure Log Analytics. "
                "Use for threat hunting, log analysis, anomaly detection, sign-in investigation, DLP events, "
                "security alerts, Office 365 audit, identity protection events, and any ad-hoc Sentinel queries."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Complete KQL query to execute"},
                    "days": {"type": "integer", "description": "Look-back window in days (default 30)", "default": 30},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_user",
            "description": (
                "Run a full automated security investigation for a user account. "
                "Collects anomalies, sign-in events, MFA status, devices, Identity Protection data, "
                "Office 365 activity, security incidents, DLP events, and IP threat intelligence. "
                "Use this when the user asks to investigate a specific person or account."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "upn": {"type": "string", "description": "User Principal Name, e.g. john@contoso.com"},
                    "days_back": {"type": "integer", "description": "Days to look back (default 7)", "default": 7},
                    "output_mode": {
                        "type": "string",
                        "enum": ["inline", "html", "both"],
                        "description": "Return inline JSON, generate HTML report, or both (default: inline)",
                        "default": "inline",
                    },
                },
                "required": ["upn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_ip_addresses",
            "description": (
                "Enrich one or more IP addresses with threat intelligence data from "
                "ipinfo.io (geo, ASN, VPN), AbuseIPDB (abuse score, reports), "
                "vpnapi.io (VPN/Tor/proxy detection), and Shodan (open ports, CVEs). "
                "Use when analyzing suspicious IPs, identifying threat actors, or validating sign-in locations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ips": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of IP addresses to enrich",
                    },
                },
                "required": ["ips"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_profile",
            "description": (
                "Get the Entra ID (Azure AD) profile for a user: display name, job title, department, "
                "office location, account enabled status, user type, and Entra object ID. "
                "Use before deeper investigation to confirm the user exists and get their object ID."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "upn": {"type": "string", "description": "User Principal Name or email address"},
                },
                "required": ["upn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_mfa_and_devices",
            "description": (
                "Get MFA authentication methods and registered devices for a user from Microsoft Graph. "
                "Returns method types (FIDO2, Authenticator, Phone, etc.) and device trust/compliance details. "
                "Use to assess identity hygiene and phishing resistance."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "description": "Entra object ID (GUID) of the user"},
                },
                "required": ["user_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_identity_protection_data",
            "description": (
                "Get Identity Protection risk profile, active risk detections, and risky sign-ins for a user. "
                "Use to assess if an account is at risk or confirmed compromised."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "description": "Entra object ID (GUID) of the user"},
                },
                "required": ["user_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_html_report",
            "description": (
                "Generate a compact HTML investigation report from a completed investigation result. "
                "Call this after investigate_user completes to create a professional formatted report."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string", "description": "The job_id returned by a completed investigate_user call"},
                },
                "required": ["job_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_security_incidents",
            "description": (
                "List recent Microsoft Sentinel security incidents. "
                "Use to get situational awareness or to identify incidents related to a UPN/entity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Days to look back (default 7)", "default": 7},
                    "severity": {
                        "type": "string",
                        "enum": ["High", "Medium", "Low", "Informational", "All"],
                        "description": "Filter by severity (default All)",
                        "default": "All",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "threat_hunt",
            "description": (
                "Run a targeted threat hunting query for a specific technique or indicator. "
                "Supports MITRE ATT&CK technique IDs, threat actor names, IOC types, or general hunting topics. "
                "Automatically selects and runs the best KQL query from the library."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "What to hunt for, e.g. 'T1566 phishing', 'AITM session hijack', 'infostealer', 'lateral movement RDP'",
                    },
                    "days": {"type": "integer", "description": "Days to look back (default 14)", "default": 14},
                },
                "required": ["topic"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "backup_sentinel_workspace",
            "description": (
                "Back up Sentinel workspace resources (rules, workbooks, watchlists, playbooks, etc.) "
                "to a local snapshot. Supports incremental backup (only changed resources). "
                "Use this before making configuration changes or for disaster recovery preparation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "resource_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific resource types to back up. If omitted, backs up all types.",
                        "enum": [
                            "scheduledRules", "nrtRules", "fusionRules", "microsoftRules",
                            "automationRules", "workbooks", "watchlists", "huntingQueries",
                            "summaryRules", "dataConnectors", "threatIntelligence", "metadata",
                        ],
                    },
                    "incremental": {
                        "type": "boolean",
                        "description": "Only back up resources that changed since the last snapshot.",
                        "default": True,
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "restore_sentinel_resources",
            "description": (
                "Restore Sentinel resources from a backup snapshot. "
                "Supports partial restore (specific types) and dry-run mode to preview what would be restored."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "snapshot_path": {
                        "type": "string",
                        "description": "Path to the backup snapshot directory.",
                    },
                    "resource_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific resource types to restore. If omitted, restores all types in the snapshot.",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, simulate the restore without making changes.",
                        "default": False,
                    },
                },
                "required": ["snapshot_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_backup_snapshots",
            "description": (
                "List all available backup snapshots with timestamps, resource counts, and types. "
                "Use this to see what backups are available before restoring."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_backup_snapshots",
            "description": (
                "Compare two backup snapshots to see what changed between them "
                "(added, removed, modified resources)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "snapshot_a": {"type": "string", "description": "Path to the older/baseline snapshot."},
                    "snapshot_b": {"type": "string", "description": "Path to the newer snapshot."},
                },
                "required": ["snapshot_a", "snapshot_b"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_backup_status",
            "description": "Get the status of a running or completed backup/restore job.",
            "parameters": {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string", "description": "The job ID returned when backup/restore was started."},
                },
                "required": ["job_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "invalidate_investigation_cache",
            "description": (
                "Clear cached investigation results for a specific user or all users. "
                "Use when you need fresh data after a user's situation has changed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "upn": {
                        "type": "string",
                        "description": "UPN of the user whose cache to clear. If omitted, clears all cached investigations.",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_permissions",
            "description": (
                "Check what Azure permissions the current service principal/managed identity has on the "
                "Sentinel workspace. Useful for diagnosing backup/restore failures."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
]

# ── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are ARIA (Advanced Risk Intelligence Assistant), a specialized AI security analyst built for the PwC Sentinel Engineering Team.

You operate directly against Microsoft Sentinel, Microsoft Graph API, and threat intelligence APIs.

## Your Capabilities
- **User Investigation**: Full analysis of sign-in anomalies, MFA, devices, Identity Protection, DLP events, security incidents
- **KQL Query Execution**: Run any KQL query against Sentinel/Log Analytics in real-time
- **Threat Hunting**: Hunt for specific MITRE techniques, threat actors, or IOC types
- **IP Enrichment**: Multi-source threat intelligence on IP addresses (geo, VPN/Tor, AbuseIPDB, Shodan)
- **Identity Analysis**: Entra ID profile, MFA methods, registered devices, risk detections
- **Report Generation**: Professional HTML security investigation reports

## Rules
1. **Evidence-based only**: All findings must come from actual tool results. Never fabricate data or invent IOCs.
2. **Always use tools**: When asked about specific users, IPs, incidents, or telemetry — call the appropriate tool. Do not say you cannot access live data.
3. **Structured findings**: Present results clearly with risk assessments, findings, and recommended actions.
4. **Security-first**: Flag critical risks (compromised accounts, threat intel matches, anomalies) prominently.
5. When investigating a user, always start with `investigate_user` — it runs all necessary queries in parallel.
6. For HTML reports, call `investigate_user` first, then `generate_html_report` with the returned job_id.

## Response Format
- Use markdown for structure
- Lead with an executive summary for investigations
- Include a risk level: 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW / 🔵 INFO
- Provide concrete recommended actions
- Reference specific data points (exact IPs, dates, counts) from tool results
"""

# ── Tool executor ─────────────────────────────────────────────────────────────

async def execute_tool(name: str, args: dict) -> Any:
    """Dispatch a tool call to the appropriate backend service."""
    logger.info("Executing tool: %s(%s)", name, list(args.keys()))

    if name == "run_kql_query":
        result = await sentinel_svc.run_kql(args["query"], days=args.get("days", 30))
        return _fmt_kql(result)

    elif name == "investigate_user":
        from datetime import datetime, timedelta
        job_id = job_svc.create_job()
        days = args.get("days_back", 7)
        end_dt = datetime.utcnow()
        start_dt = end_dt - timedelta(days=days)
        result = await inv_svc.run_investigation(
            job_id=job_id,
            upn=args["upn"],
            start_date=start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_date=end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            output_mode=args.get("output_mode", "inline"),
        )
        # Store result in job
        job = job_svc.get_job(job_id)
        if job:
            job.result = result
            job.status = job_svc.JobStatus.COMPLETED
        return json.dumps({
            "job_id": job_id,
            "upn": result.get("upn"),
            "risk_level": result.get("risk_level"),
            "risk_factors": result.get("risk_factors"),
            "mitigating_factors": result.get("mitigating_factors"),
            "anomalies_count": len(result.get("anomalies", [])),
            "total_signins": result.get("signin_events", {}).get("total_signins", 0),
            "total_failures": result.get("signin_events", {}).get("total_failures", 0),
            "incidents_count": len(result.get("incidents", [])),
            "ip_count": len(result.get("ip_intelligence", [])),
            "threat_ips": [ip["ip"] for ip in result.get("ip_intelligence", []) if ip.get("threat_detected")],
            "report_path": result.get("report_path"),
            "mfa_status": result.get("mfa_status"),
            "user_profile": result.get("user_profile"),
            "anomalies": result.get("anomalies", [])[:5],
            "incidents": result.get("incidents", [])[:5],
            "top_ips": result.get("ip_intelligence", [])[:5],
        }, default=str)

    elif name == "enrich_ip_addresses":
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        import enrich_ips as enrich_module  # type: ignore
        import asyncio
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None, lambda: enrich_module.enrich_ips(args["ips"], max_workers=5)
        )
        return json.dumps(results, default=str)

    elif name == "get_user_profile":
        user = await graph_svc.get_user(args["upn"])
        return json.dumps(user, default=str)

    elif name == "get_user_mfa_and_devices":
        uid = args["user_id"]
        mfa, devices = await asyncio.gather(
            graph_svc.get_mfa_methods(uid),
            graph_svc.get_user_devices(uid),
        )
        return json.dumps({"mfa_methods": mfa, "devices": devices}, default=str)

    elif name == "get_identity_protection_data":
        uid = args["user_id"]
        risk_profile, detections, risky_signins = await _gather_idp(uid)
        return json.dumps({
            "risk_profile": risk_profile,
            "risk_detections": detections,
            "risky_signins": risky_signins,
        }, default=str)

    elif name == "generate_html_report":
        job = job_svc.get_job(args["job_id"])
        if not job or not job.result:
            return "ERROR: Job not found or investigation not complete."
        import asyncio
        result_dict = job.result
        upn = result_dict.get("upn", "unknown")
        path = await asyncio.get_event_loop().run_in_executor(
            None, lambda: inv_svc._generate_html_report(result_dict, upn)
        )
        return f"HTML report generated: {path.name} (viewable in the Reports tab)"

    elif name == "list_security_incidents":
        severity = args.get("severity", "All")
        days = args.get("days", 7)
        severity_filter = "" if severity == "All" else f"\n| where Severity == '{severity}'"
        kql = f"""SecurityIncident
| where TimeGenerated > ago({days}d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where not(tostring(Labels) has "Redirected"){severity_filter}
| project IncidentNumber, Title, Severity, Status, CreatedTime, Classification
| order by CreatedTime desc
| take 20"""
        result = await sentinel_svc.run_kql(kql, days=days)
        return _fmt_kql(result)

    elif name == "threat_hunt":
        topic = args.get("topic", "")
        days = args.get("days", 14)
        kql = _build_hunt_query(topic, days)
        result = await sentinel_svc.run_kql(kql, days=days)
        return f"Hunt query for '{topic}':\n{_fmt_kql(result)}"

    elif name == "backup_sentinel_workspace":
        import asyncio as _asyncio
        from backend.services.backup import run_backup
        b_job_id = job_svc.create_job()
        _asyncio.create_task(
            job_svc.run_job(b_job_id, lambda: run_backup(
                job_id=b_job_id,
                resource_types=args.get("resource_types"),
                incremental=args.get("incremental", True),
            ))
        )
        return json.dumps({"job_id": b_job_id, "message": "Backup started. Use get_backup_status to monitor."})

    elif name == "restore_sentinel_resources":
        import asyncio as _asyncio
        from backend.services.restore import restore_from_snapshot
        r_job_id = job_svc.create_job()
        _asyncio.create_task(
            job_svc.run_job(r_job_id, lambda: restore_from_snapshot(
                job_id=r_job_id,
                snapshot_path=args["snapshot_path"],
                resource_types=args.get("resource_types"),
                dry_run=args.get("dry_run", False),
            ))
        )
        return json.dumps({"job_id": r_job_id, "message": "Restore started. Use get_backup_status to monitor."})

    elif name == "list_backup_snapshots":
        from backend.services.backup import list_snapshots
        return json.dumps({"snapshots": list_snapshots()})

    elif name == "compare_backup_snapshots":
        from backend.services.backup import compare_snapshots
        return json.dumps(compare_snapshots(args["snapshot_a"], args["snapshot_b"]))

    elif name == "get_backup_status":
        job = job_svc.get_job(args["job_id"])
        return json.dumps(job.model_dump() if job else {"error": "Job not found"}, default=str)

    elif name == "invalidate_investigation_cache":
        from backend.services.investigation_cache import invalidate
        count = await invalidate(args.get("upn"))
        return json.dumps({"invalidated": count})

    elif name == "check_permissions":
        from backend.config import settings as _cfg
        sub = _cfg.SUBSCRIPTION_ID
        path = f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments"
        try:
            data = await sentinel_svc.call_azure_mgmt_api_async(path, api_version="2022-04-01")
            return json.dumps({"role_assignments_count": len(data.get("value", [])), "status": "ok"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    else:
        return f"Unknown tool: {name}"


def _fmt_kql(result: dict) -> str:
    """Format KQL result as compact text."""
    rows = result.get("rows", [])
    count = result.get("row_count", 0)
    if count == 0:
        return "Query returned 0 rows."
    return f"{count} rows returned:\n{json.dumps(rows[:50], default=str)}"


def _build_hunt_query(topic: str, days: int) -> str:
    t = topic.lower()
    if "phish" in t or "aitm" in t or "t1566" in t:
        return f"""SigninLogs
| where TimeGenerated > ago({days}d)
| where isnotempty(AuthenticationDetails)
| extend AuthDetails = parse_json(AuthenticationDetails)
| where ResultType == "0"
| where UserPrincipalName !endswith "#EXT#"
| summarize SignIns = count(), IPs = make_set(IPAddress), Apps = make_set(AppDisplayName) by UserPrincipalName, Location
| order by SignIns desc | take 20"""
    elif "lateral" in t or "rdp" in t or "t1021" in t:
        return f"""DeviceNetworkEvents
| where TimeGenerated > ago({days}d)
| where RemotePort == 3389
| where ActionType == "ConnectionSuccess"
| summarize count() by DeviceName, RemoteIP, InitiatingProcessFileName
| order by count_ desc | take 20"""
    elif "infostealer" in t or "stealer" in t:
        return f"""DeviceProcessEvents
| where TimeGenerated > ago({days}d)
| where ProcessCommandLine has_any ("credential", "password", "wallet", "cookie")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc | take 20"""
    elif "anomal" in t or "signin" in t:
        return f"""Signinlogs_Anomalies_KQL_CL
| where DetectedDateTime > ago({days}d)
| summarize count() by UserPrincipalName, AnomalyType, Country
| order by count_ desc | take 30"""
    else:
        return f"""union isfuzzy=true SigninLogs, SecurityAlert, AuditLogs
| where TimeGenerated > ago({days}d)
| where * has "{topic.split()[0] if topic.split() else topic}"
| take 20"""


async def _gather_idp(uid: str):
    import asyncio
    return await asyncio.gather(
        graph_svc.get_user_risk_profile(uid),
        graph_svc.get_risk_detections(uid),
        graph_svc.get_risky_signins(uid),
        return_exceptions=True,
    )
