from typing import Optional, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from backend.services.sentinel import run_kql
from backend.services.llm import complete
from backend.config import settings
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/hunting", tags=["hunting"])

LIBRARY = [
    {
        "id": "hunt_01",
        "title": "Impossible Travel",
        "category": "Identity",
        "mitre_technique": "T1078",
        "mitre_tactic": "Initial Access",
        "severity": "High",
        "description": "Detects sign-ins from geographically impossible locations within 30 minutes — a strong indicator of credential compromise or token theft.",
        "query": """SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project UserPrincipalName, IPAddress, Location, AppDisplayName, TimeGenerated
| order by UserPrincipalName asc, TimeGenerated asc
| extend NextTime     = next(TimeGenerated, 1)
| extend NextLocation = next(Location, 1)
| extend NextUser     = next(UserPrincipalName, 1)
| where UserPrincipalName == NextUser
| extend TimeDiffMin = datetime_diff('minute', NextTime, TimeGenerated)
| where TimeDiffMin < 30 and Location != NextLocation
| project UserPrincipalName, TimeGenerated, Location, IPAddress, NextTime, NextLocation, TimeDiffMin""",
    },
    {
        "id": "hunt_02",
        "title": "Password Spray",
        "category": "Identity",
        "mitre_technique": "T1110.003",
        "mitre_tactic": "Credential Access",
        "severity": "High",
        "description": "Identifies a single source IP failing authentication against many unique accounts — the classic password-spray pattern.",
        "query": """SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    UniqueUsers    = dcount(UserPrincipalName),
    UserSample     = make_set(UserPrincipalName, 10)
  by IPAddress
| where UniqueUsers > 10 and FailedAttempts > 20
| sort by UniqueUsers desc""",
    },
    {
        "id": "hunt_03",
        "title": "Privileged Role Assignments",
        "category": "Privilege Escalation",
        "mitre_technique": "T1078.004",
        "mitre_tactic": "Privilege Escalation",
        "severity": "Medium",
        "description": "Tracks all admin-role assignments in the last 30 days. Any unexpected assignments warrant immediate investigation.",
        "query": """AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName =~ "Add member to role"
| extend RoleName    = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend UserAdded   = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where RoleName contains "Admin" or RoleName contains "Global" or RoleName contains "Privileged"
| project TimeGenerated, UserAdded, RoleName, InitiatedBy
| sort by TimeGenerated desc""",
    },
    {
        "id": "hunt_04",
        "title": "High-Risk OAuth Consent",
        "category": "Persistence",
        "mitre_technique": "T1550.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "High",
        "description": "Finds OAuth applications granted high-risk delegated permissions (mail read/write, offline access, full mailbox access).",
        "query": """AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| extend AppName  = tostring(TargetResources[0].displayName)
| extend Scopes   = tostring(TargetResources[0].modifiedProperties)
| extend Grantor  = tostring(InitiatedBy.user.userPrincipalName)
| where Scopes has_any ("Mail.ReadWrite","Files.ReadWrite","MailboxSettings","offline_access","full_access_as_user","Calendars.ReadWrite")
| project TimeGenerated, AppName, Scopes, Grantor
| sort by TimeGenerated desc""",
    },
    {
        "id": "hunt_05",
        "title": "Encoded / Obfuscated PowerShell",
        "category": "Execution",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "severity": "Medium",
        "description": "Detects encoded commands, bypass flags, and common LOTL download-cradle patterns in PowerShell process creation events.",
        "query": """SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where Process =~ "powershell.exe" or Process =~ "pwsh.exe"
| where CommandLine has_any ("-enc","-EncodedCommand","bypass","hidden","IEX",
    "Invoke-Expression","downloadstring","WebClient","DownloadFile","bitsadmin")
| project TimeGenerated, Computer, Account, CommandLine
| sort by TimeGenerated desc
| limit 50""",
    },
    {
        "id": "hunt_06",
        "title": "New Local Admin Accounts",
        "category": "Persistence",
        "mitre_technique": "T1136.001",
        "mitre_tactic": "Persistence",
        "severity": "High",
        "description": "Detects local account creation and addition to the Administrators group — a common persistence technique.",
        "query": """SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID in (4720, 4728, 4732)
| project TimeGenerated, Computer, EventID, SubjectUserName, MemberName, TargetUserName
| sort by TimeGenerated desc""",
    },
    {
        "id": "hunt_07",
        "title": "MFA Fatigue / Push Flood",
        "category": "Identity",
        "mitre_technique": "T1621",
        "mitre_tactic": "Credential Access",
        "severity": "High",
        "description": "Detects users receiving > 5 MFA push notifications within a single hour — hallmark of MFA fatigue attacks.",
        "query": """SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 500121
| summarize
    PushCount   = count(),
    IPList      = make_set(IPAddress, 5),
    LastAttempt = max(TimeGenerated)
  by UserPrincipalName, bin(TimeGenerated, 1h)
| where PushCount > 5
| sort by PushCount desc""",
    },
    {
        "id": "hunt_08",
        "title": "Service Principal Anomalies",
        "category": "Identity",
        "mitre_technique": "T1528",
        "mitre_tactic": "Credential Access",
        "severity": "High",
        "description": "Finds service principals signing in from > 3 unique IPs or generating high-volume traffic — possible stolen app credentials.",
        "query": """AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| summarize
    SignInCount = count(),
    UniqueIPs   = dcount(IPAddress),
    IPList      = make_set(IPAddress, 5),
    FirstSeen   = min(TimeGenerated),
    LastSeen    = max(TimeGenerated)
  by ServicePrincipalName, ServicePrincipalId
| where UniqueIPs > 3 or SignInCount > 100
| sort by UniqueIPs desc""",
    },
    {
        "id": "hunt_09",
        "title": "Office App Spawning Shells",
        "category": "Execution",
        "mitre_technique": "T1059",
        "mitre_tactic": "Execution",
        "severity": "High",
        "description": "Detects Office applications (Word, Excel, Outlook) spawning command interpreters — a classic macro/exploit delivery pattern.",
        "query": """DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe",
    "mshta.exe","wscript.exe","cscript.exe","onenote.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","regsvr32.exe",
    "rundll32.exe","certutil.exe","msiexec.exe","wmic.exe","bitsadmin.exe")
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by TimeGenerated desc
| limit 50""",
    },
    {
        "id": "hunt_10",
        "title": "Cloud Storage Exfiltration",
        "category": "Exfiltration",
        "mitre_technique": "T1567.002",
        "mitre_tactic": "Exfiltration",
        "severity": "High",
        "description": "Detects bulk file uploads to cloud storage in a single hour — possible data exfiltration over cloud channels.",
        "query": """CloudAppEvents
| where TimeGenerated > ago(7d)
| where Application in ("Microsoft OneDrive","SharePoint","Dropbox","Google Drive","Box")
| where ActionType in ("FileUploaded","FileSyncUploadedFull","FileCreated")
| summarize
    UploadCount  = count(),
    TotalSizeMB  = sum(todouble(RawEventData.FileSize)) / 1048576
  by AccountDisplayName, Application, bin(TimeGenerated, 1h)
| where UploadCount > 50 or TotalSizeMB > 100
| sort by UploadCount desc""",
    },
    {
        "id": "hunt_11",
        "title": "Sentinel Rule Tampering",
        "category": "Defense Evasion",
        "mitre_technique": "T1562.001",
        "mitre_tactic": "Defense Evasion",
        "severity": "Critical",
        "description": "Tracks modifications (delete / disable / write) to Sentinel analytics rules via AzureActivity — key defense evasion signal.",
        "query": """AzureActivity
| where TimeGenerated > ago(30d)
| where ResourceProviderValue =~ "MICROSOFT.SECURITYINSIGHTS"
| where OperationNameValue has_any ("alertRules/delete","alertRules/write","automationRules/delete")
| project TimeGenerated, Caller, OperationNameValue, ResourceId, ActivityStatusValue
| sort by TimeGenerated desc""",
    },
    {
        "id": "hunt_12",
        "title": "Mailbox Access Anomalies",
        "category": "Collection",
        "mitre_technique": "T1114.002",
        "mitre_tactic": "Collection",
        "severity": "Medium",
        "description": "Finds users accessing more than 3 unique mailboxes — potential email harvesting or delegated-access abuse.",
        "query": """OfficeActivity
| where TimeGenerated > ago(7d)
| where RecordType =~ "ExchangeItem"
| where Operation in ("MailItemsAccessed","UpdateInboxRules","Set-Mailbox")
| summarize
    AccessCount       = count(),
    UniqueMailboxes   = dcount(MailboxOwnerUPN),
    TargetMailboxes   = make_set(MailboxOwnerUPN, 5)
  by UserId, ClientIPAddress
| where UniqueMailboxes > 3
| sort by UniqueMailboxes desc""",
    },
    {
        "id": "hunt_13",
        "title": "Tor / Anonymized IP Sign-ins",
        "category": "Anonymous Infrastructure",
        "mitre_technique": "T1090.003",
        "mitre_tactic": "Command and Control",
        "severity": "High",
        "description": "Identifies successful sign-ins flagged with anonymized IP risk — typically Tor exit nodes or commercial VPNs used to mask origin.",
        "query": """SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where RiskEventTypes has "anonymizedIPAddress"
    or RiskEventTypes_V2 has "anonymizedIPAddress"
| project TimeGenerated, UserPrincipalName, IPAddress,
    AppDisplayName, Location, RiskEventTypes
| sort by TimeGenerated desc""",
    },
    {
        "id": "hunt_14",
        "title": "Lateral Movement via PsExec",
        "category": "Lateral Movement",
        "mitre_technique": "T1021.002",
        "mitre_tactic": "Lateral Movement",
        "severity": "High",
        "description": "Detects PsExec, PAExec, and similar remote-execution tool invocations indicative of lateral movement.",
        "query": """SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where Process has_any ("psexec","psexec64","paexec","winexesvc")
    or CommandLine has_any ("\\\\admin$","\\\\c$\\\\Windows\\\\Temp")
| project TimeGenerated, Computer, Account, Process, CommandLine
| sort by TimeGenerated desc""",
    },
    {
        "id": "hunt_15",
        "title": "PIM Role Activations",
        "category": "Privilege Escalation",
        "mitre_technique": "T1484.001",
        "mitre_tactic": "Privilege Escalation",
        "severity": "Medium",
        "description": "Monitors PIM role activations and policy changes — high-frequency activations from the same user may indicate privilege abuse.",
        "query": """AuditLogs
| where TimeGenerated > ago(30d)
| where Category =~ "RoleManagement"
| where OperationName has_any ("PIM","privileged","Activate","role assignment scheduled")
| extend RequestedRole = tostring(TargetResources[0].displayName)
| extend Requestor     = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, RequestedRole, Requestor, Result
| sort by TimeGenerated desc""",
    },
    {
        "id": "hunt_16",
        "title": "Scheduled Task / Registry Run Key Persistence",
        "category": "Persistence",
        "mitre_technique": "T1053.005",
        "mitre_tactic": "Persistence",
        "severity": "Medium",
        "description": "Detects creation of new scheduled tasks and run-key registry modifications commonly abused for malware persistence.",
        "query": """SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4698, 4702)
| project TimeGenerated, Computer, Account, EventID,
    tostring(EventData)
| sort by TimeGenerated desc
| limit 50""",
    },
    {
        "id": "hunt_17",
        "title": "Conditional Access Bypass Attempts",
        "category": "Defense Evasion",
        "mitre_technique": "T1562",
        "mitre_tactic": "Defense Evasion",
        "severity": "High",
        "description": "Finds sign-ins blocked by Conditional Access from the same IP that later succeeded — possible CA policy circumvention.",
        "query": """SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus =~ "failure"
    and ResultType in (53000, 53001, 53002, 530032)
| summarize
    BlockedAttempts  = count(),
    UniqueUsers      = dcount(UserPrincipalName),
    UserSample       = make_set(UserPrincipalName, 5)
  by IPAddress
| sort by BlockedAttempts desc
| limit 20""",
    },
    {
        "id": "hunt_18",
        "title": "Rare LSASS Access (Credential Dumping)",
        "category": "Credential Access",
        "mitre_technique": "T1003.001",
        "mitre_tactic": "Credential Access",
        "severity": "Critical",
        "description": "Detects processes opening LSASS with read access — the primary technique for in-memory credential dumping (Mimikatz, etc.).",
        "query": """DeviceEvents
| where TimeGenerated > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","svchost.exe","System","WerFault.exe","csrss.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
    InitiatingProcessAccountName, ProcessCommandLine
| sort by TimeGenerated desc
| limit 50""",
    },
]

CATEGORIES = sorted({q["category"] for q in LIBRARY})


@router.get("/library")
async def get_library(category: Optional[str] = Query(None)):
    """Return the full hunting query library, optionally filtered by category."""
    if category and category.lower() != "all":
        items = [q for q in LIBRARY if q["category"].lower() == category.lower()]
    else:
        items = LIBRARY
    return {"queries": items, "total": len(items)}


@router.get("/categories")
async def get_categories():
    return {"categories": ["All"] + CATEGORIES}


@router.post("/run/{hunt_id}")
async def run_hunt(hunt_id: str, days: float = Query(7)):
    """Execute a named hunting query from the library."""
    hunt = next((q for q in LIBRARY if q["id"] == hunt_id), None)
    if not hunt:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found")
    try:
        result = await run_kql(hunt["query"], days=days)
        return {
            "hunt_id": hunt_id,
            "title": hunt["title"],
            "columns": result.get("columns", []),
            "rows": result.get("rows", []),
            "row_count": result.get("row_count", 0),
            "status": "completed",
        }
    except Exception as e:
        logger.error("Hunt %s failed: %s", hunt_id, e)
        return {
            "hunt_id": hunt_id,
            "title": hunt["title"],
            "columns": [],
            "rows": [],
            "row_count": 0,
            "status": "error",
            "error": str(e),
        }


@router.post("/run-custom")
async def run_custom(payload: dict, days: float = Query(7)):
    """Execute an ad-hoc KQL hunting query."""
    query = (payload.get("query") or "").strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    try:
        result = await run_kql(query, days=days)
        return {
            "columns": result.get("columns", []),
            "rows": result.get("rows", []),
            "row_count": result.get("row_count", 0),
            "status": "completed",
        }
    except Exception as e:
        logger.error("Custom hunt failed: %s", e)
        return {
            "columns": [], "rows": [], "row_count": 0,
            "status": "error", "error": str(e),
        }


@router.post("/analyze")
async def analyze_hunt_result(payload: dict):
    """Generate AI analysis (indication, remediation, recommendations) for a completed hunt result."""
    hunt_id = payload.get("hunt_id", "")
    hunt = next((q for q in LIBRARY if q["id"] == hunt_id), None)
    if not hunt:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found")
    row_count = payload.get("row_count", 0)
    if row_count == 0:
        return {"indication": "No findings detected — nothing to analyse.", "remediation": [], "recommendations": []}
    rows = payload.get("rows", [])
    days = payload.get("days", 7)
    analysis = await _analyze_hunt_finding(hunt, rows, row_count, days)
    return analysis


# ── Automated Hunt Report ─────────────────────────────────────────────────────

def _esc(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

_SEV_COLOR = {"Critical": "#7c3aed", "High": "#ef4444", "Medium": "#f59e0b", "Low": "#22c55e"}
_CAT_COLOR = {
    "Identity": "#3b82f6", "Execution": "#f97316", "Persistence": "#8b5cf6",
    "Privilege Escalation": "#ec4899", "Defense Evasion": "#ef4444",
    "Credential Access": "#f59e0b", "Collection": "#14b8a6",
    "Exfiltration": "#06b6d4", "Lateral Movement": "#eab308",
    "Anonymous Infrastructure": "#94a3b8",
}

def _sev_color(s: str) -> str:
    return _SEV_COLOR.get(s, "#94a3b8")

def _cat_color(c: str) -> str:
    return _CAT_COLOR.get(c, "#64748b")


async def _generate_ai_narrative(results: list, days: int, model: str = None) -> str:
    """Call the LLM to produce a 2-3 paragraph executive narrative for the report."""
    with_hits = [r for r in results if r.get("row_count", 0) > 0]
    total_findings = sum(r.get("row_count", 0) for r in results)
    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_hits = sorted(with_hits, key=lambda x: SEV_ORDER.get(x.get("severity", "Low"), 4))

    findings_list = "\n".join(
        f"- [{r['severity']}] {r['title']} ({r['mitre_technique']}): {r['row_count']} finding(s)"
        for r in sorted_hits
    ) or "No active findings detected."

    system = (
        "You are a senior threat hunter writing an AI executive narrative for a security operations report. "
        "Be concise, professional, and actionable. Write 2-3 short paragraphs. "
        "Focus on the most critical findings, the overall security posture, and the most important recommended actions. "
        "Do not repeat statistics already shown — focus on interpretation and context."
    )
    user_msg = (
        f"Threat hunting report summary — {days}-day look-back window:\n"
        f"- Total hunts run: {len(results)}\n"
        f"- Hunts with findings: {len(with_hits)}\n"
        f"- Total finding rows: {total_findings}\n\n"
        f"Active findings (sorted by severity):\n{findings_list}\n\n"
        "Write a brief executive narrative assessing the security posture and key risks."
    )

    result = await complete(system, user_msg, model=model)
    return result["text"]


async def _analyze_hunt_finding(hunt: dict, rows: list, row_count: int, days: int) -> dict:
    """Generate structured AI analysis (indication, remediation, recommendations) for a single hunt finding."""
    sample = rows[:5]
    system = (
        "You are a senior threat hunter and incident responder analyzing Microsoft Sentinel findings. "
        "Respond ONLY with valid JSON (no markdown fences, no extra text) in exactly this format:\n"
        '{"indication":"1-2 sentences on what this finding indicates and the likely threat scenario",'
        '"remediation":["specific actionable step 1","specific actionable step 2","specific actionable step 3","specific actionable step 4"],'
        '"recommendations":["detection or hardening improvement 1","detection or hardening improvement 2","detection or hardening improvement 3"]}'
    )
    user_msg = (
        f"Hunt: {hunt['title']} ({hunt['mitre_technique']} — {hunt['mitre_tactic']})\n"
        f"Category: {hunt['category']} | Severity: {hunt['severity']}\n"
        f"Description: {hunt['description']}\n"
        f"Findings: {row_count} row(s) detected over a {days}-day look-back\n"
        f"Sample data (up to 5 rows):\n{json.dumps(sample, default=str)[:1200]}"
    )
    try:
        result = await complete(system, user_msg)
        text = result["text"].strip()
        if "```" in text:
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else parts[0]
            if text.startswith("json"):
                text = text[4:].lstrip()
        return json.loads(text)
    except Exception as e:
        logger.warning("AI hunt analysis failed for %s: %s", hunt.get("id", "?"), e)
        return {"indication": "", "remediation": [], "recommendations": []}


def _build_hunting_html_report(results: list, days: int, ai_narrative: str = "", per_hunt_analyses: dict | None = None) -> str:  # noqa: C901
    _analyses = per_hunt_analyses or {}
    gen_at = datetime.now().strftime("%B %d, %Y at %H:%M UTC")

    # ── Aggregate stats ───────────────────────────────────────────────────────
    total      = len(results)
    with_hits  = [r for r in results if r.get("row_count", 0) > 0]
    errors     = [r for r in results if r.get("status") == "error"]
    clean      = [r for r in results if r.get("row_count", 0) == 0 and r.get("status") != "error"]
    total_findings = sum(r.get("row_count", 0) for r in results)

    sev_hits: dict[str, int] = {}
    for r in with_hits:
        sev_hits[r["severity"]] = sev_hits.get(r["severity"], 0) + 1

    cat_hits: dict[str, int] = {}
    for r in with_hits:
        cat_hits[r["category"]] = cat_hits.get(r["category"], 0) + r.get("row_count", 0)

    # Overall health
    if any(r["severity"] in ("Critical",) for r in with_hits):
        health_color, health_label = "#ef4444", "CRITICAL — Immediate Action Required"
    elif any(r["severity"] == "High" for r in with_hits):
        health_color, health_label = "#f59e0b", "HIGH — Investigation Recommended"
    elif with_hits:
        health_color, health_label = "#eab308", "MEDIUM — Review Findings"
    else:
        health_color, health_label = "#22c55e", "CLEAN — No Active Threats Detected"

    # ── KPI tiles ─────────────────────────────────────────────────────────────
    def kpi(label, value, color="#e2e8f0"):
        return (
            f'<div class="kpi"><div class="kpi-label">{label}</div>'
            f'<div class="kpi-value" style="color:{color}">{value}</div></div>'
        )

    kpis = "".join([
        kpi("Hunts Run", total),
        kpi("Hunts With Findings", len(with_hits), "#f59e0b" if with_hits else "#22c55e"),
        kpi("Total Findings", total_findings, "#ef4444" if total_findings > 0 else "#22c55e"),
        kpi("Critical / High", f'{sev_hits.get("Critical",0)} / {sev_hits.get("High",0)}',
            "#ef4444" if (sev_hits.get("Critical",0) + sev_hits.get("High",0)) > 0 else "#22c55e"),
        kpi("Clean Hunts", len(clean), "#22c55e"),
        kpi("Errors", len(errors), "#94a3b8" if not errors else "#f59e0b"),
    ])

    # ── Category chart (CSS bars) ─────────────────────────────────────────────
    cat_bar_rows = ""
    max_cat = max(cat_hits.values(), default=1)
    for cat, cnt in sorted(cat_hits.items(), key=lambda x: -x[1]):
        w = round(100 * cnt / max_cat)
        color = _cat_color(cat)
        cat_bar_rows += (
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">'
            f'<div style="width:160px;font-size:12px;color:#e2e8f0;text-align:right;flex-shrink:0">{_esc(cat)}</div>'
            f'<div style="flex:1;height:20px;background:#0f172a;border-radius:4px;overflow:hidden">'
            f'<div style="width:{w}%;height:100%;background:{color};border-radius:4px;transition:width 0.3s"></div></div>'
            f'<div style="width:40px;font-size:12px;font-weight:700;color:{color}">{cnt}</div>'
            f'</div>'
        )
    if not cat_bar_rows:
        cat_bar_rows = '<p style="color:#64748b">No findings across any category.</p>'

    # ── Severity distribution pills ───────────────────────────────────────────
    sev_pills = ""
    for sev in ("Critical", "High", "Medium", "Low"):
        cnt = sev_hits.get(sev, 0)
        if cnt:
            color = _sev_color(sev)
            sev_pills += (
                f'<div style="display:inline-flex;align-items:center;gap:8px;background:{color}18;'
                f'border:1px solid {color}40;border-radius:999px;padding:4px 14px;margin:4px">'
                f'<span style="width:8px;height:8px;border-radius:50%;background:{color};display:inline-block"></span>'
                f'<span style="font-size:12px;color:{color};font-weight:700">{sev}: {cnt} hunt{"s" if cnt!=1 else ""}</span>'
                f'</div>'
            )

    # ── Hunt result cards (findings first, sorted by severity) ───────────────
    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_with_hits = sorted(with_hits, key=lambda x: SEV_ORDER.get(x.get("severity", "Low"), 4))

    def _data_table(r: dict) -> str:
        cols = r.get("columns", [])
        rows = r.get("rows", [])
        if not cols or not rows:
            return ""
        th = "".join(f"<th>{_esc(c)}</th>" for c in cols)
        trs = ""
        for row in rows[:20]:
            trs += "<tr>" + "".join(
                f'<td title="{_esc(str(row.get(c,""))[:400])}">{_esc(str(row.get(c,"") or "—")[:80])}</td>'
                for c in cols
            ) + "</tr>"
        truncation = ""
        if r.get("row_count", 0) > 20:
            truncation = f'<div class="trunc-note">Showing 20 of {r["row_count"]:,} rows — run full query in KQL Explorer for complete results</div>'
        return f'<div class="tbl-wrap"><table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table></div>{truncation}'

    def _hunt_card(r: dict, collapsed: bool = False) -> str:
        sev   = r.get("severity", "")
        cat   = r.get("category", "")
        sc    = _sev_color(sev)
        cc    = _cat_color(cat)
        rc    = r.get("row_count", 0)
        is_err = r.get("status") == "error"

        if is_err:
            status_badge = '<span class="sbadge" style="background:#451a03;color:#fbbf24">⚠ Error</span>'
            status_note  = f'<div class="err-box">{_esc(r.get("error","Unknown error"))}</div>'
        elif rc > 0:
            status_badge = f'<span class="sbadge" style="background:{sc}20;color:{sc}">⚠ {rc:,} Finding{"s" if rc != 1 else ""}</span>'
            status_note  = (
                f'<div class="alert-box" style="border-color:{sc}">'
                f'<strong style="color:{sc}">Investigation Recommended</strong> — '
                f'{rc:,} result{"s" if rc!=1 else ""} returned. Review the data below and validate each finding against known baselines.'
                f'</div>'
            )
        else:
            status_badge = '<span class="sbadge" style="background:#14532d20;color:#4ade80">✓ Clean</span>'
            status_note  = ""

        tbl = _data_table(r) if rc > 0 else ""

        rec_map = {
            "Critical": "Escalate immediately. Isolate affected assets, initiate incident response, and notify the SOC lead.",
            "High":     "Investigate within 24 hours. Correlate with other signals and determine scope before containment.",
            "Medium":   "Review and triage within 72 hours. Determine if findings represent expected or anomalous activity.",
            "Low":      "Log and monitor. No immediate action required unless part of a broader pattern.",
        }
        rec = rec_map.get(sev, "Review as appropriate.")
        rec_section = (
            f'<div class="rec-box"><strong>Recommended Action:</strong> {_esc(rec)}</div>'
            if rc > 0 else ""
        )

        # AI analysis section — populated when per-hunt analysis was generated
        ai_section = ""
        ai = _analyses.get(r.get("id", ""))
        if ai and rc > 0 and ai.get("indication"):
            remediation_items = "".join(
                f'<li>{_esc(str(step))}</li>' for step in ai.get("remediation", [])
            )
            recommendation_items = "".join(
                f'<li>{_esc(str(rec_item))}</li>' for rec_item in ai.get("recommendations", [])
            )
            ai_section = (
                f'<div class="ai-analysis">'
                f'<div class="ai-header">'
                f'<span class="ai-badge">AI Analysis</span>'
                f'<span class="ai-model">Powered by Claude</span>'
                f'</div>'
                f'<div class="ai-indication">{_esc(ai["indication"])}</div>'
                f'<div class="ai-cols">'
                f'<div><div class="ai-section-title">Remediation Steps</div>'
                f'<ol class="ai-list">{remediation_items or "<li>No steps available.</li>"}</ol></div>'
                f'<div><div class="ai-section-title">Recommendations</div>'
                f'<ul class="ai-list">{recommendation_items or "<li>No recommendations available.</li>"}</ul></div>'
                f'</div>'
                f'</div>'
            )

        return f"""
    <div class="hunt-card" id="{_esc(r['id'])}">
      <div class="hunt-card-header">
        <div class="hunt-card-meta">
          <div class="hunt-title">{_esc(r["title"])}</div>
          <div class="hunt-tags">
            <span class="tag" style="color:{cc};background:{cc}18">{_esc(cat)}</span>
            <span class="tag" style="color:{sc};background:{sc}18">{_esc(sev)}</span>
            <code class="mitre-tag">{_esc(r.get("mitre_technique",""))}</code>
            <span style="font-size:11px;color:#64748b">{_esc(r.get("mitre_tactic",""))}</span>
          </div>
          <p class="hunt-desc">{_esc(r.get("description",""))}</p>
        </div>
        <div>{status_badge}</div>
      </div>
      {status_note}
      {rec_section}
      {tbl}
      {ai_section}
    </div>"""

    findings_section = "\n".join(_hunt_card(r) for r in sorted_with_hits) or (
        '<div class="empty-note">No hunts returned findings. Environment appears clean for this look-back period.</div>'
    )

    # Clean hunts compact list
    clean_rows = "".join(
        f'<li><code style="color:#64748b;font-size:11px">{_esc(r["mitre_technique"])}</code> '
        f'<span style="color:#94a3b8">{_esc(r["title"])}</span> '
        f'<span style="font-size:10px;color:#4ade80">✓</span></li>'
        for r in sorted(clean, key=lambda x: x.get("title",""))
    )
    clean_section = f'<ul class="clean-list">{clean_rows}</ul>' if clean_rows else ""

    # Error list
    error_rows = "".join(
        f'<li style="color:#f87171">{_esc(r["title"])}: {_esc(r.get("error",""))}</li>'
        for r in errors
    )
    error_section = (
        f'<div class="card" style="margin-top:24px"><h3 style="color:#f87171;margin-bottom:12px">⚠ Query Errors ({len(errors)})</h3>'
        f'<ul style="padding-left:20px;font-size:12px;line-height:2">{error_rows}</ul></div>'
    ) if errors else ""

    # ── MITRE technique table ─────────────────────────────────────────────────
    mitre_rows = ""
    for r in sorted_with_hits:
        sc = _sev_color(r["severity"])
        mitre_rows += (
            f'<tr><td><code style="color:#93c5fd">{_esc(r.get("mitre_technique",""))}</code></td>'
            f'<td style="color:#94a3b8">{_esc(r.get("mitre_tactic",""))}</td>'
            f'<td>{_esc(r["title"])}</td>'
            f'<td><span style="color:{sc};font-weight:700">{r.get("row_count",0):,}</span></td>'
            f'<td><span style="color:{sc}">{_esc(r["severity"])}</span></td></tr>'
        )
    if not mitre_rows:
        mitre_rows = '<tr><td colspan="5" style="color:#64748b;text-align:center">No active techniques in this period</td></tr>'

    # ── KQL Appendix ─────────────────────────────────────────────────────────
    appendix = ""
    for r in results:
        sc = _sev_color(r["severity"])
        appendix += (
            f'<div style="margin-bottom:24px">'
            f'<div style="font-size:13px;font-weight:700;color:#e2e8f0;margin-bottom:4px">'
            f'{_esc(r["title"])} <code style="font-size:11px;color:#93c5fd;background:#1e3a5f;padding:2px 6px;border-radius:4px">{_esc(r.get("mitre_technique",""))}</code></div>'
            f'<pre class="kql-block">{_esc(r.get("query",""))}</pre>'
            f'</div>'
        )

    # ── AI executive narrative card ───────────────────────────────────────────
    if ai_narrative:
        _paras = [p.strip() for p in ai_narrative.strip().split("\n\n") if p.strip()]
        _paras_html = "".join(
            f'<p style="font-size:13px;color:#cbd5e1;line-height:1.8;margin-bottom:10px">{_esc(p)}</p>'
            for p in _paras
        )
        ai_exec_html = (
            f'<div class="ai-exec-card">'
            f'<div class="ai-header"><span class="ai-badge">AI Executive Narrative</span>'
            f'<span class="ai-model">Powered by Claude</span></div>'
            f'{_paras_html}'
            f'</div>'
        )
    else:
        ai_exec_html = ""

    # ── Table of contents ─────────────────────────────────────────────────────
    toc_items = "".join(
        f'<li><a href="#{_esc(r["id"])}">'
        f'<span class="toc-sev" style="color:{_sev_color(r["severity"])}">{_esc(r["severity"][0])}</span> '
        f'{_esc(r["title"])} '
        f'<strong style="color:{_sev_color(r["severity"])}">{r.get("row_count",0):,} hits</strong></a></li>'
        for r in sorted_with_hits
    ) or "<li style='color:#64748b'>No findings</li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Threat Hunting Report — {_esc(gen_at)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',Arial,sans-serif;font-size:14px;line-height:1.6}}
a{{color:#60a5fa;text-decoration:none}}a:hover{{text-decoration:underline}}
.topbar{{background:linear-gradient(135deg,#1e2a3a 0%,#162032 100%);border-bottom:3px solid #d04a02;padding:16px 40px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100}}
.topbar-logo{{font-size:22px;font-weight:900;color:#d04a02;letter-spacing:-0.5px}}
.topbar-title{{font-size:18px;font-weight:700;color:#fff}}
.topbar-sub{{font-size:12px;color:#94a3b8;margin-top:2px}}
.topbar-meta{{margin-left:auto;text-align:right;font-size:12px;color:#64748b}}
.health-banner{{padding:12px 40px;font-size:13px;font-weight:700;letter-spacing:0.05em;text-align:center;background:{health_color}15;border-bottom:2px solid {health_color}40;color:{health_color}}}
.container{{display:grid;grid-template-columns:220px 1fr;gap:0;min-height:calc(100vh - 100px)}}
.sidebar{{background:#0a1120;padding:24px 0;border-right:1px solid #1e293b;position:sticky;top:64px;height:calc(100vh - 64px);overflow-y:auto}}
.sidebar h4{{padding:0 16px 8px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#475569;font-weight:700}}
.sidebar ul{{list-style:none;padding:0 8px;margin-bottom:24px}}
.sidebar ul li{{margin-bottom:4px}}
.sidebar ul li a{{display:block;padding:5px 10px;border-radius:6px;font-size:12px;color:#94a3b8;transition:all 0.15s}}
.sidebar ul li a:hover{{background:#1e293b;color:#e2e8f0;text-decoration:none}}
.toc-sev{{font-weight:900;font-size:10px;border-radius:3px;padding:1px 4px;background:#0f172a;margin-right:4px}}
.content{{padding:32px 40px}}
h2{{font-size:17px;font-weight:700;color:#fff;margin:0 0 16px;padding-bottom:10px;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:10px}}
h2 .section-num{{width:28px;height:28px;border-radius:50%;background:#d04a02;display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:#fff;flex-shrink:0}}
section{{margin-bottom:48px}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:24px}}
.kpi{{background:#1e293b;border-radius:10px;padding:16px 18px;border:1px solid #334155}}
.kpi-label{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px}}
.kpi-value{{font-size:30px;font-weight:800}}
.card{{background:#1e293b;border-radius:10px;padding:20px 24px;border:1px solid #334155}}
.hunt-card{{background:#1e293b;border-radius:12px;border:1px solid #334155;margin-bottom:20px;overflow:hidden;transition:border-color 0.2s}}
.hunt-card:hover{{border-color:#475569}}
.hunt-card-header{{padding:18px 22px;display:flex;justify-content:space-between;align-items:flex-start;gap:16px}}
.hunt-title{{font-size:15px;font-weight:700;color:#fff;margin-bottom:8px}}
.hunt-tags{{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center}}
.tag{{font-size:10px;font-weight:800;padding:3px 10px;border-radius:999px}}
.mitre-tag{{font-size:10px;color:#93c5fd;background:#1e3a5f;padding:3px 8px;border-radius:4px;font-weight:700}}
.hunt-desc{{font-size:12px;color:#94a3b8;line-height:1.6}}
.sbadge{{display:inline-block;padding:4px 12px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap;flex-shrink:0}}
.alert-box{{margin:0 22px 16px;padding:12px 16px;border-left:3px solid;border-radius:0 8px 8px 0;background:#0f172a;font-size:12px;color:#94a3b8}}
.rec-box{{margin:0 22px 16px;padding:12px 16px;background:#162032;border-radius:8px;font-size:12px;color:#94a3b8;border:1px solid #1e3a5f}}
.err-box{{margin:0 22px 16px;padding:12px 16px;background:#1c0a0a;border-radius:8px;font-size:12px;color:#f87171;border:1px solid #450a0a}}
.tbl-wrap{{overflow-x:auto;padding:0 22px 18px}}
.trunc-note{{padding:6px 22px 14px;font-size:11px;color:#64748b;font-style:italic}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#0f172a;color:#64748b;text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;font-weight:700;position:sticky;top:0}}
td{{padding:7px 10px;border-bottom:1px solid #1e293b;color:#cbd5e1;vertical-align:top;word-break:break-all}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#263548}}
.clean-list{{list-style:none;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:6px}}
.clean-list li{{background:#0f1f0f;border:1px solid #14532d30;border-radius:6px;padding:6px 12px;font-size:12px}}
.empty-note{{color:#64748b;text-align:center;padding:40px;font-size:13px}}
.kql-block{{background:#0a1120;border:1px solid #1e3a5f;border-radius:8px;padding:14px 16px;font-size:11px;font-family:'JetBrains Mono',monospace;white-space:pre-wrap;word-break:break-all;color:#93c5fd;line-height:1.6;margin-top:6px}}
.ai-analysis{{margin:0 22px 18px;padding:16px 20px;background:linear-gradient(135deg,#0d1f3c 0%,#0a1628 100%);border:1px solid #1e40af40;border-left:3px solid #3b82f6;border-radius:0 10px 10px 0}}
.ai-header{{display:flex;align-items:center;gap:10px;margin-bottom:12px}}
.ai-badge{{display:inline-block;padding:3px 10px;border-radius:999px;background:#1e40af;color:#93c5fd;font-size:10px;font-weight:800;letter-spacing:0.05em;text-transform:uppercase}}
.ai-model{{font-size:10px;color:#64748b}}
.ai-indication{{font-size:12px;color:#cbd5e1;line-height:1.7;margin-bottom:14px;padding:10px 14px;background:#0f172a40;border-radius:6px}}
.ai-cols{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
.ai-section-title{{font-size:10px;font-weight:800;color:#3b82f6;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px}}
.ai-list{{list-style:none;padding:0;margin:0}}
.ai-list li{{font-size:12px;color:#94a3b8;padding:5px 0 5px 18px;position:relative;line-height:1.5;border-bottom:1px solid #1e293b}}
.ai-list li:last-child{{border-bottom:none}}
.ai-list li::before{{content:"→";position:absolute;left:0;color:#3b82f6;font-weight:700}}
.ai-exec-card{{background:linear-gradient(135deg,#0d1f3c 0%,#0a1628 100%);border:1px solid #1e40af40;border-left:3px solid #3b82f6;border-radius:0 10px 10px 0;padding:20px 24px;margin-top:16px}}
@media print{{
  .sidebar,.topbar{{display:none!important}} .container{{display:block}} .content{{padding:20px}}
  body{{background:#fff;color:#000}} .card,.hunt-card,.kpi{{background:#f8fafc;border:1px solid #e2e8f0}}
  .hunt-title,.kpi-value{{color:#000}} td,th{{color:#333}} .kql-block{{background:#f1f5f9;color:#1e40af}}
}}
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-logo">PwC</div>
  <div style="width:1px;height:32px;background:#334155"></div>
  <div>
    <div class="topbar-title">Threat Hunting Report</div>
    <div class="topbar-sub">Microsoft Sentinel · Look-back: {days}d · Automated Hunt Run</div>
  </div>
  <div class="topbar-meta">
    Generated: {_esc(gen_at)}<br/>
    {total} hunts · {len(with_hits)} with findings · {total_findings:,} total rows
  </div>
</div>

<div class="health-banner">{_esc(health_label)}</div>

<div class="container">
  <!-- Sidebar TOC -->
  <div class="sidebar">
    <h4>Navigation</h4>
    <ul>
      <li><a href="#summary">Executive Summary</a></li>
      <li><a href="#landscape">Threat Landscape</a></li>
      <li><a href="#findings">Findings ({len(with_hits)})</a></li>
      <li><a href="#clean">Clean Hunts ({len(clean)})</a></li>
      <li><a href="#mitre">MITRE Coverage</a></li>
      <li><a href="#appendix">KQL Appendix</a></li>
    </ul>
    {'<h4>Findings</h4><ul>' + toc_items + '</ul>' if with_hits else ''}
  </div>

  <div class="content">

    <!-- 1. Executive Summary -->
    <section id="summary">
      <h2><span class="section-num">1</span>Executive Summary</h2>
      <div class="kpi-grid">{kpis}</div>
      <div class="card" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
        <span style="font-size:12px;color:#64748b;margin-right:8px">Severity breakdown:</span>
        {sev_pills if sev_pills else '<span style="color:#4ade80;font-size:12px">✓ No severity-flagged findings</span>'}
      </div>
      {ai_exec_html}
    </section>

    <!-- 2. Threat Landscape -->
    <section id="landscape">
      <h2><span class="section-num">2</span>Threat Landscape Overview</h2>
      <div class="card">
        <div style="font-size:12px;color:#64748b;margin-bottom:16px">Findings by threat category (row count)</div>
        {cat_bar_rows}
      </div>
    </section>

    <!-- 3. Findings -->
    <section id="findings">
      <h2><span class="section-num">3</span>Hunt Findings ({len(with_hits)} hunts, {total_findings:,} rows)</h2>
      {findings_section}
      {error_section}
    </section>

    <!-- 4. Clean Hunts -->
    <section id="clean">
      <h2><span class="section-num">4</span>Clean Hunts — No Findings ({len(clean)})</h2>
      <div class="card">
        <p style="font-size:12px;color:#64748b;margin-bottom:14px">The following hunts returned zero results during this look-back period.</p>
        {clean_section}
      </div>
    </section>

    <!-- 5. MITRE Coverage -->
    <section id="mitre">
      <h2><span class="section-num">5</span>MITRE ATT&amp;CK Active Techniques</h2>
      <div class="card">
        <table>
          <thead><tr><th>Technique</th><th>Tactic</th><th>Hunt</th><th>Findings</th><th>Severity</th></tr></thead>
          <tbody>{mitre_rows}</tbody>
        </table>
      </div>
    </section>

    <!-- 6. KQL Appendix -->
    <section id="appendix">
      <h2><span class="section-num">6</span>Appendix — KQL Hunting Queries</h2>
      <div class="card">
        <p style="font-size:12px;color:#64748b;margin-bottom:20px">All queries were executed with a look-back window of <strong style="color:#e2e8f0">{"12 hours" if days == 0.5 else f"{int(days * 24)} hours" if days < 1 else f"{int(days)} day{'s' if days != 1 else ''}"}</strong>. Parameterised references to <code style="color:#93c5fd">ago(Nd)</code> use the selected look-back. Run queries in KQL Explorer for interactive investigation.</p>
        {appendix}
      </div>
    </section>

  </div><!-- /content -->
</div><!-- /container -->
</body>
</html>"""


@router.post("/report")
async def generate_hunting_report(days: float = Query(7), model: str | None = Query(None)):
    """
    Run ALL library hunts in parallel and return a comprehensive HTML report.
    Each hunt section includes statistics, data tables, MITRE mappings, and
    analyst recommendations.
    """
    import asyncio

    async def _run_one(hunt: dict) -> dict:
        try:
            result = await run_kql(hunt["query"], days=days)
            return {
                **hunt,
                "columns":   result.get("columns", []),
                "rows":      result.get("rows", []),
                "row_count": result.get("row_count", 0),
                "status":    "completed",
            }
        except Exception as e:
            logger.error("Hunt %s failed during report: %s", hunt["id"], e)
            return {**hunt, "columns": [], "rows": [], "row_count": 0, "status": "error", "error": str(e)}

    logger.info("Starting automated hunt report: %d hunts, %dd look-back", len(LIBRARY), days)
    results = list(await asyncio.gather(*[_run_one(h) for h in LIBRARY]))

    # Run AI narrative + per-hunt analyses in parallel after queries complete
    with_hits_for_ai = [r for r in results if r.get("row_count", 0) > 0]
    ai_narrative = ""
    per_hunt_analyses: dict = {}
    try:
        ai_tasks = [_generate_ai_narrative(results, days, model=model)] + [
            _analyze_hunt_finding(r, r.get("rows", []), r.get("row_count", 0), days)
            for r in with_hits_for_ai
        ]
        ai_outputs = await asyncio.gather(*ai_tasks, return_exceptions=True)
        if not isinstance(ai_outputs[0], Exception):
            ai_narrative = ai_outputs[0]
        for idx, r in enumerate(with_hits_for_ai):
            out = ai_outputs[idx + 1]
            if not isinstance(out, Exception):
                per_hunt_analyses[r["id"]] = out
    except Exception as e:
        logger.warning("AI enrichment for report failed: %s", e)

    html = _build_hunting_html_report(results, days, ai_narrative=ai_narrative, per_hunt_analyses=per_hunt_analyses)

    reports_dir = settings.OUTPUT_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = reports_dir / f"Hunting_Report_{timestamp}.html"
    html_path.write_text(html, encoding="utf-8")

    logger.info("Hunt report saved: %s", html_path)
    return FileResponse(str(html_path), media_type="text/html", filename=html_path.name)
