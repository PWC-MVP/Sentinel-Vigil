from fastapi import APIRouter, Query
from backend.services.sentinel import run_kql, call_azure_mgmt_api_async, call_sentinel_mgmt_api
from backend.services import llm as llm_service
from backend.config import settings
import asyncio
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/automation", tags=["automation"])


# ── Existing endpoints ────────────────────────────────────────────────────────

@router.get("/overview")
async def get_automation_overview(days: int = Query(30)):
    """Playbook run counts and incident classification summary."""
    la_q = f"""
    AzureActivity
    | where TimeGenerated > ago({days}d)
    | where ResourceProviderValue =~ "MICROSOFT.LOGIC"
    | summarize
        TotalRuns = count(),
        Succeeded = countif(ActivityStatusValue =~ "Succeeded"),
        Failed    = countif(ActivityStatusValue =~ "Failed")
    """
    inc_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        Total         = count(),
        TruePositive  = countif(Classification =~ "TruePositive"),
        FalsePositive = countif(Classification =~ "FalsePositive"),
        BenignPositive= countif(Classification =~ "BenignPositive"),
        Undetermined  = countif(Classification =~ "Undetermined")
    """

    try:
        la = ((await run_kql(la_q, days=days)).get("rows", [{}]) or [{}])[0]
    except Exception:
        la = {}

    try:
        inc = ((await run_kql(inc_q, days=days)).get("rows", [{}]) or [{}])[0]
    except Exception:
        inc = {}

    total = int(la.get("TotalRuns", 0))
    failed = int(la.get("Failed", 0))
    succeeded = int(la.get("Succeeded", 0))
    # AzureActivity sometimes only logs run-start events (ActivityStatusValue="Start"),
    # making explicit "Succeeded" counts zero. Fall back to total - failed.
    if total > 0 and succeeded == 0:
        succeeded = total - failed
    return {
        "playbook_runs": total,
        "playbook_success": succeeded,
        "playbook_failed": failed,
        "success_rate": round(100.0 * succeeded / total, 1) if total > 0 else 0.0,
        "incident_total": int(inc.get("Total", 0)),
        "true_positive": int(inc.get("TruePositive", 0)),
        "false_positive": int(inc.get("FalsePositive", 0)),
        "benign_positive": int(inc.get("BenignPositive", 0)),
        "undetermined": int(inc.get("Undetermined", 0)),
    }


@router.get("/playbooks")
async def get_playbook_stats(days: int = Query(30)):
    """Per-playbook execution statistics from AzureActivity."""
    q = f"""
    AzureActivity
    | where TimeGenerated > ago({days}d)
    | where ResourceProviderValue =~ "MICROSOFT.LOGIC"
    | where OperationNameValue has "workflowRun"
    | extend PlaybookName = tostring(split(ResourceId, '/')[-1])
    | summarize
        TotalRuns   = count(),
        Succeeded   = countif(ActivityStatusValue =~ "Succeeded"),
        Failed      = countif(ActivityStatusValue =~ "Failed"),
        LastRun     = max(TimeGenerated)
      by PlaybookName
    | extend SuccessRate = round(100.0 * Succeeded / TotalRuns, 1)
    | sort by TotalRuns desc
    | limit 25
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "playbooks": [
                {
                    "name": r.get("PlaybookName", "Unknown"),
                    "total_runs": int(r.get("TotalRuns", 0)),
                    "succeeded": int(r.get("Succeeded", 0)),
                    "failed": int(r.get("Failed", 0)),
                    "success_rate": float(r.get("SuccessRate", 0)),
                    "last_run": r.get("LastRun", ""),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Playbook stats query failed: %s", e)
        return {"playbooks": [], "error": str(e)}


@router.get("/outcomes")
async def get_incident_outcomes(days: int = Query(30)):
    """Closed incident classification distribution and daily open/close trend."""
    class_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed"
    | extend ClassLabel = iff(isempty(Classification), "Unclassified", Classification)
    | summarize Count = count() by ClassLabel
    | sort by Count desc
    """
    trend_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        Created = count(),
        Closed  = countif(Status =~ "Closed")
      by bin(CreatedTime, 1d)
    | sort by CreatedTime asc
    """

    try:
        class_rows = (await run_kql(class_q, days=days)).get("rows", [])
    except Exception as e:
        logger.error("Outcomes class query: %s", e)
        class_rows = []

    try:
        trend_rows = (await run_kql(trend_q, days=days)).get("rows", [])
    except Exception as e:
        logger.error("Outcomes trend query: %s", e)
        trend_rows = []

    return {
        "classifications": [
            {"label": r.get("ClassLabel", "Unknown"), "count": int(r.get("Count", 0))}
            for r in class_rows
        ],
        "daily_trend": [
            {
                "date": (r.get("CreatedTime", "") or "")[:10],
                "created": int(r.get("Created", 0)),
                "closed": int(r.get("Closed", 0)),
            }
            for r in trend_rows
        ],
    }


@router.get("/soar-actions")
async def get_soar_actions(days: int = Query(30)):
    """Automation rule owner-assignment and labeling outcomes per incident status."""
    q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | extend HasOwner     = isnotempty(Owner)
    | extend HasLabels    = Labels != "[]" and Labels != "" and isnotempty(Labels)
    | summarize
        Total        = count(),
        WithOwner    = countif(HasOwner),
        WithoutOwner = countif(not(HasOwner)),
        HighSev      = countif(Severity =~ "High"),
        AutoLabeled  = countif(HasLabels)
      by Status
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "by_status": [
                {
                    "status": r.get("Status", "Unknown"),
                    "total": int(r.get("Total", 0)),
                    "with_owner": int(r.get("WithOwner", 0)),
                    "without_owner": int(r.get("WithoutOwner", 0)),
                    "high_severity": int(r.get("HighSev", 0)),
                    "auto_labeled": int(r.get("AutoLabeled", 0)),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("SOAR actions query failed: %s", e)
        return {"by_status": [], "error": str(e)}


# ── New endpoints ─────────────────────────────────────────────────────────────

@router.get("/logic-apps")
async def get_logic_apps():
    """
    Fetch Logic App (playbook) definitions from the Azure Management API.
    Returns enabled/disabled state, trigger type, and creation/modified timestamps.
    Cross-references with AzureActivity run stats for a unified view.
    """
    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    if not sub or not rg:
        return {"logic_apps": [], "error": "Missing subscription_id or resource_group in config.json"}

    # Fetch Logic App definitions from Management API
    try:
        data = await call_azure_mgmt_api_async(
            f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Logic/workflows",
            api_version="2019-05-01",
        )
        raw_apps = data.get("value", [])
    except Exception as e:
        logger.error("Logic Apps Management API failed: %s", e)
        raw_apps = []
        mgmt_error = str(e)
    else:
        mgmt_error = None

    # Pull run stats from AzureActivity to merge in
    run_stats: dict[str, dict] = {}
    try:
        q = """
        AzureActivity
        | where TimeGenerated > ago(30d)
        | where ResourceProviderValue =~ "MICROSOFT.LOGIC"
        | where OperationNameValue has "workflowRun"
        | extend AppName = tostring(split(ResourceId, '/')[-1])
        | summarize
            TotalRuns = count(),
            Succeeded = countif(ActivityStatusValue =~ "Succeeded"),
            Failed    = countif(ActivityStatusValue =~ "Failed"),
            LastRun   = max(TimeGenerated)
          by AppName
        """
        rows = (await run_kql(q, days=30)).get("rows", [])
        for r in rows:
            name = (r.get("AppName") or "").lower()
            run_stats[name] = {
                "total_runs": int(r.get("TotalRuns", 0)),
                "succeeded":  int(r.get("Succeeded", 0)),
                "failed":     int(r.get("Failed", 0)),
                "last_run":   r.get("LastRun", ""),
            }
    except Exception as e:
        logger.warning("Logic Apps run-stats KQL failed: %s", e)

    apps = []
    for app in raw_apps:
        props   = app.get("properties", {})
        name    = app.get("name", "")
        state   = props.get("state", "Unknown")  # Enabled / Disabled / Stopped / Suspended
        defn    = props.get("definition", {})
        triggers = defn.get("triggers", {})
        trigger_type = next(iter(
            v.get("type", "Unknown") for v in triggers.values()
        ), "Unknown") if triggers else "None"

        stats = run_stats.get(name.lower(), {})
        total = stats.get("total_runs", 0)
        succ  = stats.get("succeeded", 0)
        apps.append({
            "name":           name,
            "state":          state,
            "trigger_type":   trigger_type,
            "created_time":   props.get("createdTime", ""),
            "changed_time":   props.get("changedTime", ""),
            "total_runs":     total,
            "succeeded":      succ,
            "failed":         stats.get("failed", 0),
            "success_rate":   round(100.0 * succ / total, 1) if total > 0 else None,
            "last_run":       stats.get("last_run", ""),
            "location":       app.get("location", ""),
            "tags":           app.get("tags", {}),
        })

    apps.sort(key=lambda x: (x["state"] != "Enabled", x["name"].lower()))

    result: dict = {
        "logic_apps":     apps,
        "enabled_count":  sum(1 for a in apps if a["state"] == "Enabled"),
        "disabled_count": sum(1 for a in apps if a["state"] == "Disabled"),
        "total_count":    len(apps),
    }
    if mgmt_error:
        result["mgmt_error"] = mgmt_error
    return result


@router.get("/automation-rules")
async def get_automation_rules():
    """List Sentinel automation rules with their trigger conditions and actions."""
    try:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(
            None,
            lambda: call_sentinel_mgmt_api("/automationRules", resource_type="automationrules"),
        )
        raw_rules = data.get("value", [])
    except Exception as e:
        logger.error("Automation rules fetch failed: %s", e)
        return {"rules": [], "error": str(e)}

    rules = []
    for r in raw_rules:
        props   = r.get("properties", {})
        actions = props.get("actions", [])

        parsed_actions = []
        for a in actions:
            order       = a.get("order", 0)
            action_type = a.get("actionType", "Unknown")
            detail      = {}
            if action_type == "RunPlaybook":
                detail["playbook"] = (a.get("actionConfiguration") or {}).get("logicAppResourceId", "")
            elif action_type == "ModifyProperties":
                cfg = a.get("actionConfiguration") or {}
                detail["changes"] = {k: v for k, v in cfg.items() if v is not None}
            parsed_actions.append({"order": order, "type": action_type, **detail})

        trigger    = props.get("triggeringLogic", {})
        conditions = trigger.get("conditions", [])
        parsed_conds = []
        for c in conditions:
            cond_props = c.get("conditionProperties", {})
            parsed_conds.append({
                "property": cond_props.get("propertyName", ""),
                "operator": cond_props.get("operator", ""),
                "values":   cond_props.get("propertyValues", []),
            })

        rules.append({
            "id":           r.get("name", ""),
            "display_name": props.get("displayName", ""),
            "enabled":      trigger.get("isEnabled", True),
            "order":        props.get("order", 0),
            "trigger_kind": trigger.get("triggersOn", ""),
            "trigger_when": trigger.get("triggersWhen", ""),
            "conditions":   parsed_conds,
            "actions":      parsed_actions,
            "created_time": props.get("createdTimeUtc", ""),
            "last_modified": props.get("lastModifiedTimeUtc", ""),
        })

    rules.sort(key=lambda x: (not x["enabled"], x["order"]))
    return {
        "rules":          rules,
        "total":          len(rules),
        "enabled_count":  sum(1 for r in rules if r["enabled"]),
        "disabled_count": sum(1 for r in rules if not r["enabled"]),
        "playbook_rules": sum(
            1 for r in rules
            if any(a["type"] == "RunPlaybook" for a in r["actions"])
        ),
    }


@router.get("/failures")
async def get_failure_details(days: int = Query(30)):
    """
    Detailed failure analysis: top failing playbooks, daily failure trend,
    and failure reason patterns from AzureActivity and AzureDiagnostics.
    """
    # Per-playbook failure breakdown
    by_playbook_q = f"""
    AzureActivity
    | where TimeGenerated > ago({days}d)
    | where ResourceProviderValue =~ "MICROSOFT.LOGIC"
    | where OperationNameValue has "workflowRun"
    | where ActivityStatusValue =~ "Failed"
    | extend PlaybookName = tostring(split(ResourceId, '/')[-1])
    | summarize
        FailedRuns  = count(),
        LastFailure = max(TimeGenerated)
      by PlaybookName
    | sort by FailedRuns desc
    | limit 20
    """

    # Daily failure trend
    daily_q = f"""
    AzureActivity
    | where TimeGenerated > ago({days}d)
    | where ResourceProviderValue =~ "MICROSOFT.LOGIC"
    | where OperationNameValue has "workflowRun"
    | summarize
        Total     = count(),
        Failed    = countif(ActivityStatusValue =~ "Failed"),
        Succeeded = countif(ActivityStatusValue =~ "Succeeded")
      by bin(TimeGenerated, 1d)
    | sort by TimeGenerated asc
    """

    # Failure reasons from AzureDiagnostics (Logic Apps run details)
    reasons_q = f"""
    AzureDiagnostics
    | where TimeGenerated > ago({days}d)
    | where ResourceType =~ "WORKFLOWS/RUNS"
    | where status_s =~ "Failed"
    | extend ErrorCode    = tostring(error_code_s)
    | extend ErrorMessage = tostring(error_message_s)
    | where isnotempty(ErrorCode) or isnotempty(ErrorMessage)
    | summarize Count = count() by ErrorCode, ErrorMessage
    | sort by Count desc
    | limit 15
    """

    results = await asyncio.gather(
        run_kql(by_playbook_q, days=days),
        run_kql(daily_q, days=days),
        run_kql(reasons_q, days=days),
        return_exceptions=True,
    )

    pb_rows    = results[0].get("rows", []) if not isinstance(results[0], Exception) else []
    daily_rows = results[1].get("rows", []) if not isinstance(results[1], Exception) else []
    reason_rows = results[2].get("rows", []) if not isinstance(results[2], Exception) else []

    return {
        "by_playbook": [
            {
                "name":         r.get("PlaybookName", "Unknown"),
                "failed_runs":  int(r.get("FailedRuns", 0)),
                "last_failure": r.get("LastFailure", ""),
            }
            for r in pb_rows
        ],
        "daily_trend": [
            {
                "date":      (r.get("TimeGenerated", "") or "")[:10],
                "total":     int(r.get("Total", 0)),
                "failed":    int(r.get("Failed", 0)),
                "succeeded": int(r.get("Succeeded", 0)),
            }
            for r in daily_rows
        ],
        "failure_reasons": [
            {
                "error_code":    r.get("ErrorCode", ""),
                "error_message": (r.get("ErrorMessage", "") or "")[:200],
                "count":         int(r.get("Count", 0)),
            }
            for r in reason_rows
        ],
        "total_failures": sum(int(r.get("FailedRuns", 0)) for r in pb_rows),
    }


# ── LLM Report ────────────────────────────────────────────────────────────────

@router.get("/report")
async def generate_automation_report(days: int = Query(30)):
    """
    Generate a comprehensive LLM-powered Automation & SOAR report.
    Gathers data from all available sources and uses the LLM to produce
    an executive-grade analysis with findings and recommendations.
    """
    # Incident severity distribution for automation gap analysis
    sev_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        Total  = count(),
        Open   = countif(Status =~ "New" or Status =~ "Active"),
        Closed = countif(Status =~ "Closed")
      by Severity
    | sort by Severity asc
    """

    # Top incident titles to identify automation targeting opportunities
    alert_source_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize
        IncidentCount = count(),
        HighSev       = countif(Severity =~ "High"),
        Unowned       = countif(isempty(Owner))
      by Title
    | sort by IncidentCount desc
    | limit 15
    """

    # ── Gather all data in parallel ──────────────────────────────
    tasks = await asyncio.gather(
        get_automation_overview(days=days),
        get_playbook_stats(days=days),
        get_incident_outcomes(days=days),
        get_soar_actions(days=days),
        get_logic_apps(),
        get_automation_rules(),
        get_failure_details(days=days),
        run_kql(sev_q, days=days),
        run_kql(alert_source_q, days=days),
        return_exceptions=True,
    )

    overview     = tasks[0] if not isinstance(tasks[0], Exception) else {}
    pb_stats     = tasks[1] if not isinstance(tasks[1], Exception) else {}
    outcomes     = tasks[2] if not isinstance(tasks[2], Exception) else {}
    soar         = tasks[3] if not isinstance(tasks[3], Exception) else {}
    logic_apps   = tasks[4] if not isinstance(tasks[4], Exception) else {}
    auto_rules   = tasks[5] if not isinstance(tasks[5], Exception) else {}
    failures     = tasks[6] if not isinstance(tasks[6], Exception) else {}
    sev_data     = tasks[7] if not isinstance(tasks[7], Exception) else {}
    alert_data   = tasks[8] if not isinstance(tasks[8], Exception) else {}

    raw_data = {
        "overview":         overview,
        "playbook_stats":   pb_stats,
        "outcomes":         outcomes,
        "soar_actions":     soar,
        "logic_apps":       logic_apps,
        "automation_rules": auto_rules,
        "failures":         failures,
    }

    # ── Build rich table-formatted context for the LLM ─────────
    playbooks    = pb_stats.get("playbooks", [])
    apps         = logic_apps.get("logic_apps", [])
    rules        = auto_rules.get("rules", [])
    top_fails    = failures.get("by_playbook", [])
    fail_reasons = failures.get("failure_reasons", [])
    soar_rows    = soar.get("by_status", [])
    sev_rows     = sev_data.get("rows", []) if isinstance(sev_data, dict) else []
    alert_rows   = alert_data.get("rows", []) if isinstance(alert_data, dict) else []

    disabled_apps = [a for a in apps if a["state"] != "Enabled"]
    zero_run_apps = [a for a in apps if a["total_runs"] == 0]
    high_fail_pbs = [p for p in playbooks if p["success_rate"] < 80 and p["total_runs"] > 0]

    total_inc     = overview.get("incident_total", 0)
    total_pb_runs = overview.get("playbook_runs", 0)
    auto_ratio    = round(total_pb_runs / total_inc, 2) if total_inc > 0 else 0

    # ── Table builders ───────────────────────────────────────────
    def _la_row(a):
        sr = f"{a['success_rate']}%" if a["success_rate"] is not None else "N/A"
        lr = (a.get("last_run") or "")[:10] or "Never"
        return (f"| {a['name']} | {a['state']} | {a['trigger_type']} "
                f"| {a['total_runs']} | {a.get('succeeded', 0)} | {a.get('failed', 0)} | {sr} | {lr} |")

    def _pb_row(p):
        return (f"| {p['name']} | {p['total_runs']} | {p['succeeded']} "
                f"| {p['failed']} | {p['success_rate']}% | {(p.get('last_run') or '')[:10] or 'Never'} |")

    def _rule_row(r):
        actions = ", ".join(a["type"] for a in r["actions"])
        pb_name = next(
            (a.get("playbook", "").split("/")[-1] for a in r["actions"] if a["type"] == "RunPlaybook"),
            "—",
        )
        return (f"| {r['display_name']} | {'Yes' if r['enabled'] else 'No'} "
                f"| {r['trigger_when']} | {actions} | {pb_name} |")

    la_header  = ("| Name | State | Trigger | Total Runs | Succeeded | Failed | Success% | Last Run |\n"
                  "|------|-------|---------|------------|-----------|--------|----------|----------|")
    pb_header  = ("| Playbook | Total Runs | Succeeded | Failed | Success% | Last Run |\n"
                  "|----------|------------|-----------|--------|----------|----------|")
    fl_header  = ("| Playbook | Failed Runs | Last Failure |\n"
                  "|----------|-------------|--------------|")
    err_header = ("| Error Code | Error Message | Count |\n"
                  "|------------|---------------|-------|")
    rul_header = ("| Rule Name | Enabled | Trigger Event | Actions | Playbook |\n"
                  "|-----------|---------|---------------|---------|---------|")
    soar_hdr   = ("| Status | Total | With Owner | Owner% | High Severity | Auto-Labeled |\n"
                  "|--------|-------|------------|--------|---------------|-------------|")
    sev_hdr    = ("| Severity | Total | Open | Closed |\n"
                  "|----------|-------|------|--------|")
    inc_hdr    = ("| Incident Title | Total | High Sev | Unowned (no auto-triage) |\n"
                  "|----------------|-------|----------|--------------------------|")

    la_rows   = "\n".join(_la_row(a) for a in apps[:30]) or "  No Logic Apps found"
    pb_rows   = "\n".join(_pb_row(p) for p in playbooks[:20]) or "  No data"
    fl_rows   = "\n".join(
        f"| {f['name']} | {f['failed_runs']} | {(f['last_failure'] or '')[:10]} |"
        for f in top_fails[:15]
    ) or "  No failure data"
    err_rows  = "\n".join(
        f"| {r['error_code'] or 'N/A'} | {(r['error_message'] or '')[:80]} | {r['count']} |"
        for r in fail_reasons[:12]
    ) or "  No structured error data"
    rul_rows  = "\n".join(_rule_row(r) for r in rules[:20]) or "  No automation rules"
    soar_rows_str = "\n".join(
        f"| {r['status']} | {r['total']} | {r['with_owner']} "
        f"| {round(100*r['with_owner']/r['total'], 1) if r['total'] else 0}% "
        f"| {r['high_severity']} | {r['auto_labeled']} |"
        for r in soar_rows
    ) or "  No data"
    sev_rows_str = "\n".join(
        f"| {r.get('Severity','?')} | {r.get('Total',0)} | {r.get('Open',0)} | {r.get('Closed',0)} |"
        for r in sev_rows
    ) or "  No data"
    inc_rows_str = "\n".join(
        f"| {str(r.get('Title','?'))[:60]} | {r.get('IncidentCount',0)} | {r.get('HighSev',0)} | {r.get('Unowned',0)} |"
        for r in alert_rows[:12]
    ) or "  No data"

    context = f"""WORKSPACE AUTOMATION & SOAR TELEMETRY — Last {days} days
========================================================

## 1. Global Statistics
- Total Logic App / playbook runs: {overview.get('playbook_runs', 0)}
- Succeeded: {overview.get('playbook_success', 0)} | Failed: {overview.get('playbook_failed', 0)} | Success rate: {overview.get('success_rate', 0)}%
- Total incidents in period: {total_inc}
- Automation ratio (runs per incident): {auto_ratio}
- True Positive: {overview.get('true_positive', 0)} | False Positive: {overview.get('false_positive', 0)} | Benign: {overview.get('benign_positive', 0)} | Undetermined: {overview.get('undetermined', 0)}
- Total failure count (playbooks): {failures.get('total_failures', 0)}

## 2. Incident Severity Distribution
{sev_hdr}
{sev_rows_str}

## 3. Logic App Inventory (Total: {logic_apps.get('total_count', 0)} | Enabled: {logic_apps.get('enabled_count', 0)} | Disabled: {logic_apps.get('disabled_count', 0)})
{la_header}
{la_rows}

### Disabled / Non-Enabled Logic Apps ({len(disabled_apps)}):
{chr(10).join(f"  - {a['name']} | State: {a['state']} | Last changed: {(a.get('changed_time') or '')[:10]}" for a in disabled_apps) or "  None — all apps are enabled"}

### Logic Apps with ZERO runs in {days}d (orphaned / dormant / misconfigured):
{chr(10).join(f"  - {a['name']} | State: {a['state']} | Trigger: {a['trigger_type']}" for a in zero_run_apps) or "  None — all apps have activity"}

## 4. Playbook Run Statistics (top 20 by volume)
{pb_header}
{pb_rows}

### High-failure-rate playbooks (success rate < 80%):
{chr(10).join(f"  - {p['name']}: {100-p['success_rate']:.1f}% failure rate | {p['failed']}/{p['total_runs']} runs failed" for p in high_fail_pbs) or "  None — all active playbooks are reliable"}

## 5. Failure Analysis
{fl_header}
{fl_rows}

### Error Patterns (from AzureDiagnostics):
{err_header}
{err_rows}

## 6. Sentinel Automation Rules (Total: {auto_rules.get('total', 0)} | Enabled: {auto_rules.get('enabled_count', 0)} | Disabled: {auto_rules.get('disabled_count', 0)} | Triggering Playbooks: {auto_rules.get('playbook_rules', 0)})
{rul_header}
{rul_rows}

### Rules NOT triggering any playbook (property-modification only):
{chr(10).join(f"  - {r['display_name']} [{r['trigger_when']}]" for r in rules if not any(a['type'] == 'RunPlaybook' for a in r['actions'])) or "  None — all rules trigger playbooks"}

## 7. SOAR Incident Handling Metrics
{soar_hdr}
{soar_rows_str}

## 8. Closed Incident Classification
{chr(10).join(f"  - {c['label']}: {c['count']}" for c in outcomes.get('classifications', [])) or "  No classification data"}

## 9. Top Incident Titles — Automation Targeting Opportunities
(Unowned incidents = likely no automation triage occurred)
{inc_hdr}
{inc_rows_str}
"""

    system_prompt = """You are a senior Microsoft Sentinel SOAR engineer and security automation specialist.
Analyse the workspace automation telemetry provided and produce a comprehensive, detailed assessment report.

Your report MUST include ALL of the following sections with proper markdown headings (## for main, ### for sub):

## Executive Summary
3-4 sentences covering: overall automation health, current maturity level (Basic / Developing / Advanced / Expert), the single most critical problem, and the single highest-value improvement opportunity. Include a composite automation health score out of 10.

## Logic App Inventory Analysis
- Full table of all Logic Apps: name, state (Enabled/Disabled), trigger type, run count, success rate
- For each DISABLED Logic App: assess whether it should be re-enabled, identify the operational risk of leaving it disabled
- For each Logic App with ZERO runs: determine if it is orphaned, misconfigured, or legitimately dormant — state what investigation step should be taken
- Flag apps with suspicious names (duplicates, test/dev apps left in production)
- Logic App health score and breakdown

## Run History & Performance Statistics
- Total runs, daily average, peak vs trough periods (infer from data)
- Highest-volume Logic Apps with reliability assessment
- Lowest-reliability Logic Apps (high failure rate) with performance rating
- Automation ratio analysis: playbook runs per incident — what does this ratio tell us?
- Identify Logic Apps that run too infrequently to be considered effective automated response

## Failure Analysis & Root Cause Assessment
- Detailed breakdown of the top failing playbooks — WHY each one is failing based on error patterns
- Classify failures: transient (timeout/network) vs structural (misconfiguration/permission) vs logic errors
- For each high-failure playbook: specific remediation steps
- Estimated business impact: how many incidents were not auto-handled due to these failures?
- Prioritised remediation list (Critical → High → Medium)

## Automation Coverage Assessment
- Which incident SEVERITIES (High/Medium/Low) are covered by playbooks?
- What PERCENTAGE of incidents receive automated responses (use automation ratio data)?
- Which specific incident types / alert titles have NO automation coverage (use the title data)?
- Gap analysis: what categories of threats are completely unautomated?
- Coverage score by severity tier

## SOAR Efficiency Metrics
- Owner assignment rate by incident status (are incidents being triaged?)
- Auto-labeling effectiveness and what it indicates
- High-severity incidents without owners — risk assessment
- True Positive rate implications for automation tuning (are playbooks firing on valid signals?)
- SOAR maturity score per function: Triage | Enrichment | Response | Notification | Closure

## Recommendations: New Logic Apps / Playbooks to Add
Provide exactly 10 specific, actionable recommendations for new playbooks tailored to THIS workspace. For each recommendation:
- **Name**: Exact suggested Logic App name (use Sentinel playbook naming convention)
- **Purpose**: What it does — 1-2 sentences
- **Trigger**: Exact Sentinel automation rule condition (e.g., "Incident severity = High AND title contains X")
- **Priority**: Critical / High / Medium
- **Gap it closes**: Which current blind spot this addresses
- **Expected impact**: Estimated reduction in manual analyst work or MTTD/MTTR improvement
- **Rationale**: Reference specific numbers from the telemetry that justify this recommendation

## Recommendations: Automation Rule Improvements
5-7 specific changes to make to existing Sentinel automation rules to improve coverage, efficiency, and reliability.

Be precise and evidence-based. Every finding must reference specific numbers from the data. Use markdown tables wherever a comparison is being made. Do NOT include generic advice unrelated to this workspace's actual telemetry."""

    token_usage: dict = {}
    try:
        result       = await llm_service.complete(system_prompt, context)
        llm_analysis = result["text"]
        token_usage  = result["usage"]
    except Exception as e:
        logger.exception("LLM report generation failed")
        llm_analysis = f"LLM analysis unavailable — {type(e).__name__}: {e}"

    return {
        "days":         days,
        "raw_data":     raw_data,
        "llm_analysis": llm_analysis,
        "token_usage":  token_usage,
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
