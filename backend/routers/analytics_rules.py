import asyncio
import json as _json
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from backend.services.sentinel import run_kql, call_azure_mgmt_api_async
from backend.services import llm as llm_service
from backend.config import settings
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analytics-rules", tags=["analytics-rules"])


def _parse_alert_entities(raw) -> list[dict]:
    """Extract [{type, name}] from SecurityAlert Entities column (dynamic/JSON)."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw or raw in ("[]", "null"):
            return []
        try:
            raw = _json.loads(raw)
        except Exception:
            return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    result: list[dict] = []
    seen: set = set()
    for item in raw:
        if not isinstance(item, dict):
            try:
                item = _json.loads(item) if isinstance(item, str) else {}
            except Exception:
                continue
        etype = str(item.get("Type") or item.get("type") or "").lower().strip()
        if not etype or etype.startswith("$"):
            continue
        if etype == "account":
            name = item.get("Name") or item.get("AccountName") or ""
        elif etype == "ip":
            name = item.get("Address") or ""
        elif etype == "host":
            name = item.get("HostName") or item.get("NetBiosName") or item.get("FQDN") or ""
        elif etype in ("url", "uri"):
            name = item.get("Url") or ""
        elif etype == "file":
            name = item.get("Name") or item.get("Directory") or ""
        elif etype == "dns":
            name = item.get("DomainName") or ""
        elif etype == "process":
            name = item.get("CommandLine") or str(item.get("ProcessId") or "") or ""
        elif etype == "cloud":
            name = item.get("Name") or str(item.get("AppId") or "") or ""
        else:
            name = next(
                (str(v)[:100] for k, v in item.items()
                 if not k.startswith("$") and k not in ("Type", "type") and v),
                ""
            )
        name = str(name).strip()[:120]
        if not name:
            continue
        key = (etype, name)
        if key not in seen:
            seen.add(key)
            result.append({"type": etype.title(), "name": name})
    return result[:10]


class TuneSuggestionRequest(BaseModel):
    rule_name: str
    kql_query: str = ""
    incident_comments: list[dict] = []
    alert_count: int = 0
    severity: str = ""
    description: str = ""


@router.get("/overview")
async def get_rules_overview(days: float = Query(30)):
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
async def get_rule_activity(days: float = Query(30)):
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
async def get_alerts_by_tactic(days: float = Query(30)):
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
async def get_alert_trend(days: float = Query(30)):
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
async def get_silent_rules(days: float = Query(30)):
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


@router.get("/rule-detail")
async def get_rule_detail(name: str = Query(...), days: float = Query(30)):
    """
    Fetch full detail for a single analytics rule:
    - KQL query & configuration from the Azure Management API (Sentinel alertRules)
    - Recent alert samples from SecurityAlert
    - Incident comments linked to this rule via two strategies (alert-ID join, then title fallback)
    """
    esc = name.replace("'", "\\'")

    # ── KQL queries ───────────────────────────────────────────────────────────
    samples_q = f"""
    SecurityAlert
    | where TimeGenerated > ago({days}d)
    | where AlertName =~ '{esc}'
    | project TimeGenerated, AlertSeverity, Description, Tactics, SystemAlertId,
              Entities = column_ifexists("Entities", dynamic(null))
    | sort by TimeGenerated desc
    | limit 5
    """

    # Primary: resolve incident comments via alert-ID join (most accurate)
    # Returns individual rows — avoids make_set() whose dynamic array is serialised
    # as a JSON string by the API, causing character-by-character iteration bugs.
    comments_join_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | where isnotempty(AlertIds)
    | mv-expand AlertId = todynamic(AlertIds)
    | extend AlertIdStr = tostring(AlertId)
    | join kind=inner (
        SecurityAlert
        | where TimeGenerated > ago({days}d)
        | where AlertName =~ '{esc}'
        | project SystemAlertId
    ) on $left.AlertIdStr == $right.SystemAlertId
    | where isnotempty(Comments)
    | mv-expand CommentObj = todynamic(Comments)
    | extend CommentMsg = tostring(CommentObj.message)
    | where isnotempty(CommentMsg) and strlen(CommentMsg) > 3
    | project IncidentNumber, Title, Severity, Status, CommentMsg
    | sort by IncidentNumber desc
    | limit 20
    """

    # Fallback: match incident title against rule name
    comments_title_q = f"""
    SecurityIncident
    | where TimeGenerated > ago({days}d)
    | where isnotempty(Comments)
    | where Title has '{esc}'
    | mv-expand CommentObj = todynamic(Comments)
    | extend CommentMsg = tostring(CommentObj.message)
    | where isnotempty(CommentMsg) and strlen(CommentMsg) > 3
    | project IncidentNumber, Title, Severity, Status, CommentMsg
    | sort by IncidentNumber desc
    | limit 20
    """

    samples_res, comments_join_res, comments_title_res = await asyncio.gather(
        run_kql(samples_q, days=days),
        run_kql(comments_join_q, days=days),
        run_kql(comments_title_q, days=days),
        return_exceptions=True,
    )

    # ── Rule definition from Azure Management API ─────────────────────────────
    rule_def: dict = {}
    try:
        sub = settings.SUBSCRIPTION_ID
        rg  = settings.RESOURCE_GROUP
        ws  = settings.WORKSPACE_NAME
        if sub and rg and ws:
            path = (
                f"/subscriptions/{sub}/resourceGroups/{rg}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
                f"/providers/Microsoft.SecurityInsights/alertRules"
            )
            data = await call_azure_mgmt_api_async(path, api_version="2023-02-01-preview")
            for r in data.get("value", []):
                props = r.get("properties", {})
                if props.get("displayName", "").lower() == name.lower():
                    rule_def = {
                        "display_name":         props.get("displayName", ""),
                        "description":          props.get("description", ""),
                        "severity":             props.get("severity", ""),
                        "enabled":              props.get("enabled", True),
                        "tactics":              props.get("tactics", []),
                        "techniques":           props.get("techniques", []),
                        "query":                props.get("query", ""),
                        "query_period":         props.get("queryPeriod", ""),
                        "query_frequency":      props.get("queryFrequency", ""),
                        "trigger_threshold":    props.get("triggerThreshold", 0),
                        "trigger_operator":     props.get("triggerOperator", ""),
                        "suppression_enabled":  props.get("suppressionEnabled", False),
                        "suppression_duration": props.get("suppressionDuration", ""),
                    }
                    break
    except Exception as e:
        logger.warning("Alert rule definition fetch failed for '%s': %s", name, e)

    # ── Alert samples ─────────────────────────────────────────────────────────
    sample_rows = samples_res.get("rows", []) if not isinstance(samples_res, Exception) else []
    alert_samples = [
        {
            "time":        r.get("TimeGenerated", ""),
            "severity":    r.get("AlertSeverity", ""),
            "description": r.get("Description", ""),
            "tactics":     r.get("Tactics", ""),
            "entities":    _parse_alert_entities(r.get("Entities")),
        }
        for r in sample_rows
    ]

    # ── Incident comments — prefer join result, fall back to title match ───────
    incident_comments: list[dict] = []
    seen_comments: set = set()

    def _absorb_comment_rows(rows: list) -> None:
        for r in rows:
            msg = str(r.get("CommentMsg") or "").strip()
            if not msg or len(msg) <= 3:
                continue
            num = r.get("IncidentNumber", "")
            key = (str(num), msg[:80])
            if key in seen_comments:
                continue
            seen_comments.add(key)
            incident_comments.append({
                "incident_number": num,
                "incident_title":  r.get("Title", ""),
                "severity":        r.get("Severity", ""),
                "status":          r.get("Status", ""),
                "comment":         msg,
            })

    if not isinstance(comments_join_res, Exception):
        _absorb_comment_rows(comments_join_res.get("rows", []))

    if not incident_comments and not isinstance(comments_title_res, Exception):
        _absorb_comment_rows(comments_title_res.get("rows", []))

    return {
        "rule_name":         name,
        "definition":        rule_def,
        "alert_samples":     alert_samples,
        "incident_comments": incident_comments[:15],
    }


@router.post("/tune-suggestion")
async def get_tune_suggestion(req: TuneSuggestionRequest):
    """
    Generate LLM fine-tuning suggestions for an analytics rule.
    Uses incident comments when available for evidence-based recommendations;
    falls back to general KQL quality analysis otherwise.
    """
    has_comments = bool(req.incident_comments)

    if has_comments:
        comments_text = "\n".join(
            f"- Incident #{c.get('incident_number','?')} "
            f"[{c.get('severity','?')} / {c.get('status','?')}]: "
            f"{c.get('comment','')}"
            for c in req.incident_comments[:12]
        )
        context = (
            f"Analytics Rule: {req.rule_name}\n"
            f"Severity: {req.severity}\n"
            f"Alert Count (period): {req.alert_count}\n\n"
            f"KQL Query:\n{req.kql_query or '(Not available — built-in or Microsoft-managed rule)'}\n\n"
            f"Analyst Incident Comments ({len(req.incident_comments)} from linked incidents):\n"
            f"{comments_text}"
        )
        system = (
            "You are a senior Microsoft Sentinel detection engineer. "
            "Analyse the analytics rule and the SOC analyst incident comments to produce targeted, evidence-based fine-tuning recommendations.\n\n"
            "Structure your response with these exact markdown sections:\n\n"
            "## Analyst Pattern Analysis\n"
            "What do the comments reveal? Summarise recurring false-positive patterns, true-positive themes, "
            "analyst frustrations, or investigation notes that indicate tuning opportunities.\n\n"
            "## Issues Identified\n"
            "List each distinct issue with its evidence from the comments and its impact "
            "(false positives / alert fatigue / missed detections).\n\n"
            "## Fine-Tuning Recommendations\n"
            "For each recommendation provide:\n"
            "- **Change**: What to modify in the KQL or rule config\n"
            "- **Evidence**: Which comments support this\n"
            "- **KQL Snippet**: Actual revised code in a fenced code block\n"
            "- **Expected Impact**: Estimated noise reduction or precision gain\n\n"
            "## Tuned Query (Full)\n"
            "The complete revised KQL in a single fenced code block with inline comments on key changes.\n\n"
            "## Priority Actions\n"
            "Numbered list of the 3 highest-impact changes, ordered by impact.\n\n"
            "Ground every recommendation in the analyst comments. Include real KQL code."
        )
    else:
        context = (
            f"Analytics Rule: {req.rule_name}\n"
            f"Severity: {req.severity}\n"
            f"Alert Count (period): {req.alert_count}\n"
            f"Description: {req.description or 'Not provided'}\n\n"
            f"KQL Query:\n{req.kql_query or '(Not available — built-in or Microsoft-managed rule)'}"
        )
        system = (
            "You are a senior Microsoft Sentinel detection engineer specialising in KQL optimisation and detection quality. "
            "Analyse the analytics rule and produce expert fine-tuning recommendations.\n\n"
            "Structure your response with these exact markdown sections:\n\n"
            "## Query Analysis\n"
            "What is the rule detecting? Identify weaknesses: over-broad matching, missing context, "
            "performance issues, entity mapping gaps, or coverage blind spots.\n\n"
            "## Fine-Tuning Recommendations\n"
            "Provide at least 4 recommendations covering noise reduction, enrichment/context, "
            "performance, and coverage gaps. For each:\n"
            "- **Change**: What to modify\n"
            "- **Why**: Technical rationale\n"
            "- **KQL Snippet**: Revised code in a fenced code block\n"
            "- **Expected Impact**: Precision improvement, volume reduction, or coverage gain\n\n"
            "## Tuned Query (Full)\n"
            "The complete revised KQL in a single fenced code block with inline `// comments` "
            "explaining every meaningful change.\n\n"
            "## Configuration Recommendations\n"
            "Suggest improvements beyond the KQL: query period/frequency, trigger threshold, "
            "entity mappings, suppression settings, MITRE technique tags.\n\n"
            "Include real KQL code. Assume intermediate analyst KQL knowledge."
        )

    try:
        result = await llm_service.complete(system, context)
        return {
            "suggestion":   result["text"],
            "based_on":     "incident_comments" if has_comments else "general",
            "token_usage":  result["usage"],
        }
    except Exception as e:
        logger.error("Tune suggestion failed for rule '%s': %s", req.rule_name, e)
        raise HTTPException(status_code=500, detail=f"LLM suggestion failed: {e}")


# ── LLM Bulk Report ───────────────────────────────────────────────────────────

@router.get("/report")
async def generate_analytics_rules_report(days: float = Query(30), model: str | None = Query(None)):
    """
    Generate a comprehensive LLM-powered analytics rules assessment report.
    Gathers all rule telemetry, MITRE coverage, trend data, and KQL definitions,
    then uses the LLM to produce prioritised tuning recommendations for all rules.
    """
    # ── 1. Gather all telemetry in parallel ───────────────────────────────────
    tasks = await asyncio.gather(
        get_rules_overview(days=days),
        get_rule_activity(days=days),
        get_alerts_by_tactic(days=days),
        get_alert_trend(days=days),
        get_silent_rules(days=days),
        return_exceptions=True,
    )

    overview_d    = tasks[0] if not isinstance(tasks[0], Exception) else {}
    activity_d    = tasks[1] if not isinstance(tasks[1], Exception) else {}
    tactic_d      = tasks[2] if not isinstance(tasks[2], Exception) else {}
    trend_d       = tasks[3] if not isinstance(tasks[3], Exception) else {}
    silent_d      = tasks[4] if not isinstance(tasks[4], Exception) else {}

    rules         = activity_d.get("rules", [])
    tactics       = tactic_d.get("tactics", [])
    trend         = trend_d.get("trend", [])
    silent_list   = silent_d.get("silent_rules", [])

    # ── 2. Fetch all rule definitions from Azure Management API (single call) ─
    rule_defs: dict[str, dict] = {}
    try:
        sub = settings.SUBSCRIPTION_ID
        rg  = settings.RESOURCE_GROUP
        ws  = settings.WORKSPACE_NAME
        if sub and rg and ws:
            path = (
                f"/subscriptions/{sub}/resourceGroups/{rg}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
                f"/providers/Microsoft.SecurityInsights/alertRules"
            )
            data = await call_azure_mgmt_api_async(path, api_version="2023-02-01-preview")
            for r in data.get("value", []):
                props = r.get("properties", {})
                name  = props.get("displayName", "")
                if name:
                    rule_defs[name.lower()] = {
                        "description":          props.get("description", ""),
                        "tactics":              props.get("tactics", []),
                        "techniques":           props.get("techniques", []),
                        "query":                props.get("query", ""),
                        "query_period":         props.get("queryPeriod", ""),
                        "query_frequency":      props.get("queryFrequency", ""),
                        "trigger_threshold":    props.get("triggerThreshold", 0),
                        "trigger_operator":     props.get("triggerOperator", ""),
                        "suppression_enabled":  props.get("suppressionEnabled", False),
                        "suppression_duration": props.get("suppressionDuration", ""),
                    }
    except Exception as e:
        logger.warning("Rule definitions fetch failed for bulk report: %s", e)

    # ── 3. Build context ──────────────────────────────────────────────────────
    ov            = overview_d
    total_alerts  = ov.get("total_alerts", 0)
    unique_rules  = ov.get("unique_rules", 0)
    high_alerts   = ov.get("high_alerts", 0)
    medium_alerts = ov.get("medium_alerts", 0)
    low_alerts    = ov.get("low_alerts", 0)

    def _pct(n: int) -> str:
        return f"{round(n / total_alerts * 100, 1)}%" if total_alerts else "0%"

    # All active rules table
    def _rule_row(r: dict) -> str:
        d = rule_defs.get(r["name"].lower(), {})
        tactics_str = ", ".join(d.get("tactics", [])) or "—"
        kql         = d.get("query", "")
        kql_preview = (kql[:90].replace("\n", " ") + "…") if len(kql) > 90 else (kql.replace("\n", " ") if kql else "(built-in)")
        return (
            f"| {r['name'][:55]} | {r['severity']} | {r['alert_count']:,} "
            f"| {r['linked_incidents']} | {tactics_str[:40]} | {kql_preview[:80]} |"
        )

    rule_hdr = (
        "| Rule Name | Severity | Alerts | Incidents | MITRE Tactics | KQL Preview |\n"
        "|-----------|----------|--------|-----------|---------------|-------------|"
    )
    rule_rows_str = "\n".join(_rule_row(r) for r in rules) or "  No active rules"

    # MITRE tactic table
    tactic_hdr = (
        "| MITRE Tactic | Alert Count | Unique Rules |\n"
        "|-------------|-------------|-------------|"
    )
    tactic_rows_str = "\n".join(
        f"| {t['tactic'][:45]} | {t['alert_count']:,} | {t['unique_rules']} |"
        for t in tactics[:20]
    ) or "  No tactic data"

    # Trend — last 7 days
    trend_str = " → ".join(
        f"{d['date']}: H={d.get('High',0)} M={d.get('Medium',0)} L={d.get('Low',0)}"
        for d in trend[-7:]
    ) or "No trend data"

    # Silent rules
    silent_str = "\n".join(
        f"  - {r['name']} | {r['severity']} | Last fired: {(r.get('last_fired') or '')[:10] or '?'} | Total alerts: {r['total_alerts']}"
        for r in silent_list[:20]
    ) or "  None — all rules appear active"

    # Full KQL for top 10 rules (highest volume)
    top_kql_blocks: list[str] = []
    for r in rules[:10]:
        d   = rule_defs.get(r["name"].lower(), {})
        kql = d.get("query", "")
        if kql:
            cfg = (
                f"Run: every {d.get('query_frequency','')} | "
                f"Period: {d.get('query_period','')} | "
                f"Threshold: {d.get('trigger_operator','')} {d.get('trigger_threshold',0)} | "
                f"Suppression: {'On' if d.get('suppression_enabled') else 'Off'}"
            )
            top_kql_blocks.append(
                f"### {r['name']} ({r['severity']}, {r['alert_count']:,} alerts, {r['linked_incidents']} incidents)\n"
                f"Tactics: {', '.join(d.get('tactics', [])) or '—'} | Techniques: {', '.join(d.get('techniques', [])) or '—'}\n"
                f"Config: {cfg}\n"
                f"Description: {(d.get('description') or 'N/A')[:200]}\n"
                f"KQL:\n```kql\n{kql[:1000]}\n```"
            )
    top_kql_str = "\n\n".join(top_kql_blocks) if top_kql_blocks else \
        "  (KQL not available — built-in rules or Azure Management API not configured)"

    context = f"""MICROSOFT SENTINEL ANALYTICS RULES ASSESSMENT — Last {days} days
========================================================================================

## 1. Overview
- Active detection rules (fired at least once): {unique_rules}
- Total alerts generated:                       {total_alerts:,}
- High severity alerts:                         {high_alerts:,} ({_pct(high_alerts)})
- Medium severity alerts:                       {medium_alerts:,} ({_pct(medium_alerts)})
- Low severity alerts:                          {low_alerts:,} ({_pct(low_alerts)})
- Silent rules (not fired in {days}d):           {len(silent_list)}

## 2. All Active Rules ({len(rules)} rules, sorted by alert volume)
{rule_hdr}
{rule_rows_str}

## 3. MITRE ATT&CK Tactic Distribution
{tactic_hdr}
{tactic_rows_str}

## 4. Daily Alert Trend (last 7 days of period)
{trend_str}

## 5. Silent / Stale Rules ({len(silent_list)} total)
{silent_str}

## 6. Full KQL Queries — Top 10 Highest-Volume Rules
{top_kql_str}
"""

    system_prompt = (
        "You are a senior Microsoft Sentinel detection engineer and SOC architect. "
        "Analyse the full analytics rules telemetry below and produce a comprehensive, "
        "expert-grade detection assessment report with specific, actionable recommendations for every rule.\n\n"
        "Your report MUST include ALL of the following sections with proper markdown headings "
        "(## for main sections, ### for sub-sections, #### for individual items):\n\n"
        "## Executive Summary\n"
        "3–4 sentences: overall detection health, severity distribution concerns, most critical gap, "
        "and top optimisation opportunity. Include:\n"
        "- **Detection Health Score**: X / 10 with brief justification\n"
        "- **Alert Noise Rating**: Very High / High / Medium / Low — with ratio reasoning\n"
        "- **MITRE Coverage**: one sentence on breadth vs. blind spots\n\n"
        "## Rule Effectiveness Analysis\n"
        "For EACH rule provided, produce a row in a markdown table with columns:\n"
        "Rule | Severity | Alert Volume Assessment | Severity Fit | Tuning Priority | Key Finding\n"
        "Volume Assessment: Excessive / High / Normal / Low / Dormant\n"
        "Severity Fit: Correct / Over-rated / Under-rated\n"
        "Tuning Priority: Critical / High / Medium / Low\n\n"
        "## Detection Gap Analysis\n"
        "Based on the MITRE tactic distribution:\n"
        "- Which tactics are over-represented (alert fatigue risk)?\n"
        "- Which tactics are missing or under-represented (coverage gap)?\n"
        "- Recommended detection rules to fill the top 3 identified gaps\n\n"
        "## Top 5 High-Priority Tuning Recommendations\n"
        "For the 5 rules most in need of tuning, for each provide:\n"
        "- **Rule**: name and current alert volume\n"
        "- **Problem**: specific issue identified (over-broad matching, missing time window, no exclusion list, etc.)\n"
        "- **Evidence**: what in the data suggests this (high volume vs. low incident conversion, severity mismatch, etc.)\n"
        "- **KQL Fix**: actual revised KQL snippet in a fenced `kql` code block\n"
        "- **Expected Impact**: estimated noise reduction % or precision gain\n\n"
        "## Silent Rules Assessment\n"
        "For each silent rule listed, provide:\n"
        "- Likely reason for going silent (broken connector, environment change, logic error, legitimate gap)\n"
        "- Risk level if it stays silent: Critical / High / Medium / Low\n"
        "- Recommended action: Re-enable / Investigate / Retire / Update KQL\n\n"
        "## Alert Trend Analysis\n"
        "- What does the daily severity trend reveal? (spikes, drift, drops)\n"
        "- Are severity ratios aligned with expected threat patterns?\n"
        "- Any anomalies warranting immediate investigation?\n\n"
        "## MITRE Coverage Scorecard\n"
        "Markdown table: Tactic | Alert Volume | Rule Count | Coverage Grade (A–F) | Gap Score (1–10) | Recommendation\n\n"
        "## Prioritised Action Plan\n"
        "Numbered list of the top 10 actions ordered by impact:\n"
        "- **Action**: what to do\n"
        "- **Effort**: Low / Medium / High\n"
        "- **Impact**: noise reduction / coverage gain / compliance\n"
        "- **Owner**: Detection Engineer / SOC Analyst / Both\n\n"
        "Ground every finding in the telemetry. Include real KQL where recommending changes. "
        "Assume the reader is a competent detection engineer who wants specific, actionable guidance."
    )

    try:
        result = await llm_service.complete(system_prompt, context, model=model)
        return {
            "llm_analysis": result["text"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "token_usage":  result["usage"],
        }
    except Exception as e:
        logger.error("Analytics rules report generation failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")
