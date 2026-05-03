"""
Sentinel DCR (Data Collection Rules) Assessment & Injection Optimization router.

GET /api/dcr/overview   → summary stats: DCR count, streams, ingestion totals
GET /api/dcr/rules      → full DCR inventory from Azure Management API
GET /api/dcr/ingestion  → ingestion volume by table from Usage table
GET /api/dcr/errors     → DCR log errors and dropped events
GET /api/dcr/activity   → DCR create/update/delete activity from AzureActivity
GET /api/dcr/report     → LLM-powered comprehensive DCR assessment
"""
import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Query

from backend.services.sentinel import call_azure_mgmt_api_async, run_kql
from backend.services import llm as llm_service
from backend.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dcr", tags=["dcr"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _days_since(iso_str: str) -> int | None:
    if not iso_str:
        return None
    try:
        ts = iso_str.rstrip("Z")
        dt = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


def _parse_dcr(raw: dict) -> dict:
    props       = raw.get("properties", {})
    sources     = props.get("dataSources", {})
    dests       = props.get("destinations", {})
    flows       = props.get("dataFlows", [])
    transforms  = [f for f in flows if f.get("transformKql")]
    la_dests    = dests.get("logAnalytics", [])
    system_data = raw.get("systemData", {})
    changed     = system_data.get("lastModifiedAt", "")
    created     = system_data.get("createdAt", "")
    return {
        "id":                    raw.get("id", ""),
        "name":                  raw.get("name", ""),
        "location":              raw.get("location", ""),
        "kind":                  raw.get("kind", ""),
        "provisioning_state":    props.get("provisioningState", ""),
        "created_at":            created,
        "last_modified":         changed,
        "days_since_modified":   _days_since(changed),
        "data_flows":            len(flows),
        "transformations":       len(transforms),
        "has_transformation":    len(transforms) > 0,
        "perf_counters":         len(sources.get("performanceCounters", [])),
        "windows_events":        len(sources.get("windowsEventLogs", [])),
        "syslog_sources":        len(sources.get("syslog", [])),
        "extension_sources":     len(sources.get("extensions", [])),
        "log_analytics_count":   len(la_dests),
        "workspace_names":       [ws.get("name", "") for ws in la_dests],
        "custom_streams":        len(props.get("streamDeclarations", {})),
        "stream_declarations":   list(props.get("streamDeclarations", {}).keys()),
        "tags":                  raw.get("tags", {}),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/rules")
async def get_dcr_rules():
    """Fetch all DCRs in the subscription from Azure Management API."""
    sub = settings.SUBSCRIPTION_ID
    if not sub:
        return {"rules": [], "total": 0, "error": "Missing subscription_id in config.json"}
    try:
        data = await call_azure_mgmt_api_async(
            f"/subscriptions/{sub}/providers/Microsoft.Insights/dataCollectionRules",
            api_version="2022-06-01",
        )
        rules           = [_parse_dcr(r) for r in data.get("value", [])]
        succeeded       = [r for r in rules if r["provisioning_state"] == "Succeeded"]
        failed          = [r for r in rules if r["provisioning_state"] not in ("Succeeded", "")]
        with_transform  = [r for r in rules if r["has_transformation"]]
        custom_stream   = [r for r in rules if r["custom_streams"] > 0]
        return {
            "rules":                rules,
            "total":                len(rules),
            "succeeded_count":      len(succeeded),
            "failed_count":         len(failed),
            "with_transformations": len(with_transform),
            "with_custom_streams":  len(custom_stream),
            "total_data_flows":     sum(r["data_flows"] for r in rules),
            "total_transformations": sum(r["transformations"] for r in rules),
        }
    except Exception as e:
        logger.error("DCR rules fetch failed: %s", e)
        return {"rules": [], "total": 0, "error": str(e)}


@router.get("/ingestion")
async def get_ingestion_stats(days: int = Query(30)):
    """Ingestion volumes and trends from the Usage table."""
    volume_q = f"""
    Usage
    | where TimeGenerated > ago({days}d)
    | where IsBillable == true
    | summarize
        TotalMB    = round(sum(Quantity), 2),
        DailyAvgMB = round(sum(Quantity) / {days}, 2)
      by DataType
    | sort by TotalMB desc
    | limit 40
    """
    trend_q = f"""
    Usage
    | where TimeGenerated > ago({days}d)
    | where IsBillable == true
    | summarize TotalMB = round(sum(Quantity), 2) by bin(TimeGenerated, 1d)
    | sort by TimeGenerated asc
    """
    summary_q = f"""
    Usage
    | where TimeGenerated > ago({days}d)
    | where IsBillable == true
    | summarize
        TotalMB    = round(sum(Quantity), 2),
        TableCount = dcount(DataType),
        DailyAvgMB = round(sum(Quantity) / {days}, 2)
    """
    try:
        volume, trend, summary = await asyncio.gather(
            run_kql(volume_q, days=days),
            run_kql(trend_q,  days=days),
            run_kql(summary_q, days=days),
            return_exceptions=True,
        )
        vol_rows  = volume.get("rows", [])  if not isinstance(volume,  Exception) else []
        trn_rows  = trend.get("rows",  [])  if not isinstance(trend,   Exception) else []
        sum_rows  = summary.get("rows", []) if not isinstance(summary, Exception) else []

        total_mb  = sum_rows[0].get("TotalMB",    0) if sum_rows else 0
        tbl_count = sum_rows[0].get("TableCount", 0) if sum_rows else 0
        daily_avg = sum_rows[0].get("DailyAvgMB", 0) if sum_rows else 0

        return {
            "summary": {
                "total_mb":            total_mb,
                "total_gb":            round(total_mb / 1024, 3),
                "table_count":         tbl_count,
                "daily_avg_mb":        daily_avg,
                "estimated_monthly_gb": round(daily_avg * 30 / 1024, 2),
            },
            "by_table": [
                {
                    "table":      r.get("DataType", ""),
                    "total_mb":   r.get("TotalMB",    0),
                    "daily_avg":  r.get("DailyAvgMB", 0),
                    "pct": round(100 * r.get("TotalMB", 0) / total_mb, 1) if total_mb > 0 else 0,
                }
                for r in vol_rows
            ],
            "daily_trend": [
                {"date": r.get("TimeGenerated", "")[:10], "total_mb": r.get("TotalMB", 0)}
                for r in trn_rows
            ],
        }
    except Exception as e:
        logger.error("DCR ingestion stats failed: %s", e)
        return {"summary": {}, "by_table": [], "daily_trend": [], "error": str(e)}


@router.get("/errors")
async def get_dcr_errors(days: int = Query(30)):
    """DCR transformation errors and dropped events."""
    errors_q = f"""
    DCRLogErrors
    | where TimeGenerated > ago({days}d)
    | summarize
        Count    = count(),
        FirstSeen = min(TimeGenerated),
        LastSeen  = max(TimeGenerated)
      by DCRName, StreamName, ErrorCode, ErrorMessage
    | sort by Count desc
    | limit 30
    """
    diag_q = f"""
    AzureDiagnostics
    | where TimeGenerated > ago({days}d)
    | where ResourceType =~ "MICROSOFT.INSIGHTS/DATACOLLECTIONRULES"
    | summarize Count = count() by OperationName, ResultType, Resource
    | sort by Count desc
    | limit 20
    """
    trend_q = f"""
    DCRLogErrors
    | where TimeGenerated > ago({days}d)
    | summarize ErrorCount = count() by bin(TimeGenerated, 1d), DCRName
    | sort by TimeGenerated asc
    """
    try:
        errors, diag, trend = await asyncio.gather(
            run_kql(errors_q, days=days),
            run_kql(diag_q,   days=days),
            run_kql(trend_q,  days=days),
            return_exceptions=True,
        )
        err_rows  = errors.get("rows", []) if not isinstance(errors, Exception) else []
        diag_rows = diag.get("rows",   []) if not isinstance(diag,   Exception) else []
        trn_rows  = trend.get("rows",  []) if not isinstance(trend,  Exception) else []

        return {
            "errors": [
                {
                    "rule_name":  r.get("DCRName",    ""),
                    "stream":     r.get("StreamName",  ""),
                    "error_code": r.get("ErrorCode",   ""),
                    "message":    r.get("ErrorMessage",""),
                    "count":      r.get("Count", 0),
                    "first_seen": r.get("FirstSeen",   ""),
                    "last_seen":  r.get("LastSeen",    ""),
                }
                for r in err_rows
            ],
            "diagnostics": [
                {
                    "operation": r.get("OperationName", ""),
                    "result":    r.get("ResultType",    ""),
                    "resource":  r.get("Resource",      ""),
                    "count":     r.get("Count", 0),
                }
                for r in diag_rows
            ],
            "daily_trend": [
                {
                    "date":        r.get("TimeGenerated", "")[:10],
                    "rule":        r.get("DCRName",    ""),
                    "error_count": r.get("ErrorCount",  0),
                }
                for r in trn_rows
            ],
            "total_errors":   sum(r.get("Count", 0) for r in err_rows),
            "affected_rules": len({r.get("DCRName", "") for r in err_rows if r.get("DCRName")}),
        }
    except Exception as e:
        logger.error("DCR errors query failed: %s", e)
        return {"errors": [], "diagnostics": [], "daily_trend": [], "total_errors": 0, "affected_rules": 0, "error": str(e)}


@router.get("/activity")
async def get_dcr_activity(days: int = Query(30)):
    """DCR create/update/delete governance events from AzureActivity."""
    q = f"""
    AzureActivity
    | where TimeGenerated > ago({days}d)
    | where ResourceProviderValue =~ "MICROSOFT.INSIGHTS"
    | where OperationNameValue has_any ("DATACOLLECTIONRULE", "DATACOLLECTIONENDPOINT")
    | summarize
        Count    = count(),
        LastSeen = max(TimeGenerated)
      by OperationNameValue, Resource, ActivityStatusValue, Caller
    | sort by LastSeen desc
    | limit 50
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "activity": [
                {
                    "operation": r.get("OperationNameValue", ""),
                    "resource":  r.get("Resource",           ""),
                    "status":    r.get("ActivityStatusValue",""),
                    "caller":    r.get("Caller",             ""),
                    "count":     int(r.get("Count", 0)),
                    "last_seen": r.get("LastSeen",           ""),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("DCR activity query failed: %s", e)
        return {"activity": [], "error": str(e)}


@router.get("/overview")
async def get_dcr_overview(days: int = Query(30)):
    """High-level DCR health summary combining all sub-endpoints."""
    rules_d, ing_d, errors_d = await asyncio.gather(
        get_dcr_rules(),
        get_ingestion_stats(days=days),
        get_dcr_errors(days=days),
        return_exceptions=True,
    )
    rules_d  = rules_d  if not isinstance(rules_d,  Exception) else {}
    ing_d    = ing_d    if not isinstance(ing_d,    Exception) else {}
    errors_d = errors_d if not isinstance(errors_d, Exception) else {}
    ing_sum  = ing_d.get("summary", {})
    return {
        "dcr_total":              rules_d.get("total",               0),
        "dcr_succeeded":          rules_d.get("succeeded_count",     0),
        "dcr_failed":             rules_d.get("failed_count",        0),
        "dcr_with_transforms":    rules_d.get("with_transformations", 0),
        "dcr_custom_streams":     rules_d.get("with_custom_streams", 0),
        "total_data_flows":       rules_d.get("total_data_flows",    0),
        "total_transformations":  rules_d.get("total_transformations", 0),
        "ingestion_total_gb":     ing_sum.get("total_gb",            0),
        "ingestion_daily_avg_mb": ing_sum.get("daily_avg_mb",        0),
        "ingestion_tables":       ing_sum.get("table_count",         0),
        "estimated_monthly_gb":   ing_sum.get("estimated_monthly_gb", 0),
        "total_errors":           errors_d.get("total_errors",       0),
        "affected_rules":         errors_d.get("affected_rules",     0),
    }


# ── LLM Report ────────────────────────────────────────────────────────────────

@router.get("/report")
async def generate_dcr_report(days: int = Query(30)):
    """
    Generate a comprehensive LLM-powered DCR Assessment & Injection Optimization report.
    Gathers all DCR telemetry and uses the LLM to produce an expert-grade analysis.
    """
    top_tables_q = f"""
    Usage
    | where TimeGenerated > ago({days}d)
    | where IsBillable == true
    | summarize
        TotalMB    = round(sum(Quantity), 2),
        DaysActive = dcount(bin(TimeGenerated, 1d))
      by DataType
    | extend
        DailyAvgMB       = round(TotalMB / DaysActive, 2),
        EstCostUSD       = round(TotalMB / 1024 * 2.76, 2)
    | sort by TotalMB desc
    | limit 25
    """

    tasks = await asyncio.gather(
        get_dcr_rules(),
        get_ingestion_stats(days=days),
        get_dcr_errors(days=days),
        get_dcr_activity(days=days),
        run_kql(top_tables_q, days=days),
        return_exceptions=True,
    )

    rules_d    = tasks[0] if not isinstance(tasks[0], Exception) else {}
    ing_d      = tasks[1] if not isinstance(tasks[1], Exception) else {}
    errors_d   = tasks[2] if not isinstance(tasks[2], Exception) else {}
    activity_d = tasks[3] if not isinstance(tasks[3], Exception) else {}
    top_rows   = tasks[4].get("rows", []) if not isinstance(tasks[4], Exception) and isinstance(tasks[4], dict) else []

    rules       = rules_d.get("rules",        [])
    ing_sum     = ing_d.get("summary",         {})
    by_table    = ing_d.get("by_table",        [])
    daily_trend = ing_d.get("daily_trend",     [])
    errors      = errors_d.get("errors",       [])
    diag        = errors_d.get("diagnostics",  [])
    activity    = activity_d.get("activity",   [])

    with_transforms    = [r for r in rules if r["has_transformation"]]
    without_transforms = [r for r in rules if not r["has_transformation"]]
    failed_rules       = [r for r in rules if r["provisioning_state"] not in ("Succeeded", "")]
    stale_rules        = [r for r in rules if (r.get("days_since_modified") or 0) > 90]

    total_mb     = ing_sum.get("total_mb",    0)
    total_gb     = ing_sum.get("total_gb",    0)
    daily_avg_mb = ing_sum.get("daily_avg_mb", 0)
    monthly_gb   = ing_sum.get("estimated_monthly_gb", 0)
    est_cost     = round(monthly_gb * 2.76, 2)

    # ── Table builders ────────────────────────────────────────────────────────
    def _rule_row(r):
        td = r.get("days_since_modified", "?")
        return (
            f"| {r['name'][:45]} | {r['location']} | {r['provisioning_state']} "
            f"| {r['data_flows']} | {r['transformations']} | {r['custom_streams']} "
            f"| {'Yes' if r['has_transformation'] else 'No'} | {td} days |"
        )

    def _table_row(t):
        return (
            f"| {t['table'][:40]} | {t['total_mb']} MB "
            f"| {t['daily_avg']} MB/d | {t['pct']}% |"
        )

    def _top_row(r):
        est = round(r.get("TotalMB", 0) / 1024 * 2.76, 2)
        return (
            f"| {r.get('DataType','')[:40]} | {r.get('TotalMB', 0)} MB "
            f"| {r.get('DailyAvgMB', 0)} MB/d | ${est} |"
        )

    def _err_row(e):
        return (
            f"| {e['rule_name'][:35]} | {e['stream'][:25]} | {e['error_code']} "
            f"| {str(e['message'])[:60]} | {e['count']} |"
        )

    def _act_row(a):
        op = a["operation"].split("/")[-1][:35]
        return f"| {op} | {a['resource'][:35]} | {a['status']} | {a['caller'][:25]} | {a['count']} |"

    rule_hdr = (
        "| DCR Name | Location | State | Flows | Transforms | Custom Streams | KQL Transform | Days Since Modified |\n"
        "|----------|----------|-------|-------|------------|----------------|---------------|---------------------|"
    )
    rule_rows_str = "\n".join(_rule_row(r) for r in rules[:30]) or "  No DCRs found"

    tbl_hdr = (
        "| Table | Total Volume | Daily Avg | % of Total |\n"
        "|-------|-------------|-----------|------------|"
    )
    tbl_rows_str = "\n".join(_table_row(t) for t in by_table[:20]) or "  No ingestion data"

    top_hdr = (
        "| Table | Total Volume | Daily Avg | Est. Cost (period) |\n"
        "|-------|-------------|-----------|-------------------|"
    )
    top_rows_str = "\n".join(_top_row(r) for r in top_rows[:15]) or "  No data"

    err_hdr = (
        "| DCR Rule | Stream | Error Code | Error Message | Count |\n"
        "|----------|--------|------------|---------------|-------|"
    )
    err_rows_str = "\n".join(_err_row(e) for e in errors[:15]) or "  No errors recorded"

    act_hdr = (
        "| Operation | Resource | Status | Caller | Count |\n"
        "|-----------|----------|--------|--------|-------|"
    )
    act_rows_str = "\n".join(_act_row(a) for a in activity[:15]) or "  No DCR activity"

    trend_str = " → ".join(
        f"{d['date']}: {d['total_mb']} MB"
        for d in daily_trend[-7:]
    ) or "No trend data"

    context = f"""SENTINEL DCR (DATA COLLECTION RULES) ASSESSMENT & INJECTION OPTIMIZATION — Last {days} days
========================================================================================

## 1. Global Overview
- Total DCRs in subscription:          {rules_d.get('total', 0)}
- Successfully provisioned:            {rules_d.get('succeeded_count', 0)}
- Failed / Error state:                {rules_d.get('failed_count', 0)}
- DCRs WITH KQL transformations:       {len(with_transforms)}
- DCRs WITHOUT any transformation:     {len(without_transforms)}
- DCRs with custom stream declarations:{rules_d.get('with_custom_streams', 0)}
- Total data flows across all DCRs:    {rules_d.get('total_data_flows', 0)}
- Total transformation rules:          {rules_d.get('total_transformations', 0)}
- Stale DCRs (90+ days not modified):  {len(stale_rules)}

## 2. Ingestion Volume Summary
- Total ingestion (period):   {total_gb} GB ({total_mb} MB)
- Daily average:              {daily_avg_mb} MB/day
- Active billable tables:     {ing_sum.get('table_count', 0)}
- Estimated monthly:          {monthly_gb} GB/month
- Estimated monthly cost:     ${est_cost} (at $2.76/GB Sentinel pay-as-you-go)

## 3. Ingestion Trend (last 7 days of period)
{trend_str}

## 4. DCR Inventory (All {len(rules)} DCRs)
{rule_hdr}
{rule_rows_str}

### DCRs WITHOUT transformations (cost & quality risk):
{chr(10).join(f"  - {r['name']} | {r['data_flows']} flows | Streams: {r['custom_streams']} | Last modified: {(r.get('last_modified') or '')[:10] or 'Unknown'}" for r in without_transforms[:20]) or "  None — all DCRs use KQL transformations"}

### DCRs in FAILED / non-Succeeded state:
{chr(10).join(f"  - {r['name']} | State: {r['provisioning_state']} | Location: {r['location']}" for r in failed_rules) or "  None — all DCRs are healthy"}

### Stale DCRs (90+ days without modification):
{chr(10).join(f"  - {r['name']} | Last modified: {(r.get('last_modified') or '')[:10] or 'Unknown'} ({r.get('days_since_modified', '?')} days ago)" for r in stale_rules[:10]) or "  None — all DCRs recently modified"}

## 5. Cost Analysis — Top Tables by Estimated Spend
{top_hdr}
{top_rows_str}

## 6. Full Ingestion Breakdown by Table
{tbl_hdr}
{tbl_rows_str}

## 7. DCR Errors & Dropped Events
- Total error events:   {errors_d.get('total_errors', 0)}
- Affected DCR rules:   {errors_d.get('affected_rules', 0)}

{err_hdr}
{err_rows_str}

### AzureDiagnostics DCR events:
{chr(10).join(f"  - {d['operation'].split('/')[-1]}: {d['result']} | {d['resource'][:40]} | Count: {d['count']}" for d in diag[:10]) or "  No diagnostic events"}

## 8. DCR Governance Activity (last {days} days)
{act_hdr}
{act_rows_str}

## 9. Transformation Coverage Detail
### WITH transformation:
{chr(10).join(f"  + {r['name']}: {r['transformations']} transform(s) | {r['data_flows']} flow(s)" for r in with_transforms[:15]) or "  None"}

### WITHOUT transformation:
{chr(10).join(f"  - {r['name']}: {r['data_flows']} flow(s) | {r['custom_streams']} custom streams" for r in without_transforms[:15]) or "  None"}
"""

    system_prompt = """You are a Microsoft Sentinel and Azure Monitor expert specialising in Data Collection Rules (DCR), \
log ingestion pipelines, transformation KQL, and cost optimisation.
Analyse the DCR telemetry provided and produce a comprehensive, actionable assessment report.

Your report MUST include ALL of the following sections with proper markdown headings (## for main, ### for sub):

## Executive Summary
3-4 sentences covering: overall DCR health and coverage, ingestion efficiency, the single most critical \
problem, and the highest-value optimisation opportunity. Include:
- DCR health score out of 10
- Ingestion efficiency rating: Unoptimised / Basic / Optimised / Expert

## DCR Inventory Assessment
For EACH DCR in the inventory:
- Provisioning state and health assessment
- Whether it uses KQL transformations and the significance of that fact
- What data sources it likely covers based on the name and configuration
- Risk assessment for DCRs WITHOUT transformations (data quality, cost risk)
- Flag any DCRs that are failed, stale, or suspicious
Present as a full markdown table with a health column.

## Transformation Coverage Analysis
- What percentage of DCRs use KQL transformations?
- For DCRs WITHOUT transformations: identify the specific security and cost risks per DCR
  - Are raw unfiltered logs being ingested (potential massive cost)?
  - Are enrichment fields missing (reduced detection fidelity)?
  - Estimated volume reduction potential if filtering is added
- For DCRs WITH transformations: assess transformation quality
- Provide a transformation coverage score out of 10

## Ingestion Volume & Cost Analysis
- Total and daily average ingestion with trend analysis
- For each of the top 10 tables: is this volume expected? Is there over-ingestion risk?
- Identify tables that are strong candidates for filtering via DCR transformations
- For the top 3 over-ingesting tables: provide specific KQL transformation snippets \
  that could reduce ingestion by filtering noise (include actual KQL code in code blocks)
- Cost optimisation potential: estimated monthly savings from adding/improving transformations

## Error Analysis & Pipeline Health
- Analyse all DCR errors and diagnose root cause for each error type
- Classify errors: transformation syntax | permission/auth | destination | schema mismatch
- For each error pattern: specific remediation steps with KQL examples where relevant
- Estimate how many events are being dropped or corrupted
- Pipeline health score per affected DCR

## Injection Optimisation Recommendations
Provide exactly 10 specific, actionable KQL transformation recommendations. For each:
- **Target DCR / Table**: Which DCR and destination table
- **Problem**: What is currently happening (over-ingestion, missing enrichment, quality issue)
- **KQL Transform**: Provide the actual KQL transformation code in a code block
- **Expected Impact**: Estimated volume reduction % or enrichment improvement
- **Priority**: Critical / High / Medium
- **Est. Cost Saving**: Monthly GB reduction and dollar saving at $2.76/GB

## DCR Coverage Gaps
- What data sources should have DCRs but do not appear to?
- Which Sentinel data connectors are likely NOT using DCR-based collection?
- Security data types lacking proper DCR coverage (detection blind spots)
- Recommended new DCRs to create with configuration specs

## Governance & Lifecycle Recommendations
Numbered action list covering:
1. Which stale DCRs need review or retirement (with names and urgency)
2. Change management assessment based on the activity data
3. Naming convention analysis and recommendations
4. Which DCRs should be split or consolidated
5. Recommended review cadence per criticality tier
6. How to track DCR coverage as a SOC KPI

Be precise and evidence-based. Every finding must reference specific DCR names and numbers from the telemetry. \
Include actual KQL code snippets for transformation recommendations. \
Do NOT include generic advice — everything must be grounded in this workspace's actual data."""

    token_usage: dict = {}
    try:
        result       = await llm_service.complete(system_prompt, context)
        llm_analysis = result["text"]
        token_usage  = result["usage"]
    except Exception as e:
        logger.error("DCR LLM report generation failed: %s", e)
        llm_analysis = f"LLM analysis unavailable: {e}"

    return {
        "days":        days,
        "raw_data": {
            "rules":    rules_d,
            "ingestion": ing_d,
            "errors":   errors_d,
            "activity": activity_d,
        },
        "llm_analysis": llm_analysis,
        "token_usage":  token_usage,
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
