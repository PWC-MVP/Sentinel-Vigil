"""
Sentinel Workbook Coverage router.

GET /api/workbooks/coverage  → coverage matrix + summary (main endpoint)
GET /api/workbooks/list      → raw list of all deployed workbooks
GET /api/workbooks/activity  → recent workbook ops from AzureActivity KQL
GET /api/workbooks/report    → LLM-powered comprehensive workbook analysis
"""
import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Query

from backend.services.sentinel import call_azure_mgmt_api_async, run_kql
from backend.services import llm as llm_service
from backend.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/workbooks", tags=["workbooks"])


# ── Category inference ────────────────────────────────────────────────────────

_CATEGORY_RULES: list[tuple[list[str], str]] = [
    (["identity", "azure ad", "sign-in", "signin", "aad", "entra",
      "authentication", "mfa", "privileged identity", "pim", "access review"],
     "Identity & Access"),
    (["threat intel", "threat intelligence", "ioc", "indicator of compromise",
      "timap", "tiworking", "ti "],
     "Threat Intelligence"),
    (["network", "firewall", "nsg flow", "traffic analytics", "dns",
      "proxy", "perimeter", "palo alto", "fortinet", "checkpoint"],
     "Network & Traffic"),
    (["endpoint", "defender", "mde", "mdatp", "antivirus", "edr",
      "device compliance", "microsoft defender for endpoint"],
     "Endpoint Security"),
    (["office 365", "o365", "m365", "exchange", "teams", "sharepoint",
      "onedrive", "dlp", "email protection", "mail"],
     "Microsoft 365"),
    (["ueba", "user behavior", "entity behavior", "entity exposure",
      "insider risk", "anomaly"],
     "UEBA"),
    (["azure activity", "cloud app", "storage account", "key vault",
      "resource", "subscription", "management group", "azure defender",
      "microsoft defender for cloud"],
     "Cloud Resources"),
    (["compliance", "regulatory", "gdpr", "nist", "cis", "audit",
      "policy", "benchmark"],
     "Compliance"),
    (["sentinel overview", "security operations", "workspace usage",
      "soc overview", "incident overview", "alert overview"],
     "Security Operations"),
    (["hunt", "investigation", "forensic", "threat hunting"],
     "Threat Hunting"),
    (["sap", "s/4hana", "sap hana"],                            "SAP"),
    (["github", "devops", "azure devops", "ci/cd", "jenkins"],  "DevSecOps"),
]

# Categories that every Sentinel deployment should ideally have
_EXPECTED: list[tuple[str, str, str]] = [
    ("Identity & Access",   "Critical", "Deploy Entra ID / Azure AD Sign-in & Audit Logs workbooks"),
    ("Security Operations", "Critical", "Deploy the Sentinel Overview or SOC Operations workbook"),
    ("Threat Intelligence", "High",     "Deploy the Threat Intelligence workbook to visualise IOC coverage"),
    ("Network & Traffic",   "High",     "Deploy Azure Firewall / NSG Flow Logs / Traffic Analytics workbooks"),
    ("Endpoint Security",   "High",     "Deploy Microsoft Defender for Endpoint workbook"),
    ("Microsoft 365",       "Medium",   "Deploy the Microsoft 365 / Exchange Online Protection workbook"),
    ("UEBA",                "Medium",   "Deploy the User & Entity Behaviour Analytics workbook"),
    ("Cloud Resources",     "Medium",   "Deploy the Azure Activity / Microsoft Defender for Cloud workbook"),
]

_PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _infer_category(display_name: str, template_id: str = "") -> str:
    text = f"{display_name} {template_id}".lower()
    for keywords, category in _CATEGORY_RULES:
        if any(kw in text for kw in keywords):
            return category
    return "General"


def _days_since(iso_str: str) -> int | None:
    if not iso_str:
        return None
    try:
        ts = iso_str.rstrip("Z")
        # Handle both "2024-01-15T10:23:00" and "2024-01-15T10:23:00.000000"
        dt = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


def _parse_workbooks(raw: list) -> list[dict]:
    workbooks = []
    for w in raw:
        props = w.get("properties", {})
        name  = props.get("displayName") or w.get("name", "")
        tid   = props.get("fromTemplateId", "") or ""
        lm    = props.get("timeModified", "") or props.get("timeCreated", "") or ""
        days  = _days_since(lm)
        workbooks.append({
            "id":                   w.get("name", ""),
            "name":                 name,
            "description":          (props.get("description", "") or "")[:250],
            "category":             _infer_category(name, tid),
            "kind":                 w.get("kind", "shared"),
            "version":              props.get("version", "") or "",
            "template_id":          tid,
            "last_modified":        lm,
            "days_since_modified":  days,
            "stale":                (days is not None and days > 90),
            "location":             w.get("location", ""),
        })
    workbooks.sort(key=lambda x: (x["category"], x["name"].lower()))
    return workbooks


# ── Endpoints ─────────────────────────────────────────────────────────────────

def _is_403(exc: Exception) -> bool:
    s = str(exc)
    return "403" in s or "Forbidden" in s or "AuthorizationFailed" in s


def _permission_error_msg(rg: str) -> str:
    return (
        "403 Forbidden: The service principal lacks 'Microsoft.Insights/workbooks/read' permission. "
        "To fix: open Azure Portal → Resource Group '{rg}' → Access Control (IAM) → Add role assignment → "
        "assign 'Monitoring Reader' (or 'Reader') to the service principal used by this application."
    ).format(rg=rg)


async def _fetch_workbooks(sub: str, rg: str) -> list:
    """Try subscription-scope first, fall back to RG-scope. Raises PermissionError on 403 from both."""
    paths = [
        f"/subscriptions/{sub}/providers/Microsoft.Insights/workbooks",
        f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/workbooks",
    ]
    last_exc: Exception | None = None
    for path in paths:
        try:
            data = await call_azure_mgmt_api_async(
                path, api_version="2022-04-01",
                params={"category": "sentinel"},
            )
            return data.get("value", [])
        except Exception as e:
            if _is_403(e):
                last_exc = e
                continue
            raise
    raise PermissionError(_permission_error_msg(rg)) from last_exc


@router.get("/list")
async def list_workbooks():
    """Fetch every Sentinel workbook deployed in the configured workspace resource group."""
    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    if not sub or not rg:
        return {"workbooks": [], "error": "Missing subscription_id or resource_group in config.json"}
    try:
        raw = await _fetch_workbooks(sub, rg)
        return {"workbooks": _parse_workbooks(raw)}
    except PermissionError as e:
        logger.warning("Workbooks list 403: %s", e)
        return {"workbooks": [], "error": str(e)}
    except Exception as e:
        logger.error("Workbooks list failed: %s", e)
        return {"workbooks": [], "error": str(e)}


@router.get("/coverage")
async def get_workbook_coverage():
    """
    Full coverage assessment: expected categories vs deployed workbooks,
    stale workbook detection, and a per-category breakdown.
    """
    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    if not sub or not rg:
        return {
            "summary": {}, "coverage_matrix": [], "extra_categories": [],
            "all_workbooks": [], "by_category": {},
            "error": "Missing subscription_id or resource_group in config.json",
        }

    try:
        raw = await _fetch_workbooks(sub, rg)
        workbooks = _parse_workbooks(raw)
    except PermissionError as e:
        logger.warning("Workbooks coverage 403: %s", e)
        return {
            "summary": {}, "coverage_matrix": [], "extra_categories": [],
            "all_workbooks": [], "by_category": {}, "error": str(e),
        }
    except Exception as e:
        logger.error("Workbooks coverage fetch failed: %s", e)
        return {
            "summary": {}, "coverage_matrix": [], "extra_categories": [],
            "all_workbooks": [], "by_category": {}, "error": str(e),
        }

    # Group by inferred category
    by_cat: dict[str, list] = defaultdict(list)
    for w in workbooks:
        by_cat[w["category"]].append(w)

    # Build the coverage matrix for expected categories
    covered_expected = sum(1 for cat, _, _ in _EXPECTED if cat in by_cat)
    total_expected   = len(_EXPECTED)
    coverage_pct     = round(100.0 * covered_expected / total_expected, 1) if total_expected else 0.0

    matrix = []
    for cat, priority, remediation in _EXPECTED:
        wbs = by_cat.get(cat, [])
        matrix.append({
            "category":     cat,
            "priority":     priority,
            "covered":      len(wbs) > 0,
            "count":        len(wbs),
            "stale_count":  sum(1 for w in wbs if w["stale"]),
            "remediation":  remediation,
            "workbooks": [
                {
                    "name":          w["name"],
                    "last_modified": w["last_modified"],
                    "days_since_modified": w["days_since_modified"],
                    "stale":         w["stale"],
                    "kind":          w["kind"],
                }
                for w in wbs
            ],
        })

    # Categories that are deployed but NOT in the expected list
    expected_cats = {cat for cat, _, _ in _EXPECTED}
    extra = [
        {"category": cat, "count": len(wbs), "workbooks": [w["name"] for w in wbs]}
        for cat, wbs in sorted(by_cat.items())
        if cat not in expected_cats
    ]

    # Recent modifications (last 30 days)
    recent = [w for w in workbooks if w["days_since_modified"] is not None and w["days_since_modified"] <= 30]

    return {
        "summary": {
            "total_workbooks":    len(workbooks),
            "total_categories":   len(by_cat),
            "covered_expected":   covered_expected,
            "total_expected":     total_expected,
            "coverage_pct":       coverage_pct,
            "stale_count":        sum(1 for w in workbooks if w["stale"]),
            "recent_count":       len(recent),
            "shared_count":       sum(1 for w in workbooks if w["kind"] == "shared"),
        },
        "coverage_matrix":  matrix,
        "extra_categories": extra,
        "by_category":      {
            cat: [{"name": w["name"], "stale": w["stale"], "last_modified": w["last_modified"]} for w in wbs]
            for cat, wbs in sorted(by_cat.items())
        },
        "all_workbooks":    workbooks,
    }


@router.get("/activity")
async def get_workbook_activity(days: int = Query(30)):
    """Recent workbook create / update / delete events from AzureActivity."""
    q = f"""
    AzureActivity
    | where TimeGenerated > ago({days}d)
    | where ResourceProviderValue =~ "MICROSOFT.INSIGHTS"
    | where OperationNameValue has "WORKBOOK"
    | summarize
        Count    = count(),
        LastSeen = max(TimeGenerated)
      by OperationNameValue, Resource, ActivityStatusValue, Caller
    | sort by LastSeen desc
    | limit 60
    """
    try:
        rows = (await run_kql(q, days=days)).get("rows", [])
        return {
            "activity": [
                {
                    "operation": r.get("OperationNameValue", ""),
                    "resource":  r.get("Resource", ""),
                    "status":    r.get("ActivityStatusValue", ""),
                    "caller":    r.get("Caller", ""),
                    "count":     int(r.get("Count", 0)),
                    "last_seen": r.get("LastSeen", ""),
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error("Workbook activity query failed: %s", e)
        return {"activity": [], "error": str(e)}


# ── LLM Report ────────────────────────────────────────────────────────────────

@router.get("/report")
async def generate_workbook_report(days: int = Query(30)):
    """
    Generate a comprehensive LLM-powered Workbook Coverage report.
    Gathers coverage matrix, all workbook metadata, and recent activity,
    then uses the LLM to produce an analysis with gap remediation and recommendations.
    """
    # ── Gather data in parallel ───────────────────────────────────
    coverage_data, activity_data = await asyncio.gather(
        get_workbook_coverage(),
        get_workbook_activity(days=days),
    )

    summary    = coverage_data.get("summary", {})
    matrix     = coverage_data.get("coverage_matrix", [])
    extras     = coverage_data.get("extra_categories", [])
    all_wbs    = coverage_data.get("all_workbooks", [])
    by_cat     = coverage_data.get("by_category", {})
    activity   = activity_data.get("activity", [])

    covered   = [e for e in matrix if e["covered"]]
    gaps      = [e for e in matrix if not e["covered"]]
    stale_wbs = [w for w in all_wbs if w.get("stale")]

    # ── Table builders ───────────────────────────────────────────
    def _stale_risk(category: str) -> str:
        if category in ("Identity & Access", "Security Operations"):
            return "CRITICAL"
        if category in ("Endpoint Security", "Threat Intelligence", "Network & Traffic"):
            return "High"
        return "Medium"

    matrix_hdr = ("| Category | Priority | Status | Workbooks | Stale | Remediation |\n"
                  "|----------|----------|--------|-----------|-------|-------------|")
    matrix_rows = "\n".join(
        f"| {e['category']} | {e['priority']} | {'✔ Covered' if e['covered'] else '✘ MISSING'} "
        f"| {e['count']} | {e['stale_count']} | {e['remediation'] if not e['covered'] else '—'} |"
        for e in matrix
    )

    wb_hdr = ("| Name | Category | Last Modified | Days Since | Stale | Kind |\n"
              "|------|----------|---------------|------------|-------|------|")
    wb_rows = "\n".join(
        f"| {w['name'][:50]} | {w['category']} | {(w['last_modified'] or '')[:10] or 'Unknown'} "
        f"| {w.get('days_since_modified', '?')} | {'YES' if w.get('stale') else 'No'} | {w['kind']} |"
        for w in all_wbs[:50]
    ) or "  No workbooks deployed"

    stale_hdr = ("| Name | Category | Days Since Modified | Stale Risk |\n"
                 "|------|----------|---------------------|------------|")
    stale_rows = "\n".join(
        f"| {w['name'][:50]} | {w['category']} | {w['days_since_modified']} days | {_stale_risk(w['category'])} |"
        for w in stale_wbs
    ) or "  None"

    activity_hdr = ("| Operation | Resource | Status | Caller | Count |\n"
                    "|-----------|----------|--------|--------|-------|")
    activity_rows = "\n".join(
        f"| {a['operation'].split('/')[-1][:40]} | {a['resource'][:40]} | {a['status']} "
        f"| {a['caller'][:30]} | {a['count']} |"
        for a in activity[:20]
    ) or "  No workbook activity recorded"

    gaps_sorted = sorted(gaps, key=lambda x: _PRIORITY_ORDER.get(x["priority"], 99))

    context = f"""SENTINEL WORKBOOK COVERAGE TELEMETRY — Last {days} days
========================================================

## 1. Summary Statistics
- Total workbooks deployed: {summary.get('total_workbooks', 0)}
- Coverage score: {summary.get('coverage_pct', 0)}% ({summary.get('covered_expected', 0)} / {summary.get('total_expected', 0)} expected security domains)
- Coverage gaps (missing expected domains): {len(gaps)}
- Covered expected domains: {len(covered)}
- Stale workbooks (>90 days without modification): {summary.get('stale_count', 0)}
- Recently modified (last 30d): {summary.get('recent_count', 0)}
- Shared workbooks: {summary.get('shared_count', 0)}
- Total distinct categories deployed: {summary.get('total_categories', 0)}

## 2. Full Coverage Matrix
{matrix_hdr}
{matrix_rows}

### Missing Domains — Priority Ordered:
{chr(10).join(f"  [{g['priority']}] {g['category']}: {g['remediation']}" for g in gaps_sorted) or "  None — all expected domains are covered"}

### Covered Domains with workbook details:
{chr(10).join(f"  [{e['priority']}] {e['category']}: {e['count']} workbook(s){(', ' + str(e['stale_count']) + ' STALE') if e['stale_count'] else ''} — {', '.join(w['name'] for w in e.get('workbooks', [])[:3])}" for e in covered) or "  None"}

## 3. Full Workbook Inventory ({len(all_wbs)} workbooks)
{wb_hdr}
{wb_rows}

## 4. Stale Workbooks Detail ({len(stale_wbs)} workbooks older than 90 days)
{stale_hdr}
{stale_rows}

## 5. Additional Deployed Categories (beyond expected baseline)
{chr(10).join(f"  + {e['category']}: {e['count']} workbook(s) — {', '.join(e['workbooks'][:5])}" for e in extras) or "  None — deployment matches expected baseline"}

## 6. Category Breakdown (deployed workbooks per category)
{chr(10).join(f"  [{cat}]: {len(wbs)} workbook(s) — {', '.join(w['name'] for w in wbs[:4])}" for cat, wbs in sorted(by_cat.items()) if wbs) or "  No data"}

## 7. Recent Workbook Activity (last {days} days)
{activity_hdr}
{activity_rows}
"""

    system_prompt = """You are a Microsoft Sentinel SOC architect specialising in workbook governance, visibility coverage, and detection engineering.
Analyse the workbook coverage telemetry provided and produce a comprehensive, detailed assessment report.

Your report MUST include ALL of the following sections with proper markdown headings (## for main, ### for sub):

## Executive Summary
3-4 sentences covering: overall workbook health, visibility maturity level, the most critical gap, and the most urgent stale workbook risk. Include:
- Coverage rating: Poor (<50%) / Fair (50-74%) / Good (75-89%) / Excellent (≥90%)
- A visibility health score out of 10

## Coverage Gap Analysis
For EACH missing expected security domain (in priority order):
- The exact security blind spot it creates — what threats, attack techniques, or behaviours become invisible
- The specific Microsoft Sentinel gallery workbook(s) to deploy (use exact gallery names)
- Required data connector prerequisites
- Estimated deployment effort (< 1 hour / half-day / full day)
- Risk if left unaddressed

Present as a markdown table: Domain | Security Blind Spot | Recommended Workbook | Prerequisites | Effort | Priority

## Stale Workbook Risk Assessment
For each stale workbook (>90 days since last modification):
- Is the underlying data connector still active? (infer from category)
- Does the workbook still reflect current threat landscape?
- Risk of operating on outdated visualizations in an incident response scenario
- Recommended action: Refresh / Replace with newer gallery version / Retire
- If covering a critical security domain (Identity, SOC, Endpoint): flag as HIGH RISK

Present as a markdown table: Workbook | Category | Age (days) | Risk Level | Recommended Action | Justification

## Workbook Health by Category
For EACH category (covered or missing):
- Status: Covered / Gap
- Count: number deployed (0 = critical blind spot; >3 = possible redundancy/overlap)
- Staleness: any stale workbooks in this category
- Specific health observations and actions

## Deployment & Governance Activity Analysis
Based on the AzureActivity data:
- Who is creating / modifying / deleting workbooks?
- Are there any signs of ad-hoc changes without governance?
- Any deletion events that should be investigated?
- Workbooks with no activity (potentially unused despite being deployed)
- Recommended governance process improvements

## Recommendations: New Workbooks to Deploy
Provide exactly 10 specific, actionable recommendations. For each:
- **Name**: Exact Microsoft Sentinel gallery workbook name
- **Category**: Security domain
- **Priority**: Critical / High / Medium
- **Visibility Gap**: What is currently invisible that this workbook makes visible
- **Prerequisites**: Required data connectors and tables (exact table names if known)
- **Rationale**: Reference specific telemetry numbers justifying this recommendation

## Maintenance & Governance Action Plan
Numbered action list covering:
1. Which stale workbooks to refresh first (with specific names and urgency)
2. Which workbooks to consolidate (where redundancy is detected)
3. Which workbooks to archive or retire
4. Recommended workbook review cadence per priority tier
5. Naming convention and ownership governance recommendations
6. How to track workbook coverage as a KPI in the SOC

Be precise and evidence-based. Every finding must reference specific data from the telemetry. Use markdown tables for all comparisons. Do NOT include generic advice — everything must be grounded in this workspace's actual data."""

    token_usage: dict = {}
    try:
        result       = await llm_service.complete(system_prompt, context)
        llm_analysis = result["text"]
        token_usage  = result["usage"]
    except Exception as e:
        logger.exception("Workbook LLM report generation failed")
        llm_analysis = f"LLM analysis unavailable — {type(e).__name__}: {e}"

    return {
        "days":         days,
        "raw_data":     {
            "summary":   summary,
            "matrix":    matrix,
            "extras":    extras,
            "workbooks": all_wbs,
            "activity":  activity,
        },
        "llm_analysis": llm_analysis,
        "token_usage":  token_usage,
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
