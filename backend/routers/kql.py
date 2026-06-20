"""KQL Explorer / Log Parser API router."""
import asyncio
import json as _json
import logging
import re

_log = logging.getLogger(__name__)

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.services import sentinel as sentinel_svc
from backend.services.llm import complete as _llm_complete, get_llm_status
from backend.config import settings

router = APIRouter(prefix="/api/kql", tags=["kql"])

MAX_SMART_RETRIES = 4

_KQL_FIX_SYSTEM = (
    "You are an expert Microsoft Sentinel / Azure Log Analytics KQL engineer.\n"
    "A KQL query has failed with an error. Diagnose the root cause and produce a corrected query.\n\n"
    "CRITICAL: Reply ONLY with a valid JSON object — no markdown, no code fences, nothing else:\n"
    '{"query": "<corrected KQL with \\n between each pipe operator>", '
    '"explanation": "<one sentence: what was wrong and what you fixed>"}\n\n'
    "Common fixes by error code:\n"
    "- SEM0040 in() cast failure: replace in(list) with in~ or has_any() for strings, "
    "or use dynamic([...]) for scalar lists\n"
    "- SEM0100 type mismatch: wrap values with tostring(), toint(), todouble(), tolong()\n"
    "- Unknown column: verify column name against the Sentinel table schema\n"
    "- Parse errors: ensure all string literals are quoted, operators are valid KQL\n"
    "- Aggregate after aggregate: use subqueries or materialize()\n"
    "- The query JSON value must use \\n for newlines so it is valid JSON"
)


class KQLRequest(BaseModel):
    query: str
    workspace_id: str | None = None
    days: int = 30


class KQLGenerateRequest(BaseModel):
    prompt: str
    days: int = 30


class SmartRunRequest(BaseModel):
    query: str
    prompt: str = ""
    days: int = 30


def _sse(obj: dict) -> str:
    return f"data: {_json.dumps(obj)}\n\n"


def _parse_llm_json(text: str) -> dict:
    """Strip code fences and parse JSON from LLM response."""
    s = text.strip()
    for fence in ("```json", "```"):
        if s.startswith(fence):
            s = s[len(fence):]
    if s.endswith("```"):
        s = s[:-3]
    return _json.loads(s.strip())


def _extract_fix_from_response(text: str) -> tuple[str, str]:
    """
    Robustly extract (query, explanation) from a fix response.
    Handles: valid JSON, partial JSON, or bare KQL text returned by the LLM.
    Returns ("", "") on complete failure so the caller can retry.
    """
    if not text or not text.strip():
        return "", ""
    try:
        obj = _parse_llm_json(text)
        return obj.get("query", "").replace("\\n", "\n").strip(), obj.get("explanation", "fixed")
    except Exception:
        pass
    # Fallback: try to find a JSON object anywhere in the text
    try:
        start = text.index("{")
        end   = text.rindex("}") + 1
        obj   = _json.loads(text[start:end])
        return obj.get("query", "").replace("\\n", "\n").strip(), obj.get("explanation", "fixed")
    except Exception:
        pass
    # Last resort: if the text looks like KQL (starts with a table name / pipe), treat it as the query
    stripped = text.strip()
    if stripped and not stripped.startswith("{"):
        return stripped, "Query returned as plain text"
    return "", ""


@router.post("/generate")
async def generate_kql_from_prompt(req: KQLGenerateRequest):
    """Use LLM to generate a KQL query from a natural language description."""
    status = get_llm_status()
    if not status.get("available"):
        raise HTTPException(
            status_code=503,
            detail="LLM not configured — add AZURE_ANTHROPIC_API_KEY / AZURE_OPENAI_API_KEY to .env",
        )

    kql_system = (
        "You are an expert Microsoft Sentinel / Azure Log Analytics KQL engineer for a SOC team.\n"
        "Given a natural language security question, produce a precise, ready-to-run KQL query.\n\n"
        "CRITICAL: Reply ONLY with a valid JSON object — no markdown, no code fences, nothing else:\n"
        '{"query": "<full KQL query with \\n between each pipe operator>", '
        '"explanation": "<1-2 sentences on what the query does and what it returns>"}\n\n'
        "KQL rules:\n"
        f"- Default time window: ago({req.days}d) unless the user specifies otherwise\n"
        "- Use correct Microsoft Sentinel table names: SecurityAlert, SecurityIncident, SigninLogs,\n"
        "  AuditLogs, OfficeActivity, CloudAppEvents, DeviceEvents, BehaviorAnalytics,\n"
        "  ThreatIntelligenceIndicator, IdentityInfo, Syslog, WindowsEvent, CommonSecurityLog,\n"
        "  AzureActivity, AzureDiagnostics, MicrosoftGraphActivityLogs, IdentityLogonEvents\n"
        "- Each pipe operator on its own line\n"
        "- Append | take 500 at the end if the query does not use summarize\n"
        "- Prefer readability — use let statements for complex sub-expressions\n"
        "- The query JSON value must use \\n for newlines so it is valid JSON"
    )

    try:
        result = await _llm_complete(kql_system, req.prompt)
        raw = result["text"]
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM generation failed: {e}")

    try:
        obj = _parse_llm_json(raw)
        return {"query": obj.get("query", "").replace("\\n", "\n"), "explanation": obj.get("explanation", "")}
    except Exception:
        return {"query": raw.strip(), "explanation": ""}


@router.post("/smart-run")
async def smart_run_kql(req: SmartRunRequest):
    """Run KQL with automatic LLM-powered retry on semantic errors. Streams SSE log events."""

    async def event_gen():
        query = req.query

        yield _sse({"type": "log", "level": "info", "msg": "Smart query engine initialised"})
        await asyncio.sleep(0.04)

        for attempt in range(1, MAX_SMART_RETRIES + 1):
            yield _sse({"type": "log", "level": "info",
                        "msg": f"Attempt {attempt} of {MAX_SMART_RETRIES} — executing against Sentinel…"})
            yield _sse({"type": "query", "query": query, "attempt": attempt})
            await asyncio.sleep(0.04)

            try:
                result = await sentinel_svc.run_kql(query, None, req.days)
                row_count = result.get("row_count", 0)
                yield _sse({"type": "log", "level": "success",
                            "msg": f"Query succeeded — {row_count} row(s) returned"})
                yield _sse({"type": "result", "data": result})
                yield _sse({"type": "done", "success": True})
                return

            except (RuntimeError, ValueError) as e:
                error_str = str(e)
                short_err = error_str[:350] if len(error_str) > 350 else error_str
                yield _sse({"type": "log", "level": "warn", "msg": f"Execution failed: {short_err}"})

                if attempt >= MAX_SMART_RETRIES:
                    yield _sse({"type": "log", "level": "error",
                                "msg": "Maximum retries reached — could not produce a valid query"})
                    yield _sse({"type": "done", "success": False, "error": error_str})
                    return

                yield _sse({"type": "log", "level": "ai",
                            "msg": "Consulting AI to diagnose and fix the query…"})
                await asyncio.sleep(0.04)

                fix_prompt = (
                    f"Fix the following KQL query that failed with an error.\n\n"
                    f"FAILED QUERY:\n{query}\n\n"
                    f"ERROR:\n{error_str}\n\n"
                    f"User's original intent: {req.prompt or 'Not provided'}"
                )

                try:
                    fix_result = await _llm_complete(_KQL_FIX_SYSTEM, fix_prompt)
                    new_query, fix_note = _extract_fix_from_response(fix_result["text"])

                    if not new_query or new_query == query:
                        yield _sse({"type": "log", "level": "warn",
                                    "msg": "AI returned an unchanged query — retrying as-is"})
                    else:
                        yield _sse({"type": "log", "level": "ai", "msg": f"Fix applied: {fix_note}"})
                        query = new_query

                except Exception as llm_err:
                    yield _sse({"type": "log", "level": "warn",
                                "msg": f"AI fix request failed: {llm_err} — retrying"})
                    # don't abort — let the loop retry with the original query

        yield _sse({"type": "done", "success": False, "error": "Max retries exceeded"})

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("")
async def run_kql(req: KQLRequest):
    """Execute a KQL query against the configured Sentinel workspace."""
    try:
        result = await sentinel_svc.run_kql(req.query, req.workspace_id, req.days)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/workspaces")
async def list_workspaces():
    """List configured Sentinel workspaces."""
    return {"workspaces": await sentinel_svc.list_workspaces()}


# ── Log Parser endpoints ──────────────────────────────────────────────────────

_TIME_MAP: dict[str, tuple[int, str]] = {
    "1h":  (1,  "1h"),
    "4h":  (1,  "4h"),
    "12h": (1,  "12h"),
    "24h": (1,  "24h"),
    "7d":  (7,  "7d"),
    "30d": (30, "30d"),
}

_IDENT = re.compile(r"^[A-Za-z0-9_\-]+$")


class TableLogsRequest(BaseModel):
    table: str
    time_filter: str = "24h"
    search: str = ""
    column_filters: dict = {}
    sort_column: str = ""
    sort_desc: bool = True
    limit: int = 200


class CreateParserRequest(BaseModel):
    table: str
    sample_logs: list[dict]
    columns: list[str]


class SaveFunctionRequest(BaseModel):
    function_name: str
    display_name: str
    query: str
    category: str = "Parser"
    function_parameters: str = ""


class ParserRunRequest(BaseModel):
    table: str
    sample_logs: list[dict]
    columns: list[str]
    days: int = 1


class RunWithFixRequest(BaseModel):
    query: str
    days: int = 1


@router.get("/tables")
async def list_tables():
    """
    List all tables in the workspace.

    Fires ARM Tables API and Usage KQL in parallel.  ARM covers Defender /
    Advanced Hunting tables and every schema table; Usage provides row counts.
    Falls back gracefully when either source fails.
    """
    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    ws  = settings.WORKSPACE_NAME

    arm_path = (
        f"/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}/tables"
    ) if all([sub, rg, ws]) else None

    # Run ARM (latest API) and Usage KQL in parallel
    arm_coro = (
        sentinel_svc.call_azure_mgmt_api_async(arm_path, "2023-09-01")
        if arm_path else asyncio.sleep(0, result={})
    )
    usage_coro = sentinel_svc.run_kql(
        "Usage\n| summarize SizeMB=sum(Quantity) by DataType\n| sort by DataType asc",
        None, 90,
    )

    arm_result, usage_result = await asyncio.gather(arm_coro, usage_coro, return_exceptions=True)

    # Build usage map (ignore if it errored)
    usage_map: dict[str, float] = {}
    if isinstance(usage_result, dict):
        usage_map = {r["DataType"]: r.get("SizeMB", 0) for r in usage_result.get("rows", [])}

    tables: list[dict] = []

    # Prefer ARM result — includes built-in, Defender, AND custom tables
    if isinstance(arm_result, dict) and arm_result.get("value"):
        seen: set[str] = set()
        for t in arm_result["value"]:
            name = t.get("name", "")
            # Skip internal system tables (prefixed with _) but keep custom _CL tables
            if name.startswith("_") and not name.endswith("_CL"):
                continue
            props  = t.get("properties", {})
            schema = props.get("schema", {})
            table_type = schema.get("tableType", "")
            is_custom  = table_type == "CustomLog" or name.endswith("_CL")

            # Column count = user-defined columns + standard columns
            cols = schema.get("columns", []) or []
            std_cols = schema.get("standardColumns", []) or []
            col_count = len(cols) + len(std_cols) if (cols or std_cols) else None

            seen.add(name)
            tables.append({
                "DataType": name,
                "SizeMB":   usage_map.get(name),
                "Columns":  col_count,
                "Custom":   is_custom,
            })

        # Also include any Usage tables not returned by ARM (edge case)
        for name, rows in usage_map.items():
            if name not in seen:
                tables.append({"DataType": name, "SizeMB": rows, "Columns": None, "Custom": False})

        tables.sort(key=lambda x: x["DataType"])

    elif usage_map:
        # ARM unavailable — fall back to Usage alone
        tables = [{"DataType": k, "SizeMB": v, "Columns": None, "Custom": False} for k, v in usage_map.items()]
        tables.sort(key=lambda x: x["DataType"])

    return {"columns": ["DataType", "SizeMB", "Columns", "Custom"], "rows": tables, "row_count": len(tables)}


@router.post("/table-logs")
async def get_table_logs(req: TableLogsRequest):
    """Get logs from a specific table with optional full-text and column filters."""
    if not _IDENT.match(req.table):
        raise HTTPException(status_code=400, detail="Invalid table name")

    days, kql_ago = _TIME_MAP.get(req.time_filter, (1, "24h"))
    parts = [req.table, f"| where TimeGenerated > ago({kql_ago})"]

    if req.search:
        safe = req.search.replace('"', '\\"')
        parts.append(f'| where * has "{safe}"')

    for col, val in (req.column_filters or {}).items():
        if val and _IDENT.match(col):
            safe_val = str(val).replace('"', '\\"')
            parts.append(f'| where {col} has "{safe_val}"')

    sort_col = req.sort_column if req.sort_column and _IDENT.match(req.sort_column) else "TimeGenerated"
    direction = "desc" if req.sort_desc else "asc"
    parts.append(f"| sort by {sort_col} {direction}")
    parts.append(f"| take {min(req.limit, 500)}")

    try:
        return await sentinel_svc.run_kql("\n".join(parts), None, days)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


_PARSER_SYSTEM = """\
You are an expert Microsoft Sentinel / Azure Log Analytics KQL engineer specialising in log parsers.
Your goal is to create a PRODUCTION-QUALITY, maximally-complete KQL parser from the sample data provided.

═══ STEP 1 — DEEPLY ANALYSE every column ═══
Before writing a single KQL token, study each column and identify:
• Embedded structured data: JSON objects/arrays, XML, CEF (key=value extension), LEEF, syslog RFC3164/RFC5424, Windows Event XML, pipe/comma/tab-delimited values
• Columns containing IP addresses, URLs, UPNs, email addresses, file paths, hostnames, GUIDs, hash values
• Enum-like columns (limited distinct values) that should be mapped to ASIM standard vocabulary
• Timestamp strings in non-standard formats that need todatetime() conversion
• Numeric strings that need toint() / tolong() conversion

═══ STEP 2 — EXTRACT every useful field ═══
• JSON fields: use parse_json() then project sub-fields with dot notation or todynamic(); handle nested objects
• CEF/LEEF extension strings: use extract() or parse_csv() to pull all key=value pairs into named columns
• Syslog RFC3164/5424: extract facility, severity, hostname, appname, procid, msgid, message body, structured-data elements
• Windows Event XML: use extract() with XPath-style regex patterns
• Key=value strings: use parse_csv() or a series of extract() calls
• Multi-value fields (comma-separated arrays): use split() and mv-expand where needed

═══ STEP 3 — MAP to ASIM schema ═══
Map every extracted field to the correct ASIM name:
  Actors/Users : ActorUsername, ActorUserId, ActorUserType, TargetUsername, TargetUserId
  Networks     : SrcIpAddr, DstIpAddr, SrcPortNumber, DstPortNumber, NetworkProtocol, NetworkApplicationProtocol, NetworkDirection
  Hosts        : SrcHostname, DstHostname, DvcHostname, DvcDomain, DvcIpAddr
  Files        : TargetFilePath, TargetFileName, TargetFileExtension, TargetFileMD5, TargetFileSHA256
  Processes    : ActingProcessName, ActingProcessId, ActingProcessCommandLine, TargetProcessName, TargetProcessId
  Auth         : LogonType, AuthenticationMethod, LogonProtocol
  Web/HTTP     : HttpRequestMethod, HttpStatusCode, UrlOriginal, HttpUserAgent, HttpReferrer
  Events       : EventType, EventResult ("Success"/"Failure"), EventResultDetails, EventSeverity ("Informational"/"Low"/"Medium"/"High"/"Critical"), EventMessage, EventOriginalUid, EventVendor, EventProduct, EventSchemaVersion

═══ STEP 4 — TYPE-CAST every field ═══
• tostring()   for all string-valued fields extracted from dynamic/JSON
• toint()      for ports, error codes, HTTP status codes, PIDs, counts
• tolong()     for large numeric IDs, timestamps-as-epoch
• todatetime() for ISO/epoch timestamp strings
• tobool()     for boolean-like strings ("true"/"false", "yes"/"no")
• Do NOT leave any extracted field as dynamic/untyped in the final projection

═══ STEP 5 — ENRICHMENT / COMPUTED fields ═══
Add these where the underlying data supports it:
• EventResult       — derive "Success"/"Failure" from result codes, status strings, or boolean flags
• DvcAction         — "Allow"/"Deny"/"Block"/"Drop" from action fields
• EventSeverity     — normalise vendor severity strings to the ASIM vocabulary
• ActorUsernameSplit — strip domain prefix (split(ActorUsername,"\\\\")[-1] or UPN local-part)
• Geo hints         — note if SrcIpAddr / DstIpAddr exist (caller can add geo_info_from_ip_address())

═══ STEP 6 — PARSER STRUCTURE ═══
• First line: the table name (no leading whitespace)
• Use | extend for ALL field extraction and computation (never project first)
• Parse expensive string columns (JSON, regex) once with let or extend, reuse the variable
• Final line: | project TimeGenerated, <every ASIM field you populated>, <original fields not yet covered>
• Do NOT include | take, | limit, or any row-reducing operator in the parser body
• Each pipe operator on its own line with a single leading space
• Use //-style inline comments ONLY for non-obvious regex patterns

Function alias: snake_case, product-specific (e.g. parse_aad_pim_audit, parse_cisco_asa_syslog, parse_windows_security_events)

CRITICAL: Reply ONLY with valid JSON — no markdown, no code fences, no explanation outside the JSON:
{"parser_query": "<full KQL starting with the table name; use \\n between each pipe operator>", "function_alias": "<snake_case_alias>", "explanation": "<3-4 sentences: what product/table this covers, what embedded structures are parsed, what ASIM schema it maps to, and what security use cases it enables>"}"""


@router.post("/create-parser")
async def create_parser(req: CreateParserRequest):
    """Use AI to analyse table sample logs and produce a KQL parser query."""
    status = get_llm_status()
    if not status.get("available"):
        raise HTTPException(status_code=503, detail="LLM not configured — add AZURE_ANTHROPIC_API_KEY to .env")

    sample_str = _json.dumps(req.sample_logs[:10], indent=2, default=str)
    prompt = (
        f"Table: {req.table}\n"
        f"Columns: {', '.join(req.columns)}\n\n"
        f"Sample logs (up to 10 rows):\n{sample_str}\n\n"
        "Create a KQL parser for this table that extracts and normalises the key fields."
    )

    try:
        result = await _llm_complete(_PARSER_SYSTEM, prompt)
        obj = _parse_llm_json(result["text"])
        return {
            "parser_query": obj.get("parser_query", "").replace("\\n", "\n"),
            "function_alias": obj.get("function_alias", req.table.lower() + "_parser"),
            "explanation": obj.get("explanation", ""),
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Parser creation failed: {e}")


@router.post("/run-with-fix")
async def run_with_fix(req: RunWithFixRequest):
    """Run a KQL query, auto-fix on error, stream SSE step events (up to 3 attempts)."""

    async def event_gen():
        query = req.query
        status = get_llm_status()

        for attempt in range(1, 5):
            run_label = "Running query" if attempt == 1 else f"Retrying with fixed query (attempt {attempt})"
            yield _sse({"type": "step", "label": run_label, "status": "running"})
            await asyncio.sleep(0.04)

            try:
                result = await sentinel_svc.run_kql(query, None, req.days)
                row_count = result.get("row_count", 0)
                col_count = len(result.get("columns", []))
                yield _sse({"type": "step", "label": run_label, "status": "done",
                            "detail": f"{row_count} rows · {col_count} columns"})
                yield _sse({"type": "query", "query": query, "alias": "", "explanation": ""})
                yield _sse({"type": "result", "data": result})
                yield _sse({"type": "done", "success": True})
                return

            except (RuntimeError, ValueError) as e:
                error_str = str(e)
                yield _sse({"type": "step", "label": run_label, "status": "error",
                            "detail": error_str[:280]})

                if attempt >= 4 or not status.get("available"):
                    yield _sse({"type": "done", "success": False, "error": error_str})
                    return

                fix_label = f"Diagnosing and fixing query error (attempt {attempt})"
                yield _sse({"type": "step", "label": fix_label, "status": "running"})
                await asyncio.sleep(0.04)

                fix_prompt = (
                    f"Fix the following KQL query that failed.\n\n"
                    f"FAILED QUERY:\n{query}\n\n"
                    f"ERROR:\n{error_str}"
                )
                try:
                    fix_result = await _llm_complete(_KQL_FIX_SYSTEM, fix_prompt)
                    new_query, fix_note = _extract_fix_from_response(fix_result["text"])
                except Exception as llm_err:
                    new_query, fix_note = "", str(llm_err)[:120]

                if new_query and new_query != query:
                    query = new_query
                    yield _sse({"type": "step", "label": fix_label, "status": "done",
                                "detail": fix_note})
                    yield _sse({"type": "query", "query": query, "alias": "", "explanation": ""})
                else:
                    yield _sse({"type": "step", "label": fix_label, "status": "error",
                                "detail": fix_note or "AI returned empty or unchanged query — will retry"})
                    # don't abort — outer loop will retry with the (possibly unchanged) query

        yield _sse({"type": "done", "success": False, "error": "Max retries exceeded"})

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/parser-run")
async def parser_run(req: ParserRunRequest):
    """Generate a KQL parser, run it, and auto-fix on failure. Streams SSE thinking steps."""

    async def event_gen():
        # Step 1 — analyse
        yield _sse({"type": "step", "label": "Analysing table schema and sample logs", "status": "running"})
        await asyncio.sleep(0.05)

        status = get_llm_status()
        if not status.get("available"):
            yield _sse({"type": "step", "label": "Analysing table schema and sample logs", "status": "error",
                        "detail": "LLM not configured"})
            yield _sse({"type": "done", "success": False, "error": "LLM not configured — add AZURE_ANTHROPIC_API_KEY to .env"})
            return

        sample_rows = req.sample_logs[:20]
        sample_str = _json.dumps(sample_rows, indent=2, default=str)

        # Build per-column value samples so the LLM sees actual data patterns
        col_samples: dict[str, list[str]] = {}
        for row in sample_rows:
            for col, val in row.items():
                sv = str(val) if val is not None else ""
                if sv and sv not in col_samples.get(col, []):
                    col_samples.setdefault(col, [])
                    if len(col_samples[col]) < 3:
                        col_samples[col].append(sv[:300])
        col_hints = "\n".join(
            f"  {col}: {' | '.join(repr(v) for v in vals)}"
            for col, vals in col_samples.items() if vals
        )

        prompt = (
            f"Table: {req.table}\n"
            f"Columns ({len(req.columns)}): {', '.join(req.columns)}\n\n"
            f"Column value samples (up to 3 distinct values per column):\n{col_hints}\n\n"
            f"Full sample logs ({len(sample_rows)} rows):\n{sample_str}\n\n"
            "Study every column carefully. Identify ALL embedded structured data (JSON, CEF, syslog, XML, "
            "key=value pairs). Extract and normalise every useful field. "
            "Create the most complete, production-ready KQL parser possible for this table."
        )
        yield _sse({"type": "step", "label": "Analysing table schema and sample logs", "status": "done",
                    "detail": f"{len(sample_rows)} sample rows examined, {len(req.columns)} columns"})

        # Step 2 — generate parser
        yield _sse({"type": "step", "label": "Drafting KQL parser with ASIM normalisation", "status": "running"})
        await asyncio.sleep(0.05)

        try:
            result = await _llm_complete(_PARSER_SYSTEM, prompt)
            obj = _parse_llm_json(result["text"])
            parser_query = obj.get("parser_query", "").replace("\\n", "\n")
            function_alias = obj.get("function_alias", req.table.lower() + "_parser")
            explanation = obj.get("explanation", "")
        except Exception as e:
            yield _sse({"type": "step", "label": "Drafting KQL parser with ASIM normalisation",
                        "status": "error", "detail": str(e)[:200]})
            yield _sse({"type": "done", "success": False, "error": f"Parser generation failed: {e}"})
            return

        yield _sse({"type": "step", "label": "Drafting KQL parser with ASIM normalisation", "status": "done",
                    "detail": f"alias: {function_alias}"})
        yield _sse({"type": "query", "query": parser_query, "alias": function_alias, "explanation": explanation})

        # Steps 3+ — run with auto-fix
        for attempt in range(1, 5):
            run_label = (
                f"Running parser against {req.table}"
                if attempt == 1 else
                f"Retrying with fixed query (attempt {attempt})"
            )
            yield _sse({"type": "step", "label": run_label, "status": "running"})
            await asyncio.sleep(0.05)

            try:
                run_result = await sentinel_svc.run_kql(parser_query, None, req.days)
                row_count = run_result.get("row_count", 0)
                col_count = len(run_result.get("columns", []))
                yield _sse({"type": "step", "label": run_label, "status": "done",
                            "detail": f"{row_count} rows · {col_count} columns"})
                yield _sse({"type": "result", "data": run_result})
                yield _sse({"type": "done", "success": True})
                return

            except (RuntimeError, ValueError) as e:
                error_str = str(e)
                short_err = error_str[:280]
                yield _sse({"type": "step", "label": run_label, "status": "error", "detail": short_err})

                if attempt >= 4:
                    yield _sse({"type": "done", "success": False, "error": error_str})
                    return

                fix_label = f"Diagnosing and fixing query error (attempt {attempt})"
                yield _sse({"type": "step", "label": fix_label, "status": "running"})
                await asyncio.sleep(0.05)

                fix_prompt = (
                    f"Fix the following KQL parser query that failed.\n\n"
                    f"TABLE: {req.table}\n"
                    f"COLUMNS: {', '.join(req.columns)}\n\n"
                    f"FAILED QUERY:\n{parser_query}\n\n"
                    f"ERROR:\n{error_str}\n\n"
                    "Correct only the syntax/type error(s). Preserve all field extraction and ASIM mapping logic. "
                    "Return the full corrected query."
                )
                try:
                    fix_result = await _llm_complete(_KQL_FIX_SYSTEM, fix_prompt)
                    new_query, fix_note = _extract_fix_from_response(fix_result["text"])
                except Exception as llm_err:
                    new_query, fix_note = "", str(llm_err)[:120]

                if new_query and new_query != parser_query:
                    parser_query = new_query
                    yield _sse({"type": "step", "label": fix_label, "status": "done", "detail": fix_note})
                    yield _sse({"type": "query", "query": parser_query, "alias": function_alias,
                                "explanation": explanation})
                else:
                    yield _sse({"type": "step", "label": fix_label, "status": "error",
                                "detail": fix_note or "AI returned empty or unchanged query — will retry"})
                    # don't abort — outer loop retries with the (possibly unchanged) query

        yield _sse({"type": "done", "success": False, "error": "Max retries exceeded"})

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/save-function")
async def save_function(req: SaveFunctionRequest):
    """Save a KQL parser as a Log Analytics workspace function (Saved Search v2)."""
    if not _IDENT.match(req.function_name):
        raise HTTPException(status_code=400, detail="function_name must be alphanumeric / underscore only")

    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    ws  = settings.WORKSPACE_NAME
    if not all([sub, rg, ws]):
        raise HTTPException(
            status_code=503,
            detail="Missing config: subscription_id, resource_group, workspace_name must all be set",
        )

    # savedSearch resource ID — must be unique within the workspace
    saved_search_id = f"parser-{req.function_name}"
    path = (
        f"/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/savedSearches/{saved_search_id}"
    )
    # 2020-08-01 is the minimum version that persists functionAlias correctly.
    # Later versions (2023-09-01, 2025-07-01) do not exist for this resource type
    # and cause ARM to silently strip functionAlias from the saved object.
    _SS_API = "2020-08-01"

    props: dict = {
        "category":      req.category,
        "displayName":   req.display_name or req.function_name,
        "query":         req.query,
        "functionAlias": req.function_name,
        "version":       2,
    }
    if req.function_parameters.strip():
        props["functionParameters"] = req.function_parameters.strip()

    body = {"properties": props}

    try:
        put_result = await sentinel_svc.call_azure_mgmt_api_async(
            path, _SS_API, method="PUT", body=body
        )
        put_alias  = put_result.get("properties", {}).get("functionAlias", "NOT_SET")
        put_id     = put_result.get("id", "")
        print(f"[save-function] PUT 200 — id={put_id!r}  functionAlias={put_alias!r}")
    except Exception as e:
        print(f"[save-function] PUT failed: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to save function: {e}")

    # Read back immediately to confirm the alias persisted
    try:
        verify      = await sentinel_svc.call_azure_mgmt_api_async(path, _SS_API)
        saved_alias = verify.get("properties", {}).get("functionAlias", "")
        print(f"[save-function] GET verify — functionAlias={saved_alias!r}")
        return {
            "success":       True,
            "function_name": req.function_name,
            "alias":         saved_alias,
            "verified":      saved_alias == req.function_name,
            "properties":    verify.get("properties", {}),
        }
    except Exception as e:
        print(f"[save-function] GET verify failed: {e}")
        return {"success": True, "function_name": req.function_name, "verified": False}


@router.get("/list-functions")
async def list_workspace_functions():
    """List all savedSearches that have a functionAlias (i.e. workspace functions)."""
    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    ws  = settings.WORKSPACE_NAME
    if not all([sub, rg, ws]):
        raise HTTPException(status_code=503, detail="Missing workspace config")

    path = (
        f"/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/savedSearches"
    )
    try:
        data = await sentinel_svc.call_azure_mgmt_api_async(path, "2020-08-01")
        all_saved = data.get("value", [])
        functions = [
            {
                "id":           s.get("name", ""),
                "alias":        s.get("properties", {}).get("functionAlias", ""),
                "displayName":  s.get("properties", {}).get("displayName", ""),
                "category":     s.get("properties", {}).get("category", ""),
            }
            for s in all_saved
            if s.get("properties", {}).get("functionAlias")
        ]
        print(f"[list-functions] total savedSearches={len(all_saved)}, with alias={len(functions)}")
        return {"functions": functions, "total_saved_searches": len(all_saved)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
