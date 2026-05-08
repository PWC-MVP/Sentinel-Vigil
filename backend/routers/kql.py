"""KQL Explorer API router."""
import asyncio
import json as _json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.services import sentinel as sentinel_svc
from backend.services.llm import complete as _llm_complete, get_llm_status

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
                    fix_obj = _parse_llm_json(fix_result["text"])
                    new_query = fix_obj.get("query", "").replace("\\n", "\n").strip()
                    fix_note = fix_obj.get("explanation", "Query corrected")

                    if not new_query or new_query == query:
                        yield _sse({"type": "log", "level": "warn",
                                    "msg": "AI returned an unchanged query — retrying as-is"})
                    else:
                        yield _sse({"type": "log", "level": "ai", "msg": f"Fix applied: {fix_note}"})
                        query = new_query

                except Exception as llm_err:
                    yield _sse({"type": "log", "level": "error",
                                "msg": f"AI fix request failed: {llm_err}"})
                    yield _sse({"type": "done", "success": False, "error": str(llm_err)})
                    return

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
