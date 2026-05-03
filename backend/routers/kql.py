"""KQL Explorer API router."""
import json as _json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.services import sentinel as sentinel_svc
from backend.services.llm import complete as _llm_complete, get_llm_status

router = APIRouter(prefix="/api/kql", tags=["kql"])


class KQLRequest(BaseModel):
    query: str
    workspace_id: str | None = None
    days: int = 30


class KQLGenerateRequest(BaseModel):
    prompt: str
    days: int = 30


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
        raw = await _llm_complete(kql_system, req.prompt)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM generation failed: {e}")

    cleaned = raw.strip()
    for fence in ("```json", "```"):
        if cleaned.startswith(fence):
            cleaned = cleaned[len(fence):]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    try:
        obj = _json.loads(cleaned)
        return {"query": obj.get("query", "").replace("\\n", "\n"), "explanation": obj.get("explanation", "")}
    except Exception:
        return {"query": raw.strip(), "explanation": ""}


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
