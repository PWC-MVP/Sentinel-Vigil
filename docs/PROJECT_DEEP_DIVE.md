# Sentinel Vigil — Complete Project Deep Dive

> A comprehensive explanation of every file and every line of code in the project.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Folder Structure](#2-folder-structure)
3. [backend/main.py — Application Entry Point](#3-backendmainpy)
4. [backend/config.py — Configuration Loader](#4-backendconfigpy)
5. [backend/auth.py — Azure Authentication](#5-backendauthpy)
6. [backend/services/token_manager.py — Token Cache](#6-backendservicestoken_managerpy)
7. [backend/services/sentinel.py — KQL & ARM API](#7-backendservicessentinelpy)
8. [backend/services/graph.py — Microsoft Graph](#8-backendservicesgraphpy)
9. [backend/services/llm.py — LLM Provider Layer](#9-backendservicesllmpy)
10. [backend/services/tools.py — ARIA Tool Definitions](#10-backendservicestoolspy)
11. [backend/services/investigation.py — Investigation Orchestrator](#11-backendservicesinvestigationpy)
12. [backend/services/investigation_cache.py — TTL Cache](#12-backendservicesinvestigation_cachepy)
13. [backend/services/jobs.py — Background Job Manager](#13-backendservicesjobspy)
14. [backend/services/backup.py — Sentinel Backup Engine](#14-backendservicesbackuppy)
15. [backend/services/restore.py — Sentinel Restore Engine](#15-backendservicesrestorepy)
16. [backend/services/file_tracker.py — Change Detection](#16-backendservicesfile_trackerpy)
17. [backend/services/keyvault.py — Key Vault Client](#17-backendserviceskeyvaultpy)
18. [backend/core/investigator.py — Data Models](#18-backendcoreinvestigatorpy)
19. [backend/core/enrich_ips.py — IP Enrichment Engine](#19-backendcoreenrich_ipspy)
20. [backend/core/report_generator.py — HTML Report Generator](#20-backendcorereport_generatorpy)
21. [backend/routers/ — All 19 API Routers](#21-backendrouters)
22. [frontend/src/App.tsx — SPA Router](#22-frontendsrCapptsx)
23. [frontend/src/api/client.ts — API Client](#23-frontendsrcapiclientts)
24. [frontend/src/pages/ — All 23 Pages](#24-frontendsrcpages)
25. [Dockerfile — Container Build](#25-dockerfile)
26. [Data Flow Diagrams](#26-data-flow-diagrams)

---

## 1. Project Overview

**Sentinel Vigil** is a standalone web application for Microsoft Sentinel security operations. It replaces a fragmented GitHub Copilot + MCP workflow with a single, self-contained backend + React frontend.

**What it does:**
- Runs automated security investigations on Entra ID users (sign-ins, anomalies, MFA, devices, risk detections)
- Provides an AI chat interface (ARIA) backed by Azure Anthropic / Claude with live tool calling against Sentinel and Graph
- Backs up and restores Sentinel workspace resources (alert rules, workbooks, watchlists, etc.)
- Enriches IP addresses with threat intelligence from 4 APIs
- Generates professional HTML/PDF investigation reports

**Tech stack:**
| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, asyncio, Azure SDK |
| AI | Azure Anthropic (Claude), fallback to OpenAI |
| Azure | Log Analytics (KQL), ARM REST API, Microsoft Graph, Identity Protection |
| Frontend | React 18, TypeScript, Vite, Axios |
| Container | Docker multi-stage (Node → Python) |

---

## 2. Folder Structure

```
Sentinel-Vigil/
├── backend/
│   ├── main.py              ← FastAPI app, CORS, routers, SPA serving
│   ├── config.py            ← All config from .env + config.json
│   ├── auth.py              ← Azure credential singleton
│   ├── core/
│   │   ├── investigator.py  ← Data model dataclasses
│   │   ├── report_generator.py  ← HTML report generator
│   │   └── enrich_ips.py    ← IP threat intelligence enrichment
│   ├── routers/             ← 19 FastAPI router files
│   ├── services/
│   │   ├── sentinel.py      ← KQL queries + ARM management API
│   │   ├── graph.py         ← Microsoft Graph API
│   │   ├── llm.py           ← Multi-provider LLM (Anthropic/OpenAI)
│   │   ├── tools.py         ← ARIA tool definitions + executor
│   │   ├── investigation.py ← Investigation orchestrator
│   │   ├── investigation_cache.py  ← 30-min result cache
│   │   ├── jobs.py          ← Background job system
│   │   ├── backup.py        ← Sentinel backup engine
│   │   ├── restore.py       ← Sentinel restore engine
│   │   ├── file_tracker.py  ← SHA-256 change detection
│   │   ├── token_manager.py ← Proactive OAuth token refresh
│   │   └── keyvault.py      ← Azure Key Vault (optional)
│   └── scripts/             ← 14 standalone utility scripts
├── frontend/
│   └── src/
│       ├── App.tsx           ← SPA router (useState, no React Router)
│       ├── api/client.ts     ← All API functions + TypeScript interfaces
│       ├── components/       ← Layout, panels, shared components
│       └── pages/            ← 23 page components
├── data/
│   ├── reports/             ← Generated investigation reports + backups
│   ├── jobs/                ← Completed job state JSON files
│   └── temp/                ← Temporary investigation JSON files
├── docs/                    ← Documentation markdown
├── queries/                 ← KQL templates by domain
├── mcp-apps/                ← 3 MCP servers (geomap, heatmap, incident-comment)
├── Dockerfile               ← Two-stage build (Node + Python)
└── .env / config.json       ← Runtime configuration (not committed)
```

---

## 3. `backend/main.py`

The **entry point** for the entire backend. Every request passes through here.

### Lines 1–7: Imports + Windows Fix

```python
import asyncio
import sys
import datetime
from contextlib import asynccontextmanager

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
```

`asyncio`, `sys`, `datetime` are standard library modules. The Windows check at line 6 patches the asyncio event loop **before anything else loads**. Windows defaults to `SelectorEventLoop` which does not support subprocess operations needed by the Azure SDK. `WindowsProactorEventLoopPolicy` fixes this. This must run at the very top.

### Lines 9–21: Framework + Application Imports

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.config import settings
from backend.auth import check_auth
from backend.routers import kql, investigations, reports, enrichment, chat, mitre, geomap, analytics
# ... more routers
```

`FastAPI` is the ASGI web framework. `CORSMiddleware` allows browsers to call the API from a different origin (the Vite dev server on port 5173). `settings` is the `Config` singleton from config.py. Each router import is a module that defines a group of API endpoints.

### Lines 26–39: Scheduled Backup Loop

```python
async def _scheduled_backup_loop():
    while True:
        now      = datetime.datetime.utcnow()
        next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += datetime.timedelta(days=1)
        await asyncio.sleep((next_run - now).total_seconds())
        try:
            from backend.services.backup import run_backup
            from backend.services.jobs import create_job, run_job
            job_id = create_job()
            asyncio.create_task(run_job(job_id, lambda: run_backup(job_id=job_id, incremental=True)))
        except Exception as e:
            print(f"Scheduled backup failed: {e}")
```

An infinite async loop that runs as a background task. Calculates the next 02:00 UTC moment, sleeps until then, then triggers an incremental backup. Errors are caught and printed — the loop never crashes. Next night it retries. `asyncio.sleep()` is non-blocking: while the loop is sleeping, all other request handlers continue running normally.

### Lines 42–46: Lifespan Hook

```python
@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_scheduled_backup_loop())
    yield
    task.cancel()
```

FastAPI's lifecycle hook. Before `yield` = startup: launches the backup loop as a background asyncio task. `yield` = serving requests. After `yield` = shutdown: cancels the backup loop cleanly when the server stops (Ctrl+C or Docker SIGTERM).

### Lines 50–58: FastAPI App Object

```python
app = FastAPI(
    title="Sentinel Vigil API",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
```

Creates the ASGI application. `docs_url` moves Swagger UI to `/api/docs` (instead of the default `/docs`) to avoid clashing with frontend routes. `lifespan=lifespan` wires the startup/shutdown logic.

### Lines 61–67: CORS

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Browsers enforce a security policy that blocks cross-origin API calls unless the server explicitly allows them. This middleware responds to the browser's preflight OPTIONS request with permission headers. `settings.CORS_ORIGINS` defaults to `["http://localhost:5173", "http://localhost:3000"]` but is overridable via env var.

### Lines 70–88: Router Registration

Each `app.include_router(...)` mounts a group of endpoints. All 19 routers are registered here:

| Router | Prefix | Purpose |
|--------|--------|---------|
| kql | `/api/kql` | Run KQL queries, generate KQL with AI, smart retry |
| investigations | `/api/investigations` | Start/poll investigations, WebSocket progress |
| reports | `/api/reports` | List/download HTML reports, PDF export |
| enrichment | `/api/enrich` | IP enrichment jobs |
| chat | `/api/chat` | ARIA AI chat (SSE streaming) |
| mitre | `/api/mitre` | MITRE ATT&CK coverage analysis |
| geomap | `/api/geomap` | Sign-in geolocation map |
| analytics | `/api/analytics` | Dashboard charts data |
| sentinel_health | `/api/sentinel/health` | Workspace health check |
| automation | `/api/automation` | Logic App playbooks |
| analytics_rules | `/api/analytics-rules` | Alert rule management |
| incident_analytics | `/api/incidents` | Incident trends |
| entity_exposure | `/api/entity-exposure` | Risky users and hosts |
| hunting | `/api/hunting` | Saved hunting queries |
| workbooks | `/api/workbooks` | Workbook management |
| backup | `/api/backup` | Start backup jobs |
| restore | `/api/restore` | Start restore jobs |
| dcr | `/api/dcr` | Data Collection Rules |
| threat_feed | `/api/threat-feed` | Threat intelligence |

### Lines 92–200: System Endpoints

**`GET /api/config`** — Returns current config (workspace ID, tenant, resource group, auth status, which APIs are configured). Called by the frontend on startup to check health.

**`PATCH /api/config`** — Updates `config.json` on disk. Currently supports `output_dir` only.

**`GET /api/config/env`** — Returns the current values of all env vars. Used to pre-fill the Settings form.

**`PATCH /api/config/env`** — The hot-reload endpoint. Writes new values to `.env` using python-dotenv's `set_key()`, reloads the env file, calls `settings.reload()` and `reset_credential()`. No restart needed.

**`POST /api/auth/login`** — Validates username + password against `APP_USERNAME`/`APP_PASSWORD`. Uses `hmac.compare_digest` instead of `==` to prevent timing attacks (an attacker cannot determine how many characters match by measuring response time).

**`POST /api/auth/verify-settings`** — Checks the Settings page password (`SETTINGS_PASSWORD`). Guards the API key configuration form.

**`GET /api/health`** — Static `{"status": "ok"}`. Used as the Kubernetes/Container Apps liveness probe.

### Lines 203–226: React SPA Serving

```python
_DIST = _Path(__file__).parent.parent / "frontend" / "dist"
if _DIST.exists():
    app.mount("/assets", _StaticFiles(directory=_DIST / "assets"), name="frontend-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa_fallback(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        static_file = _DIST / full_path
        if static_file.is_file():
            return _FileResponse(static_file)
        return _FileResponse(_DIST / "index.html")
```

Only active in Docker (where `frontend/dist/` exists after the Stage 1 Node build). Serves:
- `/assets/*` → Vite's hashed JS/CSS bundles
- `/favicon.ico`, `/logo.png` etc. → static files from `dist/`
- Everything else → `index.html` so React handles its own routing
- `/api/*` with no matching route → 404 (prevents returning index.html for broken API calls)

---

## 4. `backend/config.py`

All configuration for the entire application is centralized here.

### ROOT Calculation

```python
ROOT = Path(__file__).parent.parent
```

`Path(__file__)` is `backend/config.py`. `.parent` = `backend/`. `.parent` again = `Sentinel-Vigil/`. `ROOT` is used to build all other absolute paths.

### .env Loading

```python
load_dotenv(ROOT / ".env")
```

No `override=True` — existing environment variables (from Container Apps or Docker Compose) are not overridden. The `.env` file is a development convenience; production always uses real env vars.

### Config JSON Loading

```python
def _load_config_json() -> dict:
    config_path = ROOT / "config.json"
    if not config_path.exists():
        return {}
    with open(config_path, "r") as f:
        return json.load(f)

_raw = _load_config_json()
```

`_raw` is module-level — read once at import time. The JSON file holds workspace IDs, mappings, and anything that's easier to configure as JSON than env vars.

### The Config Class Pattern

Every attribute uses: `os.getenv("ENV_VAR") or _raw.get("json_key", "default")`. Python's `or` short-circuits — if the env var is set, the JSON is never consulted. Priority: **env var → config.json → hardcoded default**.

### Key Attributes

| Attribute | Default | Purpose |
|-----------|---------|---------|
| `SENTINEL_WORKSPACE_ID` | `""` | Log Analytics workspace GUID for KQL |
| `TENANT_ID` | `""` | Azure AD tenant for auth |
| `SUBSCRIPTION_ID` | `""` | Azure subscription for ARM API |
| `RESOURCE_GROUP` | `""` | Resource group for Sentinel workspace |
| `WORKSPACE_NAME` | `""` | Workspace name for ARM paths |
| `OUTPUT_DIR` | `ROOT/data/reports` | Where reports and backups are written |
| `APP_USERNAME` / `APP_PASSWORD` | `admin` / `PwC@y14` | UI login credentials |
| `SETTINGS_PASSWORD` | `changeme` | Settings page gate |
| `DEFAULT_MODEL` | `claude-sonnet-4-6` | Default LLM model |

### `reload()` Method

Re-reads all env vars and config.json values into the class attributes. Called after `PATCH /api/config/env`. Uses `override=True` so the new `.env` values replace the cached ones.

### Helper Methods

- `is_valid()` — returns `True` if workspace ID and tenant ID are both set.
- `api_status()` — returns `{"ipinfo": bool, "abuseipdb": bool, ...}` without exposing token values.
- `to_public_dict()` — safe-to-send config snapshot for the frontend (no secrets).

### `settings = Config()` (Line 230)

Creates the singleton. All code imports this: `from backend.config import settings`.

---

## 5. `backend/auth.py`

### Module-Level State

```python
_credential: DefaultAzureCredential | None = None
```

A module-level singleton. Once created, the credential object is reused for every API call.

### `get_credential()` — Credential Factory

```python
def get_credential():
    global _credential
    if _credential is None:
        client_id = os.getenv("AZURE_CLIENT_ID", "").strip()
        client_secret = os.getenv("AZURE_CLIENT_SECRET", "").strip()
        tenant_id = (os.getenv("AZURE_TENANT_ID") or os.getenv("TENANT_ID") or "").strip()

        if client_id and client_secret and tenant_id:
            _credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        else:
            _credential = DefaultAzureCredential(
                exclude_workload_identity_credential=False,
                exclude_managed_identity_credential=False,
            )
    return _credential
```

If all three service principal env vars are set → uses `ClientSecretCredential` (explicit service principal). Otherwise → uses `DefaultAzureCredential`, which tries: environment vars → workload identity → managed identity → Azure CLI → VS Code extension → Azure PowerShell. Developers typically run with `az login` (CLI token). Production containers use managed identity or service principal env vars.

### `reset_credential()`

Sets `_credential = None`. Called after settings update so the next API call rebuilds with the new credentials.

### `check_auth()`

```python
async def check_auth() -> dict:
    try:
        cred = get_credential()
        loop = asyncio.get_event_loop()
        token = await loop.run_in_executor(
            None, lambda: cred.get_token("https://api.loganalytics.io/.default")
        )
        ...
```

Tests credential health by acquiring a Log Analytics token. `run_in_executor` prevents the synchronous `get_token()` call from blocking the async event loop. Returns `{"authenticated": True, "method": "...", "token_expires": ...}` on success.

---

## 6. `backend/services/token_manager.py`

### Why It Exists

Azure OAuth tokens expire (typically 60-90 min). A request that fires exactly at token expiry gets a 401. The fix: refresh 5 minutes early. But two threads must not refresh simultaneously.

### `TokenManager` Class

```python
class TokenManager:
    _instances: dict[str, "TokenManager"] = {}
    _lock = threading.Lock()
```

`_instances` maps `"{id(credential)}:{scope}"` → manager instance. A separate manager exists per (credential, scope) pair: one for Log Analytics, one for ARM, one for Graph.

### `get(credential, scope)` — Thread-Safe Factory

```python
@classmethod
def get(cls, credential, scope: str) -> "TokenManager":
    key = f"{id(credential)}:{scope}"
    with cls._lock:
        if key not in cls._instances:
            cls._instances[key] = cls(credential, scope)
    return cls._instances[key]
```

`id(credential)` is Python's memory address — unique per object. The `_lock` protects the dict from concurrent creation. Returns without holding the lock (lock only covers the creation step).

### `get_token()` — Token Fetch with Refresh Guard

```python
def get_token(self) -> str:
    with self._refresh_lock:
        if self._needs_refresh():
            self._token = self._credential.get_token(self._scope)
    return self._token.token
```

Per-instance lock ensures only one thread refreshes at a time. All others wait and then return the new token.

### `_needs_refresh()`

```python
return time.time() >= (self._token.expires_on - 300)
```

Returns `True` if the token expires within 5 minutes (300 seconds). `expires_on` is a Unix timestamp.

---

## 7. `backend/services/sentinel.py`

### API Version Map

```python
_API_VERSIONS: dict[str, str] = {
    "alertrules":         "2023-02-01",
    "automationrules":    "2025-01-01-preview",
    "workbooks":          "2022-04-01",
    "watchlists":         "2023-02-01",
    ...
}
```

Azure ARM requires a specific `api-version` query parameter for each resource type. Wrong version = 404 or 400. This map keeps them all in one place.

### `run_kql(query, workspace_id, days)` — The Core Query Function

Called by almost every part of the backend that needs Sentinel data.

```python
async def run_kql(query, workspace_id=None, days=30) -> dict:
    ws_id = workspace_id or settings.SENTINEL_WORKSPACE_ID
    client = _client()  # creates LogsQueryClient(get_credential())
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.query_workspace(workspace_id=ws_id, query=query, timespan=timedelta(days=days))
    )
```

`query_workspace` is synchronous → must run in the thread pool via `run_in_executor` to avoid blocking the event loop. `timespan` sets the implicit time window for the query (individual queries can add further `| where TimeGenerated > ago(7d)` filters).

Returns `{"columns": [...], "rows": [{...}, ...], "row_count": N}`.

`_serialize(val)` converts `datetime` and `timedelta` values in rows to strings (JSON doesn't have native datetime type).

### `call_sentinel_mgmt_api(...)` — ARM REST API with Pagination

```python
def call_sentinel_mgmt_api(path, api_version, method="GET", body=None, resource_type=None) -> dict:
```

All backup/restore operations use this. Key behaviors:

**Automatic API version selection:** `if resource_type: api_version = _api_version(resource_type)` — callers don't need to know versions.

**Automatic pagination:** Azure returns up to 1000 items per page with a `nextLink` for the next page. This function follows all `nextLink` URLs and merges all pages into a single `{"value": [...]}` response.

**401 retry:** If the server returns 401, the token is force-cleared (`token_mgr._token = None`) and the request is retried once. Handles the edge case where a token expires in the millisecond between the freshness check and the API call.

`call_sentinel_mgmt_api_async` wraps this in `run_in_executor` for async callers.

### `call_azure_mgmt_api_async(path, api_version, ...)` — Generic ARM Client

For ARM paths outside the Sentinel workspace (e.g., workbooks at the resource group level, role assignments). Takes a full `/subscriptions/...` path. Same pagination and 401 retry behavior.

---

## 8. `backend/services/graph.py`

### `graph_get(path, version)` — Core Graph Fetch

```python
async def graph_get(path: str, version: str = "v1.0") -> dict[str, Any]:
    cred = get_credential()
    url = f"{GRAPH_BASE}/{version}{path}"
    token = await loop.run_in_executor(None, lambda: _get_token(cred))
    resp = await _do_get(token)

    if resp.status_code == 401:
        # Force-clear token and retry once
        TokenManager.get(cred, GRAPH_SCOPE)._token = None
        token = await loop.run_in_executor(None, lambda: _get_token(cred))
        resp = await _do_get(token)

    if resp.status_code == 404:
        return {}  # user not found — not an error
```

Token fetch is in the thread pool (synchronous operation). Graph uses `httpx.AsyncClient` for the actual HTTP call (fully async). Returns empty dict on 404 (user doesn't exist is not a crash condition).

### Convenience Wrappers

| Function | Graph Path | Returns |
|----------|-----------|---------|
| `get_user(upn)` | `/users/{upn}?$select=...` | User profile dict |
| `get_mfa_methods(user_id)` | `/users/{id}/authentication/methods` | List of auth method objects |
| `get_user_devices(user_id)` | `/users/{id}/ownedDevices?$orderby=...` | List of device objects |
| `get_user_risk_profile(user_id)` | `/identityProtection/riskyUsers/{id}` | Risk profile dict |
| `get_risk_detections(user_id)` | `/identityProtection/riskDetections?$filter=...` | List of risk events |
| `get_risky_signins(user_id)` | `/auditLogs/signIns?$filter=...` (beta) | List of risky sign-ins |

`get_risky_signins` uses `version="beta"` because the `riskState` filter on sign-in logs is a beta-only feature. It catches all exceptions and returns `[]` on failure — beta endpoints can be unreliable.

---

## 9. `backend/services/llm.py`

### `_llm_creds()` — Fresh Credential Read

Reads all LLM-related env vars on every call. This means when the user updates the `.env` via the Settings page and `settings.reload()` runs, the very next LLM call uses the new credentials automatically.

### Provider Fallback Chain

The code implements a 4-tier fallback:

```
Azure Anthropic (AZURE_ANTHROPIC_API_KEY + AZURE_ANTHROPIC_ENDPOINT)
    ↓ (if not configured, or if deployment not found)
Direct Anthropic (ANTHROPIC_API_KEY)
    ↓ (if not configured)
Azure OpenAI (AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY)
    ↓ (if not configured)
OpenAI (OPENAI_API_KEY)
```

### ARIA System Prompt

Defines ARIA's identity, capabilities, rules (evidence-based only, use tables, use emojis for risk levels), and the expected response format (Executive Summary → Findings Table → Detailed Analysis → Recommended Actions → KQL Reference). This is injected into every conversation.

### `stream_chat(messages, tools, on_tool_call, model)` — Agentic Streaming

The main ARIA chat function. Implements a **multi-round agentic loop**:

1. Send messages + tools to the LLM
2. Stream text deltas to the browser in real time via SSE
3. If the model calls a tool:
   - Emit `{"type": "tool_call", "name": "...", "args": {...}}` to the browser
   - Execute the tool via `on_tool_call(name, args)`
   - Emit `{"type": "tool_result", "name": "...", "result": "..."}` to the browser
   - Append tool result to conversation history
   - Loop back to step 1
4. If no tools called → emit `{"type": "done"}` and return

Maximum 8 tool-calling rounds. If exceeded, emits an error.

**Anthropic streaming protocol:** Events arrive as `data: {...}` lines. `content_block_start` with type `tool_use` signals a tool call; `content_block_delta` with `text_delta` is streaming text; `input_json_delta` streams tool arguments in JSON fragments that must be accumulated.

### `complete(system, user_msg, model)` — Non-Streaming Single Turn

Used for report generation and summaries. Returns `{"text": str, "usage": {...}}`. Has the same fallback chain as `stream_chat`.

### Token Budget Retry (`_complete_anthropic`)

Some Azure deployments have lower `max_tokens` limits than configured. The code tries `[configured, min(configured, 8192), min(configured, 4096)]` in order, retrying with a smaller budget if the API returns a 400/422 error containing "token" in the error message.

### Continuation Loop (Truncation Handling)

When `stop_reason == "max_tokens"`, the model was cut off mid-output. The code sends a new request with the partial text + `"Continue exactly where it was cut off. No preamble."`. Happens up to 3 times, effectively enabling reports up to 4× the token limit.

This pattern exists in all 4 completion paths: `_complete_anthropic`, `_complete_anthropic_direct`, `_complete_openai`, and all streaming variants.

---

## 10. `backend/services/tools.py`

### `TOOLS` — 16 Tool Schemas

Defined in OpenAI function-calling format. Each tool has a name, description (which the LLM reads to decide when to use it), and a JSON Schema for the parameters. The LLM picks which tool to call and constructs the arguments.

| Tool | What It Executes |
|------|----------------|
| `run_kql_query` | `sentinel_svc.run_kql(query, days)` |
| `investigate_user` | `inv_svc.run_investigation(job_id, upn, dates, output_mode)` |
| `enrich_ip_addresses` | `enrich_ips.enrich_ips(ips, max_workers=5)` in thread pool |
| `get_user_profile` | `graph_svc.get_user(upn)` |
| `get_user_mfa_and_devices` | `gather(get_mfa_methods, get_user_devices)` in parallel |
| `get_identity_protection_data` | `gather(risk_profile, risk_detections, risky_signins)` in parallel |
| `generate_html_report` | `inv_svc._generate_html_report(result_dict, upn)` in thread pool |
| `list_security_incidents` | KQL on `SecurityIncident` table |
| `threat_hunt` | `_build_hunt_query(topic, days)` + `sentinel_svc.run_kql` |
| `backup_sentinel_workspace` | `asyncio.create_task(run_backup(...))` — returns job_id immediately |
| `restore_sentinel_resources` | `asyncio.create_task(restore_from_snapshot(...))` — async |
| `list_backup_snapshots` | `backup_svc.list_snapshots()` |
| `compare_backup_snapshots` | `backup_svc.compare_snapshots(a, b)` |
| `get_backup_status` | `job_svc.get_job(job_id).model_dump()` |
| `invalidate_investigation_cache` | `investigation_cache.invalidate(upn)` |
| `check_permissions` | `call_azure_mgmt_api_async` on role assignments |

### `_build_hunt_query(topic, days)` — KQL Query Builder

Matches hunt topic keywords to pre-written KQL templates:
- `phish/aitm/T1566` → SigninLogs anomaly hunt
- `lateral/rdp/T1021` → DeviceNetworkEvents port 3389 hunt
- `infostealer/stealer` → DeviceProcessEvents credential command hunt
- `anomal/signin` → custom anomaly table
- Anything else → union of SigninLogs + SecurityAlert + AuditLogs with fuzzy text search

---

## 11. `backend/services/investigation.py`

The orchestrator that runs a complete user security investigation by coordinating Sentinel, Graph, and IP enrichment in parallel.

### KQL Templates

9 pre-written KQL templates are defined as module-level string constants with `{upn}`, `{start}`, `{end}`, `{user_id}` placeholders:

| Template | What It Queries |
|----------|----------------|
| `_KQL_ANOMALIES` | Custom anomaly table `Signinlogs_Anomalies_KQL_CL` |
| `_KQL_SIGNIN_APPS` | Sign-ins grouped by application |
| `_KQL_SIGNIN_LOCATIONS` | Sign-ins grouped by location |
| `_KQL_SIGNIN_FAILURES` | Failed sign-ins grouped by error code |
| `_KQL_AUDIT_LOGS` | AuditLogs entries for the user |
| `_KQL_OFFICE_ACTIVITY` | OfficeActivity grouped by operation |
| `_KQL_CLOUD_APP_EVENTS` | CloudAppEvents grouped by action |
| `_KQL_IP_SELECTION` | Selects the most important IPs (anomaly IPs first, then frequent) |
| `_KQL_SECURITY_INCIDENTS` | SecurityIncidents linked to the user via SecurityAlert entities |
| `_KQL_THREAT_INTEL` | Checks collected IPs against `ThreatIntelIndicators` |

### `run_investigation(job_id, upn, start_date, end_date, ...)` — Main Workflow

8 phases, each emitting progress updates to the WebSocket via `job_svc.emit()`:

**Phase 1: User profile**
```python
user_data = await graph_svc.get_user(upn)
user_id = user_data.get("id", "")
```

**Phase 2: Parallel Sentinel queries** — 9 KQL queries run simultaneously with `asyncio.gather()`:
```python
results = await asyncio.gather(*sentinel_tasks)
```
All queries fire at once. Total time = slowest single query, not sum of all queries.

**Phase 3: Parallel Graph identity data**
```python
await asyncio.gather(
    get_mfa_methods, get_user_devices, get_user_risk_profile,
    get_risk_detections, get_risky_signins, return_exceptions=True
)
```
`return_exceptions=True` means a single Graph failure doesn't abort all 5 calls.

**Phase 4: Threat intelligence** — Checks the collected IPs against `ThreatIntelIndicators` table.

**Phase 5: IP enrichment** — Calls `enrich_ips.enrich_ips()` in the thread pool, merges with threat intel and anomaly data.

**Phase 6: Result assembly** — Builds the complete result dict with user profile, MFA status, devices, all events, and risk assessment.

**Phase 7 (optional): AI executive summary** — Calls `llm.summarize_investigation()`.

**Phase 8 (optional): HTML report** — Calls `generate_html_report()` in the thread pool.

### `_compute_risk(...)` — Scoring Algorithm

| Factor | Score Impact |
|--------|-------------|
| New country access (per country) | +3 each |
| Threat intel match (per IP) | +5 each |
| High-severity incident | +3 |
| Identity Protection `confirmedCompromised` | +10 |
| Identity Protection `atRisk` | +3 |
| Active risk detections (per detection) | +2 each |
| MFA enabled | -2 |
| FIDO2 registered | -1 |

Score thresholds: CRITICAL ≥ 8, HIGH ≥ 5, MEDIUM ≥ 3, LOW ≥ 1, INFO = 0.

### Caching

Results are cached in `investigation_cache` keyed by `(upn, days_back)` for 30 minutes. On cache hit, emits `"⚡ Returning cached investigation"` and returns immediately. Cache is written after every successful investigation.

---

## 12. `backend/services/investigation_cache.py`

```python
_CACHE: dict[str, tuple[float, dict]] = {}
_LOCK = asyncio.Lock()
DEFAULT_TTL = 1800  # 30 minutes
```

Module-level dict. Keys are `"{upn}:{days_back}"`. Values are `(timestamp, result_dict)` tuples. `asyncio.Lock()` prevents concurrent read/write races.

- `get_cached(upn, days_back)` — returns `None` if no entry or if `(now - cached_at) >= 1800`
- `set_cached(upn, days_back, result)` — stores with current timestamp
- `invalidate(upn=None)` — removes all entries for a user, or clears everything if `upn=None`
- `list_cached()` — returns metadata (age, expiry) for all cached entries (used by ARIA tool)

---

## 13. `backend/services/jobs.py`

Background job system for investigations and backup/restore operations. Survives backend restarts via JSON persistence.

### Data Models

```python
class JobStatus(str, Enum):
    PENDING = "pending"    # created, not yet started
    RUNNING = "running"    # asyncio task is executing
    COMPLETED = "completed"
    FAILED = "failed"

class JobUpdate(BaseModel):
    phase: str      # "start", "queries", "enrichment", "done", etc.
    message: str
    timestamp: str  # ISO UTC string, auto-set
    data: Any = None

class Job(BaseModel):
    job_id: str
    status: JobStatus = PENDING
    created_at: str
    completed_at: str | None = None
    error: str | None = None
    result: Any = None
    updates: list[JobUpdate] = []
```

### Global State

```python
_jobs: dict[str, Job] = {}
_queues: dict[str, asyncio.Queue] = {}
```

`_jobs` stores all job objects in memory. `_queues` stores per-job asyncio queues used for WebSocket streaming.

### Persistence

On startup, `_load_jobs()` scans `data/jobs/*.json` and restores COMPLETED and FAILED jobs. RUNNING/PENDING jobs are stale after restart and are ignored. When a job completes or fails, `_save_job(job)` writes `data/jobs/{job_id}.json`.

### `create_job()` → `run_job()`

```python
def create_job() -> str:
    job_id = str(uuid.uuid4())
    _jobs[job_id] = Job(job_id=job_id)
    _queues[job_id] = asyncio.Queue()
    return job_id

async def run_job(job_id, coro_factory):
    job = _jobs[job_id]
    job.status = JobStatus.RUNNING
    try:
        result = await coro_factory()
        job.result = result
        job.status = JobStatus.COMPLETED
        await emit(job_id, "done", "Complete", result)
    except Exception as e:
        job.status = JobStatus.FAILED
        job.error = str(e)
        await emit(job_id, "error", f"Failed: {e}")
    finally:
        _save_job(job)
```

### `emit(job_id, phase, message, data)` + `subscribe(job_id)`

`emit()` appends a `JobUpdate` to `job.updates` and pushes it to the asyncio Queue. `subscribe()` is an async generator that yields updates from the queue — used by the WebSocket endpoint to stream real-time progress to the browser.

---

## 14. `backend/services/backup.py`

Backs up up to 12 Sentinel resource types to a timestamped snapshot directory.

### `RESOURCE_TYPES` List

```python
RESOURCE_TYPES = [
    "scheduledRules", "nrtRules", "fusionRules", "microsoftRules",
    "automationRules", "workbooks", "watchlists", "huntingQueries",
    "summaryRules", "dataConnectors", "threatIntelligence", "metadata",
]
```

### Per-Type Extractors

Each type has a dedicated async function (e.g., `extract_scheduled_rules`, `extract_workbooks`). The pattern is:

```python
async def extract_XXXX(snapshot_dir, tracker, job_id) -> int:
    data = await call_sentinel_mgmt_api_async("/alertRules", resource_type="alertrules")
    rules = data.get("value", [])
    count = 0
    for rule in rules:
        if not tracker.is_changed(rule_id, rule):
            continue  # incremental: skip unchanged
        out_path = snapshot_dir / "scheduledRules" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(rule, indent=2))
        tracker.record(rule_id, "scheduledRules", str(out_path), rule)
        count += 1
    await emit(job_id, type_label, f"Backed up {count} items")
    return count
```

`tracker.is_changed(id, content)` computes SHA-256 of the current JSON and compares to the stored hash. If unchanged, the file is skipped (incremental backup).

Alert rules (Scheduled, NRT, Fusion, Microsoft) all share `_extract_alert_rules` which filters by `props.get("kind")` value.

### `run_backup(job_id, resource_types, output_dir, incremental)` — Orchestrator

```python
timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
base_dir = Path(output_dir or settings.OUTPUT_DIR) / "backups" / timestamp
tracker = FileTracker(str(base_dir))

if incremental:
    prev_snapshot = _find_latest_snapshot(...)
    if prev_snapshot:
        prev_tracker = FileTracker(str(prev_snapshot))
        tracker._manifest = dict(prev_tracker._manifest)  # copy previous hashes
```

For incremental backup, loads the previous snapshot's manifest (hash map) so that unchanged resources are still skipped even though they're in a new directory.

Runs each extractor sequentially (not parallel — avoids throttling Azure). Writes `backup_summary.json` with counts and snapshot path.

---

## 15. `backend/services/restore.py`

### `_rewrite_resource(resource, source_workspace, target_workspace, ...)` — Cross-Tenant ID Rewriting

```python
raw = json.dumps(resource)
raw = raw.replace(source_workspace, target_workspace)
raw = raw.replace(source_subscription, target_subscription)
raw = raw.replace(source_rg, target_rg)
return json.loads(raw)
```

When restoring to a different workspace (cross-tenant migration), all ARM IDs and workspace references in the JSON must be updated. This simple string-replace approach works because ARM resource IDs follow a predictable pattern.

### `_put_path(rtype, name)` — ARM PUT Path Map

Maps resource type folder names to their ARM PUT endpoints:
- `scheduledRules/nrtRules/fusionRules/microsoftRules` → `/alertRules/{name}`
- `automationRules` → `/automationRules/{name}`
- `watchlists` → `/watchlists/{name}`
- etc.

### `restore_from_snapshot(job_id, snapshot_path, resource_types, dry_run)` — Main Restore

Iterates over resource type directories in the snapshot. For each `.json` file, optionally rewrites IDs and calls `call_sentinel_mgmt_api_async(path, method="PUT", body=resource)`. `dry_run=True` increments the counter without making any API calls — lets users preview what would be restored.

---

## 16. `backend/services/file_tracker.py`

Change detection for incremental backups using SHA-256 content hashing.

### `FileTracker` Class

```python
class FileTracker:
    def __init__(self, snapshot_dir: str):
        self.manifest_path = self.snapshot_dir / "manifest.json"
        self._manifest: dict[str, dict] = {}
        self._load()  # reads existing manifest.json if present
```

### Key Methods

**`hash_content(content)`** — `hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()`. `sort_keys=True` ensures consistent hashing regardless of dict key order.

**`is_changed(resource_id, content)`** — computes hash of new content, compares to stored hash. Returns `True` if different (or not seen before).

**`record(resource_id, resource_type, file_path, content)`** — stores the new hash in `_manifest`.

**`save()`** — writes `_manifest` to `manifest.json`.

**`diff(other)`** — compares two trackers: returns `{"added": [...], "removed": [...], "changed": [...], "unchanged": N}`. Used by `compare_backup_snapshots` tool.

---

## 17. `backend/services/keyvault.py`

Optional. If `AZURE_KEYVAULT_URL` is set, secrets can be fetched from Azure Key Vault instead of `.env`.

```python
_client = None

def _get_client() -> SecretClient:
    global _client
    if _client is None:
        vault_url = os.environ.get("AZURE_KEYVAULT_URL")
        _client = SecretClient(vault_url=vault_url, credential=get_credential())
    return _client

def get_secret(name: str) -> str:
    return _get_client().get_secret(name).value
```

Lazy singleton (same pattern as auth.py). Uses the same credential from `get_credential()`. Not currently wired into the main application flow — available for custom scripting or future integration.

---

## 18. `backend/core/investigator.py`

Pure data model definitions — no business logic, no HTTP calls.

### `@dataclass` Classes

| Dataclass | Fields |
|-----------|--------|
| `InvestigationConfig` | workspace_id, tenant_id, API tokens, output_dir |
| `AnomalyFinding` | detected_date, upn, anomaly_type, value, severity, country, city, novelty flags, artifact_hits |
| `IPIntelligence` | ip, city, region, country, org, asn, timezone, risk_level, abuse_score, is_vpn, is_whitelisted, threat fields, anomaly context |
| `UserProfile` | display_name, upn, job_title, department, office_location, account_enabled, user_type |
| `MFAStatus` | mfa_enabled, methods_count, methods, has_fido2, has_authenticator |
| `DeviceInfo` | display_name, os, trust_type, is_compliant, last_sign_in |
| `RiskDetection` | risk_event_type, state, level, detail, dates, ip, location |
| `RiskySignIn` | sign_in_id, dates, app, ip, location, risk_state, risk_level, error details |
| `DLPEvent` | time, user, device, ip, rule_name, file_name, operation, target |
| `UserRiskProfile` | risk_level, risk_state, risk_detail, last_updated, is_deleted |
| `InvestigationResult` | **All of the above** + signin_events, audit_events, office_events, security_alerts, risk_level, risk_factors, mitigating_factors, recommendations, kql_queries, result_counts |

`InvestigationResult.to_dict()` calls `asdict(self)` from `dataclasses` — converts the entire nested structure to a plain dict for JSON serialization.

### `SecurityInvestigator` Class

The original (legacy) investigation class that uses direct HTTP calls via `requests.Session`. The modern async backend uses `services/investigation.py` instead. `SecurityInvestigator` is kept for `backend/scripts/` utilities.

---

## 19. `backend/core/enrich_ips.py`

### `ABUSE_CATEGORIES` Dict

Maps AbuseIPDB category IDs (1–23) to human-readable names (e.g., `7: "Phishing"`, `18: "Brute-Force"`, `22: "SSH"`). Used when formatting AbuseIPDB abuse reports.

### `load_config()` — Token Loading

Reads from `config.json` then overrides with env vars (`IPINFO_TOKEN`, `ABUSEIPDB_TOKEN`, `VPNAPI_TOKEN`, `SHODAN_TOKEN`). Also calls `load_dotenv()` pointing at the project root's `.env` file.

### `enrich_single_ip(ip, config)` — Single IP Enrichment

Queries 4 APIs sequentially for one IP:

**1. IPInfo.io** — geo (city, country, region), ASN, org, timezone, lat/lon. Free tier works without token (rate-limited).

**2. VPN API (vpnapi.io)** — detects VPN, proxy, Tor, hosting/relay. Token required for full data.

**3. AbuseIPDB** — abuse confidence score (0-100%), total reports count, recent report comments, ISP, usage type. Requires API key.

**4. Shodan** — open ports list, service fingerprints (product/version), detected OS, CVE IDs, hostnames, CPEs, tags (`"honeypot"`, `"c2"`, etc.). Requires API key.

Returns a flat dict with all fields. Missing/error values default to `"Unknown"`, `False`, `0`, or `[]`.

### `enrich_ips(ips, config, max_workers)` — Parallel Enrichment

```python
def enrich_ips(ips, config=None, max_workers=5):
    if config is None:
        config = load_config()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(enrich_single_ip, ip, config): ip for ip in ips}
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"ip": futures[future], "error": str(e), ...})
    return results
```

Runs `enrich_single_ip` for each IP in a thread pool. `max_workers=5` means 5 IPs enriched simultaneously. `as_completed` returns results as they finish (fastest IPs appear first). Individual IP failures don't crash the whole batch — caught and returned as error dicts.

---

## 20. `backend/core/report_generator.py`

### `CompactReportGenerator` Class

Generates self-contained HTML reports from an `InvestigationResult` object.

**`generate(result, output_path)`** — main entry point. Creates the output directory if needed, calls `_generate_html(result)` to produce the HTML string, writes it to a file, returns the path.

Default output path: `reports/user-investigations/Investigation_Report_Compact_{username}_{timestamp}.html`

**`_generate_html(result)`** — constructs the complete HTML document. Two-column layout with:
- Header with risk level badge (color-coded)
- User profile + MFA status card
- Anomaly findings table
- IP intelligence cards with badges (🚨 THREAT, ⚠️ RISKY, ANOMALY, PRIMARY, ACTIVE)
- Sign-in statistics
- Incident list
- Identity Protection data
- Devices table

**`_get_ip_category_badges(categories, size)`** — generates HTML badge spans for IP categories. Sorts by severity (threat > risky > anomaly > primary > active) and renders color-coded `<span>` elements.

**`_get_current_user()` / `_get_machine_name()`** — stamped in the report footer for audit trail.

---

## 21. `backend/routers/`

### `chat.py` — ARIA Chat Endpoint

**`GET /api/chat/status`** → `get_llm_status()` — returns `{"available": true, "provider": "Azure Anthropic", "model": "claude-sonnet-4-6"}`.

**`POST /api/chat/upload`** — accepts PDF or text file upload. Uses `pypdf.PdfReader` to extract text page-by-page (up to 60,000 chars). Returns `{"status": "success", "text": "...", "pages": N}`. The extracted text is inserted into the chat context so ARIA can answer questions about the document.

**`POST /api/chat`** — the main agentic chat endpoint:
```python
history = [{"role": "system", "content": SYSTEM_PROMPT}]
for msg in req.messages:
    history.append({"role": msg.role, "content": msg.content})

async def event_stream():
    async for chunk in stream_chat(history, TOOLS, execute_tool, model=req.model):
        yield chunk.encode("utf-8")

return StreamingResponse(event_stream(), media_type="text/event-stream", ...)
```
Injects the system prompt, then streams SSE chunks from `stream_chat`. Headers `X-Accel-Buffering: no` and `Cache-Control: no-cache` prevent Nginx/proxies from buffering the stream.

---

### `investigations.py` — Investigation Jobs

**`POST /api/investigations`** — creates a job, spawns `asyncio.create_task(run_job(...))`, returns `{"job_id": "...", "status": "pending"}` immediately. The investigation runs in the background.

**`GET /api/investigations/{job_id}`** — polls job status and result.

**`WS /api/investigations/ws/{job_id}`** — WebSocket for real-time progress:
1. Accepts connection
2. Sends all buffered updates already in `job.updates`
3. Streams new updates via `job_svc.subscribe(job_id)` async generator
4. Sends `{"phase": "ping"}` keepalives every 60 seconds
5. Closes when job completes or client disconnects

**`POST /api/investigations/analyze-incident`** — single-turn LLM analysis of a specific incident. Builds a structured prompt with incident details + investigation context, calls `llm_svc.complete()`, returns the analysis text.

**`POST /api/investigations/export-html-report`** + **`GET /api/investigations/export-html-report/{id}`** — async HTML report export. Creates a job, runs `generate_html_report` in the thread pool. Poll the GET endpoint; when `status == "completed"`, returns the HTML file with `Content-Disposition: attachment`.

---

### `kql.py` — KQL Explorer

**`POST /api/kql`** — run a KQL query directly. Returns `{"columns": [...], "rows": [...], "row_count": N}`.

**`POST /api/kql/generate`** — natural language → KQL using LLM. Builds a detailed system prompt listing all valid Sentinel table names, then calls `llm.complete()`. Parses the JSON response `{"query": "...", "explanation": "..."}`.

**`POST /api/kql/smart-run`** — streams SSE log events. Runs the query; if it fails, asks the LLM to diagnose and fix it. Up to 4 retry attempts. The LLM receives the full error text and the original user intent, returns a corrected query + explanation. The browser sees each attempt and fix logged in real-time.

---

### `enrichment.py` — IP Enrichment

**`POST /api/enrich/ips`** — accepts up to 50 IPs. Creates a job, spawns async task that calls `enrich_ips.enrich_ips()` in the thread pool. Returns `{"job_id": "..."}`.

**`GET /api/enrich/ips/{job_id}`** — poll job. Returns `{"status": "...", "results": [...], "updates": [...]}`.

---

### `reports.py` — Report Browser

**`GET /api/reports`** — scans `settings.OUTPUT_DIR` recursively for `*.html` files, returns list with name, size, modification time, subdirectory.

**`GET /api/reports/{filename:path}`** — serves an HTML report. Uses `(report_dir / filename).resolve()` and verifies the resolved path starts with `report_dir.resolve()` — this prevents **path traversal attacks** (e.g., `../../../etc/passwd`).

**`POST /api/reports/export-pdf`** — converts HTML to PDF using `convert_html_to_pdf.html_to_pdf()`. Uses system temp files (not the reports directory) to avoid triggering Uvicorn's auto-reload on writes.

**`POST /api/reports/export-html`** — serves HTML content as a downloadable file with `Content-Disposition: attachment`.

---

### Other Routers (Summary)

| Router | Key Endpoints |
|--------|--------------|
| `analytics.py` | `GET /api/analytics/mcp-stats`, `/ingestion-trend`, `/incidents`, `/posture` — mock data with KQL fallback |
| `sentinel_health.py` | `GET /api/sentinel/health/overview`, `/connectors`, `/agents`, `/data-gaps`, `/ingestion-trend` |
| `entity_exposure.py` | `GET /api/entity-exposure/risky-users`, `/anomalous-behavior`, `/alert-entities`, `/risky-hosts`, `/overview` |
| `backup.py` (router) | `POST /api/backup/start` — thin delegator to `services/backup.run_backup` |
| `restore.py` (router) | `POST /api/restore/start` — thin delegator to `services/restore.restore_from_snapshot` |
| `analytics_rules.py` | CRUD for alert rules via ARM API |
| `automation.py` | Logic App (playbook) management |
| `incident_analytics.py` | Incident trend charts, MTTR, severity breakdown |
| `hunting.py` | Saved KQL hunting queries management |
| `workbooks.py` | Workbook listing via ARM API |
| `geomap.py` | Generates Leaflet.js map HTML from sign-in geo data |
| `mitre.py` | MITRE ATT&CK coverage analysis |
| `dcr.py` | Data Collection Rule assessment |
| `threat_feed.py` | ThreatIntelIndicators feed |

---

## 22. `frontend/src/App.tsx`

The **root React component** and application router. Uses `useState` — no React Router library.

```typescript
type Page = 'chat' | 'dashboard' | 'investigate' | 'reports' | 'enrich' | 'kql' | 'settings'
    | 'mitre' | 'geomap' | 'analytics' | 'sentinel-health' | 'automation' | 'rules'
    | 'incidents' | 'entities' | 'hunting' | 'workbooks' | 'backup' | 'restore'
    | 'snapshots' | 'dcr' | 'threat-feed';

function App() {
  const [page, setPage] = useState<Page>('chat');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  ...
```

`Page` is a TypeScript union type — limits valid page names to this exact list (typos cause compile-time errors). `useState<Page>('chat')` initializes on the Chat page.

**Authentication gate:**
```typescript
if (!isAuthenticated) {
    return <Login onLogin={() => setIsAuthenticated(true)} />;
}
```
Before login, only `<Login>` is rendered. After login, the full `<Layout>` with the current page is shown.

**`renderPage()`** — a switch statement that returns the correct page component based on the current `page` state. Each page is a lazy import at the top of the file.

**`navigate(p)`** — sets `page` to the new value. All navigation in the app calls `onNavigate(page)` which traces back to `setPage`.

**Layout wrapping:**
```typescript
return (
    <Layout currentPage={page} onNavigate={navigate} onLogout={handleLogout}>
        {renderPage()}
    </Layout>
);
```
`Layout` provides the sidebar navigation, header, and scroll container. The current page component renders as `children` inside the content area.

---

## 23. `frontend/src/api/client.ts`

All TypeScript interfaces and API functions. The single source of truth for what data the frontend receives from the backend.

### Axios Instances

```typescript
export const api = axios.create({ baseURL: '/api' });
export const http = axios.create({});
```

`api` is used for all backend calls (baseURL `/api` means `/api/chat` etc.). `http` is for calls to external URLs (not currently used but available).

### TypeScript Interfaces

All response shapes are typed. Key interfaces:

| Interface | Represents |
|-----------|-----------|
| `Config` | Response from `GET /api/config` |
| `Job` | A background job with status/result |
| `InvestigationResult` | Complete investigation result dict |
| `UserProfile` | Entra ID user profile |
| `MFAStatus` | MFA methods |
| `Device` | Registered device |
| `IPIntelligence` | Enriched IP data |
| `AnomalyFinding` | A Sentinel anomaly |
| `BackupSnapshot` | A backup snapshot |
| `LLMStatus` | LLM provider availability |

### API Functions

Every backend endpoint has a corresponding typed function. Pattern:
```typescript
export const startInvestigation = (req: InvestigationRequest) =>
    api.post<{ job_id: string }>('/investigations', req).then(r => r.data);

export const getInvestigation = (jobId: string) =>
    api.get<Job>(`/investigations/${jobId}`).then(r => r.data);
```

Using `.then(r => r.data)` unwraps the Axios response so callers get the typed payload directly.

---

## 24. `frontend/src/pages/`

23 page components, each focused on one area:

| Page | What It Shows |
|------|--------------|
| `Login.tsx` | Username/password form. Calls `POST /api/auth/login`. |
| `Chat.tsx` | ARIA chat interface. Sends messages, parses SSE stream (`data: {...}` events), shows tool calls in real-time, renders markdown. Supports file upload via drag-and-drop. |
| `Dashboard.tsx` | Overview with stats cards. Calls analytics + sentinel health endpoints. Clickable cards navigate to detail pages. |
| `Investigate.tsx` | User investigation form. Shows WebSocket progress log, then investigation result with anomalies, IPs, incidents, MFA, devices. Has incident analysis (LLM) and HTML report export. |
| `Reports.tsx` | File browser for generated reports. Preview + download + PDF export. |
| `Enrich.tsx` | IP enrichment form. Polls job result, shows enriched IP cards. |
| `KQLExplorer.tsx` | KQL editor. Run queries, generate KQL from natural language, smart-run with AI retry. Table result viewer. |
| `Settings.tsx` | Settings form behind settings-password gate. Hot-reloads env vars. |
| `MitreCoverage.tsx` | MITRE ATT&CK heatmap visualization. |
| `GeoMap.tsx` | Renders geomap HTML from `/api/geomap`. |
| `Analytics.tsx` | Charts: ingestion trend, incident distribution, posture score. |
| `SentinelHealth.tsx` | Connector health status, data gap table, agent status. |
| `AutomationStats.tsx` | Logic App playbook management. |
| `AnalyticsRules.tsx` | Alert rule list with CRUD operations. |
| `IncidentAnalytics.tsx` | Incident trend charts, MTTR, severity breakdown. |
| `EntityExposure.tsx` | Risky users, anomalous behavior, risky hosts. |
| `ThreatHunting.tsx` | Saved hunting queries browser and runner. |
| `WorkbookCoverage.tsx` | Workbook coverage assessment. |
| `Backup.tsx` | Backup configuration form, start backup, live progress log. |
| `Restore.tsx` | Restore from snapshot, dry-run support. |
| `Snapshots.tsx` | List available snapshots with resource counts. |
| `DcrAssessment.tsx` | Data Collection Rule health assessment. |
| `ThreatFeed.tsx` | Threat intelligence indicator browser. |

---

## 25. `Dockerfile`

Two-stage build to produce a small production image.

```dockerfile
# ── Stage 1: Build React/Vite frontend ────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci --silent        # install exactly what's in package-lock.json
COPY frontend/ ./
RUN npm run build          # outputs to /build/frontend/dist/

# ── Stage 2: Python backend + bundled frontend ────────────────────────────────
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ ./backend/
COPY --from=frontend-build /build/frontend/dist ./frontend/dist  # copy only dist, not node_modules
RUN mkdir -p data/reports data/jobs data/temp
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Stage 1 (Node):** Installs npm dependencies, compiles TypeScript/React to static HTML/JS/CSS in `dist/`. The entire `node_modules` (hundreds of MB) stays in Stage 1 and is discarded.

**Stage 2 (Python):** Installs Python dependencies, copies backend source, copies only the compiled `dist/` from Stage 1. Creates `data/` runtime directories. Runs Uvicorn (ASGI server) on port 8000.

**Why two stages?** The final image only contains Python + compiled frontend. No Node.js, no source TypeScript, no `node_modules`. Results in a much smaller image (~200MB vs ~1GB).

---

## 26. Data Flow Diagrams

### ARIA Chat with Tool Calling

```
Browser                  FastAPI (chat.py)           services/llm.py          Azure Anthropic
  │                            │                            │                        │
  │──POST /api/chat ──────────►│                            │                        │
  │                            │──stream_chat(msgs, TOOLS)─►│                        │
  │                            │                            │──POST (streaming)──────►│
  │◄── SSE: text delta ────────│◄── {"type":"text"} ────────│◄── content_block_delta─│
  │◄── SSE: text delta ────────│                            │                        │
  │                            │                            │◄── tool_use block ─────│
  │◄── SSE: tool_call ─────────│◄── {"type":"tool_call"}───│                        │
  │                            │──execute_tool(name, args)─►│                        │
  │                            │   (calls KQL/Graph/etc.)   │                        │
  │◄── SSE: tool_result ───────│◄── {"type":"tool_result"} ─│                        │
  │                            │                            │──POST (with results)───►│
  │◄── SSE: text delta ────────│◄── text ───────────────────│◄── final answer ───────│
  │◄── SSE: done ──────────────│◄── {"type":"done"} ────────│                        │
```

### Investigation Workflow

```
Browser          investigations.py       investigation.py        Azure (parallel)
  │                    │                       │                        │
  │──POST /api/investigations ─►│              │                        │
  │◄── {job_id} ───────│        │              │                        │
  │                    │──create_task──────────►│                       │
  │──WS /ws/{job_id}──►│        │              │                        │
  │                    │        │──Graph: get_user ──────────────────────►
  │◄── progress: start │        │                                        │
  │                    │        │──asyncio.gather([9 KQL queries]) ──────►
  │◄── progress: queries        │                                        │
  │                    │        │──asyncio.gather([5 Graph calls]) ──────►
  │◄── progress: identity       │                                        │
  │                    │        │──ThreatIntelIndicators KQL ────────────►
  │◄── progress: threat_intel   │                                        │
  │                    │        │──enrich_ips() in thread pool ──────────►
  │◄── progress: enrichment     │                                        │
  │                    │        │──_compute_risk() ── score → CRITICAL/HIGH/...
  │◄── progress: complete       │
  │──GET /api/investigations/{id}►─────── returns full result ─────────────►
```

### Backup Flow

```
User                   backup.py (router)        services/backup.py       Azure ARM API
  │                          │                         │                       │
  │──POST /api/backup/start─►│                         │                       │
  │◄── {job_id} ─────────────│                         │                       │
  │                          │──create_task(run_job)──►│                       │
  │                          │                         │──GET /alertRules ─────►│
  │                          │                         │◄── rules list ────────│
  │                          │                         │  for each changed rule:│
  │                          │                         │  write {name}.json     │
  │                          │                         │──GET /workbooks ───────►│
  │                          │                         │  ... (12 resource types)
  │                          │                         │──save manifest.json    │
  │──GET /api/backup/{job_id}►──────────── result ─────────────────────────────►
```

---

*This document covers every file in the Sentinel Vigil project. For line-by-line details on specific files, see the individual deep-dive documents in `docs/00_main_py_deep_dive.md` through `docs/05_backend_services_backup_restore.md`.*
