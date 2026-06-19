"""
Microsoft Sentinel / Log Analytics KQL query service.
Replaces the `mcp_sentinel-data_query_lake` MCP tool.
"""
import logging
import asyncio
from datetime import timedelta, datetime
from typing import Any

import requests as _requests
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.core.exceptions import HttpResponseError

from backend.auth import get_credential
from backend.config import settings
from backend.services.token_manager import TokenManager

logger = logging.getLogger(__name__)

# ── API version map (per resource type) ─────────────────────────────────────

_API_VERSIONS: dict[str, str] = {
    "alertrules":         "2023-02-01",
    "automationrules":    "2025-01-01-preview",
    "workbooks":          "2022-04-01",
    "watchlists":         "2023-02-01",
    "summaryrules":       "2025-07-01",
    "savedSearches":      "2020-08-01",
    "huntingQueries":     "2023-02-01",
    "threatintelligence": "2024-03-01",
    "dataConnectors":     "2023-02-01",
    "metadata":           "2023-02-01",
}
_DEFAULT_API_VERSION = "2023-02-01"


def _api_version(resource_type: str) -> str:
    return _API_VERSIONS.get(resource_type, _DEFAULT_API_VERSION)


def _client() -> LogsQueryClient:
    return LogsQueryClient(get_credential())


def _rows_to_dicts(result) -> list[dict]:
    """Convert azure-monitor-query rows to plain dicts."""
    rows = []
    for row in result.tables[0].rows:
        rows.append(dict(zip(result.tables[0].columns, row)))
    return rows


async def run_kql(
    query: str,
    workspace_id: str | None = None,
    days: int = 30,
) -> dict[str, Any]:
    """
    Execute a KQL query against the configured Log Analytics workspace.

    Args:
        query: KQL query string
        workspace_id: Override workspace ID (defaults to config.json value)
        days: How many days to look back (for the implicit timespan)

    Returns:
        { columns, rows, row_count }
    """
    ws_id = workspace_id or settings.SENTINEL_WORKSPACE_ID
    if not ws_id:
        raise ValueError("No Sentinel workspace ID configured in config.json")

    client = _client()
    try:
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.query_workspace(
                workspace_id=ws_id,
                query=query,
                timespan=timedelta(days=days),
            )
        )

        if response.status == LogsQueryStatus.FAILURE:
            raise RuntimeError(f"KQL query failed: {response.partial_error}")

        # LogsQueryPartialResult (PARTIAL status) uses .partial_data; full result uses .tables
        if response.status == LogsQueryStatus.PARTIAL:
            tables = response.partial_data
        else:
            tables = response.tables

        if not tables:
            return {"columns": [], "rows": [], "row_count": 0}

        table = tables[0]
        columns = [getattr(col, "name", col) for col in table.columns]
        rows = [
            {columns[i]: _serialize(val) for i, val in enumerate(row)}
            for row in table.rows
        ]

        return {
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
        }

    except HttpResponseError as e:
        logger.error("KQL HTTP error: %s", e)
        raise RuntimeError(f"KQL query failed: {e.message}") from e


async def list_workspaces() -> list[dict]:
    """
    List available Sentinel workspaces using their workspace IDs.
    For now returns the single configured workspace.
    Could be extended to query Azure Resource Manager for all workspaces.
    """
    if not settings.SENTINEL_WORKSPACE_ID:
        return []
    return [
        {
            "id": settings.SENTINEL_WORKSPACE_ID,
            "name": settings.WORKSPACE_NAME or "Sentinel Workspace",
            "resource_group": settings.RESOURCE_GROUP,
        }
    ]


def _serialize(val: Any) -> Any:
    """Make a KQL result value JSON-serializable."""
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, timedelta):
        return str(val)
    return val


# ── Azure Sentinel Management REST API ───────────────────────────────────────

_MGMT_BASE = "https://management.azure.com"
_MGMT_SCOPE = f"{_MGMT_BASE}/.default"
_SENTINEL_API_VERSION = _DEFAULT_API_VERSION


def _sentinel_mgmt_base() -> str:
    """Build the base URL for the Sentinel management API from config."""
    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    ws  = settings.WORKSPACE_NAME
    if not all([sub, rg, ws]):
        raise ValueError(
            "Missing config: subscription_id, resource_group, and "
            "azure_mcp.workspace_name must all be set in config.json"
        )
    return (
        f"{_MGMT_BASE}/subscriptions/{sub}"
        f"/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/providers/Microsoft.SecurityInsights"
    )


def call_sentinel_mgmt_api(
    path: str,
    api_version: str = _DEFAULT_API_VERSION,
    method: str = "GET",
    body: dict | None = None,
    resource_type: str | None = None,
) -> dict:
    """
    Call the Azure Sentinel management REST API (synchronous).

    Handles nextLink pagination automatically — all pages are merged into a
    single ``{"value": [...]}`` response.

    Args:
        path:          Path after the Sentinel base URL, e.g. ``/alertRules``
        api_version:   API version query param (default 2023-02-01)
        method:        HTTP method (GET / POST / PUT / DELETE)
        body:          Optional JSON request body for non-GET methods
        resource_type: If set, selects the appropriate api_version from the map

    Returns:
        Merged JSON dict, always containing a ``"value"`` list for list calls.
    """
    if resource_type:
        api_version = _api_version(resource_type)

    cred = get_credential()
    token_mgr = TokenManager.get(cred, _MGMT_SCOPE)

    def _do_request() -> dict:
        token = token_mgr.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }
        base     = _sentinel_mgmt_base()
        sep      = "&" if "?" in path else "?"
        url: str | None = f"{base}{path}{sep}api-version={api_version}"

        all_items: list = []
        last_response: dict = {}

        while url:
            if method.upper() == "GET":
                resp = _requests.get(url, headers=headers, timeout=30)
            else:
                resp = _requests.request(method.upper(), url, headers=headers,
                                         json=body, timeout=30)
            if resp.status_code == 401:
                # Force token refresh and retry once (recursive call resolves new token)
                token_mgr._token = None
                return _do_request()
            resp.raise_for_status()
            data          = resp.json()
            last_response = data
            all_items.extend(data.get("value", []))
            url = data.get("nextLink")

        if "value" in last_response or all_items:
            last_response["value"] = all_items
        return last_response

    return _do_request()


async def call_sentinel_mgmt_api_async(
    path: str,
    api_version: str = _DEFAULT_API_VERSION,
    method: str = "GET",
    body: dict | None = None,
    resource_type: str | None = None,
) -> dict:
    """Async wrapper around call_sentinel_mgmt_api (runs in thread pool)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: call_sentinel_mgmt_api(path, api_version, method, body, resource_type),
    )


async def call_azure_mgmt_api_async(
    path: str,
    api_version: str,
    params: dict | None = None,
    method: str = "GET",
    body: dict | None = None,
) -> dict:
    """
    Call any Azure management REST API by full path (does NOT prepend the
    Sentinel workspace prefix).  ``path`` should start with ``/subscriptions/``
    or ``/providers/``.

    Extra query parameters can be passed via ``params`` (e.g.
    ``{"category": "sentinel"}``).  Handles nextLink pagination automatically.
    Supports GET and PUT methods.
    """
    def _call() -> dict:
        cred    = get_credential()
        token_mgr = TokenManager.get(cred, _MGMT_SCOPE)

        def _do():
            token   = token_mgr.get_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type":  "application/json",
            }
            extra = ""
            if params:
                extra = "&".join(f"{k}={v}" for k, v in params.items())
            sep = "&" if "?" in path else "?"
            base_url = (
                f"{_MGMT_BASE}{path}{sep}api-version={api_version}"
                + (f"&{extra}" if extra else "")
            )

            if method.upper() != "GET":
                r = _requests.request(method.upper(), base_url, headers=headers, json=body, timeout=60)
                if r.status_code == 401:
                    token_mgr._token = None
                    return _do()
                r.raise_for_status()
                return r.json()

            url: str | None = base_url
            all_items: list = []
            last_resp:  dict = {}
            while url:
                r = _requests.get(url, headers=headers, timeout=30)
                if r.status_code == 401:
                    token_mgr._token = None
                    return _do()
                r.raise_for_status()
                d          = r.json()
                last_resp  = d
                all_items.extend(d.get("value", []))
                url = d.get("nextLink")
            if "value" in last_resp or all_items:
                last_resp["value"] = all_items
            return last_resp

        return _do()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _call)
