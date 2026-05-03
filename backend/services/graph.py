"""
Microsoft Graph API service.
Replaces `microsoft_graph_get` MCP tool calls.
"""
import asyncio
import logging
from typing import Any

import httpx
from azure.identity import DefaultAzureCredential

from backend.auth import get_credential
from backend.services.token_manager import TokenManager

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def _get_token(credential: DefaultAzureCredential) -> str:
    return TokenManager.get(credential, GRAPH_SCOPE).get_token()


async def graph_get(path: str, version: str = "v1.0") -> dict[str, Any]:
    """
    Execute a Microsoft Graph GET request.
    e.g. path = "/users/user@domain.com"

    Args:
        path: Graph API path (with leading slash)
        version: "v1.0" or "beta"

    Returns:
        Parsed JSON response dict
    """
    cred = get_credential()
    url = f"{GRAPH_BASE}/{version}{path}"
    loop = asyncio.get_event_loop()

    async def _do_get(token: str):
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.get(url, headers={"Authorization": f"Bearer {token}"})

    token = await loop.run_in_executor(None, lambda: _get_token(cred))
    resp = await _do_get(token)

    if resp.status_code == 401:
        # Force token refresh and retry once
        TokenManager.get(cred, GRAPH_SCOPE)._token = None
        token = await loop.run_in_executor(None, lambda: _get_token(cred))
        resp = await _do_get(token)

    if resp.status_code == 404:
        return {}
    if not resp.is_success:
        logger.error("Graph API error %s: %s — %s", resp.status_code, url, resp.text[:300])
        raise RuntimeError(f"Graph API returned {resp.status_code}: {resp.text[:200]}")

    return resp.json()


# ── Convenience wrappers ────────────────────────────────────────────────────


async def get_user(upn: str) -> dict:
    """Get Entra ID user profile."""
    fields = "id,displayName,userPrincipalName,mail,userType,jobTitle,department,officeLocation,accountEnabled,onPremisesSecurityIdentifier"
    return await graph_get(f"/users/{upn}?$select={fields}")


async def get_mfa_methods(user_id: str) -> list[dict]:
    """Get authentication methods for a user."""
    result = await graph_get(f"/users/{user_id}/authentication/methods?$top=10")
    return result.get("value", [])


async def get_user_devices(user_id: str) -> list[dict]:
    """Get devices registered or owned by a user."""
    fields = "id,deviceId,displayName,operatingSystem,operatingSystemVersion,registrationDateTime,isCompliant,isManaged,trustType,approximateLastSignInDateTime"
    result = await graph_get(
        f"/users/{user_id}/ownedDevices?$select={fields}&$orderby=approximateLastSignInDateTime desc&$top=10"
    )
    return result.get("value", [])


async def get_user_risk_profile(user_id: str) -> dict:
    """Get Identity Protection risk profile for a user."""
    return await graph_get(f"/identityProtection/riskyUsers/{user_id}")


async def get_risk_detections(user_id: str) -> list[dict]:
    """Get Identity Protection risk detections for a user."""
    result = await graph_get(
        f"/identityProtection/riskDetections?$filter=userId eq '{user_id}'"
        "&$select=id,detectedDateTime,riskEventType,riskLevel,riskState,riskDetail,ipAddress,location,activity,activityDateTime"
        "&$orderby=detectedDateTime desc&$top=10"
    )
    return result.get("value", [])


async def get_risky_signins(user_id: str) -> list[dict]:
    """Get risky sign-ins from Identity Protection (beta endpoint only)."""
    try:
        result = await graph_get(
            f"/auditLogs/signIns?$filter=userId eq '{user_id}' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')"
            "&$select=id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,riskState,riskLevelDuringSignIn,riskEventTypes_v2,riskDetail,status"
            "&$orderby=createdDateTime desc&$top=10",
            version="beta",
        )
        return result.get("value", [])
    except Exception as e:
        logger.warning("Risky sign-ins fetch failed (needs beta): %s", e)
        return []
