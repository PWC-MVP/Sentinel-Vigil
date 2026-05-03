"""
Azure authentication helper.

Uses DefaultAzureCredential — automatically picks up:
  1. az login (cached CLI token — most common for this project)
  2. VS Code Azure extension token
  3. AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID env vars
  4. Managed Identity (when deployed to Azure)
"""
from azure.identity import DefaultAzureCredential, AzureCliCredential, ClientSecretCredential
from azure.identity._exceptions import CredentialUnavailableError
import asyncio
import os
import logging

logger = logging.getLogger(__name__)

_credential: DefaultAzureCredential | None = None


def reset_credential() -> None:
    """Clear the cached credential so it is rebuilt on next use (call after .env changes)."""
    global _credential
    _credential = None


def get_credential():
    """Return an appropriate Azure credential, preferring service principal from env vars."""
    global _credential
    if _credential is None:
        client_id = (os.getenv("AZURE_CLIENT_ID") or "").strip()
        client_secret = (os.getenv("AZURE_CLIENT_SECRET") or "").strip()
        tenant_id = (os.getenv("AZURE_TENANT_ID") or os.getenv("TENANT_ID") or "").strip()

        if client_id and client_secret and tenant_id:
            _credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            _credential = DefaultAzureCredential(
                exclude_workload_identity_credential=False,
                exclude_managed_identity_credential=False,
            )
    return _credential


async def check_auth() -> dict:
    """
    Try to acquire a token for Log Analytics.
    Returns status dict for the /api/config endpoint.
    """
    try:
        cred = get_credential()
        loop = asyncio.get_event_loop()
        token = await loop.run_in_executor(
            None, lambda: cred.get_token("https://api.loganalytics.io/.default")
        )
        method = "ClientSecretCredential" if isinstance(cred, ClientSecretCredential) else "DefaultAzureCredential"
        return {
            "authenticated": True,
            "method": method,
            "token_expires": token.expires_on,
        }
    except CredentialUnavailableError as e:
        return {
            "authenticated": False,
            "error": str(e),
            "hint": "Ensure AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID are set in your .env file.",
        }
    except Exception as e:
        return {"authenticated": False, "error": str(e)}
