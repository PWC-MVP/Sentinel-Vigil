"""Azure Key Vault integration for secure secret management (optional)."""
import os
from azure.keyvault.secrets import SecretClient
from backend.auth import get_credential

_client = None


def _get_client() -> SecretClient:
    global _client
    if _client is None:
        vault_url = os.environ.get("AZURE_KEYVAULT_URL")
        if not vault_url:
            raise RuntimeError("AZURE_KEYVAULT_URL not set")
        _client = SecretClient(vault_url=vault_url, credential=get_credential())
    return _client


def get_secret(name: str) -> str:
    return _get_client().get_secret(name).value


def set_secret(name: str, value: str) -> None:
    _get_client().set_secret(name, value)
