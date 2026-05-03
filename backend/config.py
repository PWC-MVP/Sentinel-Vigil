"""
Configuration loader for Sentinel Vigil Backend.
Reads config.json and .env from the project root.
"""
import json
import os
from pathlib import Path
from dotenv import load_dotenv

# Root of the project (parent of the backend/ folder)
ROOT = Path(__file__).parent.parent

# Load .env if present
load_dotenv(ROOT / ".env", override=True)


def _load_config_json() -> dict:
    config_path = ROOT / "config.json"
    if not config_path.exists():
        return {}
    with open(config_path, "r") as f:
        return json.load(f)


_raw = _load_config_json()


class Config:
    # ── Azure / Sentinel ────────────────────────────────────────
    SENTINEL_WORKSPACE_ID: str = os.getenv("SENTINEL_WORKSPACE_ID") or _raw.get("sentinel_workspace_id", "")
    TENANT_ID: str = os.getenv("TENANT_ID") or os.getenv("AZURE_TENANT_ID") or _raw.get("tenant_id", "")
    SUBSCRIPTION_ID: str = os.getenv("SUBSCRIPTION_ID") or _raw.get("subscription_id", "")

    # Azure MCP section (resource group / workspace name)
    _azure_mcp = _raw.get("azure_mcp", {})
    RESOURCE_GROUP: str = os.getenv("RESOURCE_GROUP") or _azure_mcp.get("resource_group", "")
    WORKSPACE_NAME: str = os.getenv("WORKSPACE_NAME") or _azure_mcp.get("workspace_name", "")

    # ── Threat-intel API tokens ──────────────────────────────────
    # env vars take precedence over config.json values
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN") or _raw.get("ipinfo_token") or ""
    ABUSEIPDB_TOKEN: str = os.getenv("ABUSEIPDB_TOKEN") or _raw.get("abuseipdb_token") or ""
    VPNAPI_TOKEN: str = os.getenv("VPNAPI_TOKEN") or _raw.get("vpnapi_token") or ""
    SHODAN_TOKEN: str = os.getenv("SHODAN_TOKEN") or _raw.get("shodan_token") or ""

    # ── Report output ────────────────────────────────────────────
    OUTPUT_DIR: Path = ROOT / _raw.get("output_dir", "reports")

    # ── Optional label/SIT mappings ─────────────────────────────
    SIT_MAPPING: dict = {
        k: v for k, v in _raw.get("sit_mapping", {}).items()
        if not k.startswith("__")
    }
    LABEL_MAPPING: dict = {
        k: v for k, v in _raw.get("label_mapping", {}).items()
        if not k.startswith("__")
    }

    # ── App settings ─────────────────────────────────────────────
    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    # CORS_ORIGINS env var: comma-separated list of extra allowed origins.
    # In production (Container Apps) the frontend is same-origin, so this is
    # only needed for local dev or cross-origin deployments.
    _extra = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    CORS_ORIGINS: list[str] = _extra or [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # ── Settings page access password ───────────────────────────
    SETTINGS_PASSWORD: str = os.getenv("SETTINGS_PASSWORD", "changeme")

    @classmethod
    def reload(cls) -> None:
        """Reload all values from .env and config.json without restarting."""
        load_dotenv(ROOT / ".env", override=True)
        raw = _load_config_json()

        cls.SENTINEL_WORKSPACE_ID = os.getenv("SENTINEL_WORKSPACE_ID") or raw.get("sentinel_workspace_id", "")
        cls.TENANT_ID = os.getenv("TENANT_ID") or os.getenv("AZURE_TENANT_ID") or raw.get("tenant_id", "")
        cls.SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID") or raw.get("subscription_id", "")

        azure_mcp = raw.get("azure_mcp", {})
        cls.RESOURCE_GROUP = os.getenv("RESOURCE_GROUP") or azure_mcp.get("resource_group", "")
        cls.WORKSPACE_NAME = os.getenv("WORKSPACE_NAME") or azure_mcp.get("workspace_name", "")

        cls.IPINFO_TOKEN = os.getenv("IPINFO_TOKEN") or raw.get("ipinfo_token") or ""
        cls.ABUSEIPDB_TOKEN = os.getenv("ABUSEIPDB_TOKEN") or raw.get("abuseipdb_token") or ""
        cls.VPNAPI_TOKEN = os.getenv("VPNAPI_TOKEN") or raw.get("vpnapi_token") or ""
        cls.SHODAN_TOKEN = os.getenv("SHODAN_TOKEN") or raw.get("shodan_token") or ""

        output_dir = raw.get("output_dir", "reports")
        cls.OUTPUT_DIR = ROOT / output_dir

        cls.SIT_MAPPING = {k: v for k, v in raw.get("sit_mapping", {}).items() if not k.startswith("__")}
        cls.LABEL_MAPPING = {k: v for k, v in raw.get("label_mapping", {}).items() if not k.startswith("__")}

        cls.SETTINGS_PASSWORD = os.getenv("SETTINGS_PASSWORD", "changeme")

        _extra = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
        cls.CORS_ORIGINS = _extra or [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]

    @classmethod
    def is_valid(cls) -> bool:
        return bool(cls.SENTINEL_WORKSPACE_ID and cls.TENANT_ID)

    @classmethod
    def api_status(cls) -> dict:
        """Return which API tokens are configured (without exposing values)."""
        return {
            "ipinfo": bool(cls.IPINFO_TOKEN),
            "abuseipdb": bool(cls.ABUSEIPDB_TOKEN),
            "vpnapi": bool(cls.VPNAPI_TOKEN),
            "shodan": bool(cls.SHODAN_TOKEN),
        }

    @classmethod
    def to_public_dict(cls) -> dict:
        """Serializable config view safe to send to frontend."""
        return {
            "sentinel_workspace_id": cls.SENTINEL_WORKSPACE_ID,
            "workspace_name": cls.WORKSPACE_NAME,
            "resource_group": cls.RESOURCE_GROUP,
            "tenant_id": cls.TENANT_ID,
            "subscription_id": cls.SUBSCRIPTION_ID,
            "output_dir": str(cls.OUTPUT_DIR),
            "apis_configured": cls.api_status(),
            "config_valid": cls.is_valid(),
        }


settings = Config()
