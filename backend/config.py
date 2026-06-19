"""
Configuration loader for Sentinel Vigil Backend.
Reads config.json and .env from the project root.
"""
import json
import os
from pathlib import Path
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

# Root of the project (parent of the backend/ folder)
ROOT = Path(__file__).parent.parent

# Load .env if present — no override so Container App env vars always win
load_dotenv(ROOT / ".env")


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
    TENANT_ID: str = os.getenv("AZURE_TENANT_ID") or os.getenv("TENANT_ID") or _raw.get("tenant_id", "")
    SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID") or os.getenv("SUBSCRIPTION_ID") or _raw.get("subscription_id", "")

    # Azure MCP section (resource group / workspace name)
    _azure_mcp = _raw.get("azure_mcp", {})
    RESOURCE_GROUP: str = (
        os.getenv("AZURE_LOGIC_APPS_RESOURCE_GROUP")
        or os.getenv("AZURE_RESOURCE_GROUP")
        or os.getenv("RESOURCE_GROUP")
        or _azure_mcp.get("resource_group", "")
    )
    WORKSPACE_NAME: str = (
        os.getenv("AZURE_WORKSPACE_NAME")
        or os.getenv("WORKSPACE_NAME")
        or _azure_mcp.get("workspace_name", "")
    )
    LOGIC_APP_NAMES: str = os.getenv("LOGIC_APP_NAMES", "")

    # ── Threat-intel API tokens ──────────────────────────────────
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN") or _raw.get("ipinfo_token") or ""
    ABUSEIPDB_TOKEN: str = os.getenv("ABUSEIPDB_TOKEN") or _raw.get("abuseipdb_token") or ""
    VPNAPI_TOKEN: str = os.getenv("VPNAPI_TOKEN") or _raw.get("vpnapi_token") or ""
    SHODAN_TOKEN: str = os.getenv("SHODAN_TOKEN") or _raw.get("shodan_token") or ""
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

    # ── Report output ────────────────────────────────────────────
    OUTPUT_DIR: Path = ROOT / (os.getenv("OUTPUT_DIR") or _raw.get("output_dir", "data/reports"))

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
    APP_HOST: str = os.getenv("HOST") or os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("PORT") or os.getenv("APP_PORT", "8000"))
    _extra = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    CORS_ORIGINS: list[str] = _extra or [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # ── Security ─────────────────────────────────────────────────
    API_KEY: str = os.getenv("API_KEY", "")
    MCP_API_KEY: str = os.getenv("MCP_API_KEY", "")
    SETTINGS_PASSWORD: str = os.getenv("SETTINGS_PASSWORD", "changeme")
    APP_USERNAME: str = os.getenv("APP_USERNAME", "admin")
    APP_PASSWORD: str = os.getenv("APP_PASSWORD", "PwC@y14")

    # ── LLM defaults ─────────────────────────────────────────────
    DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "claude-sonnet-4-6")
    AUTOMATION_DEFAULT_MODEL: str = os.getenv("AUTOMATION_DEFAULT_MODEL", "claude-sonnet-4-6")

    # ── Email via Microsoft Graph API ────────────────────────────
    GRAPH_MAIL_FROM: str = os.getenv("GRAPH_MAIL_FROM") or os.getenv("GRAPH_ADMIN_EMAIL", "")
    GRAPH_CLIENT_ID: str = os.getenv("GRAPH_CLIENT_ID") or os.getenv("AZURE_CLIENT_ID", "")
    GRAPH_CLIENT_SECRET: str = os.getenv("GRAPH_CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET", "")
    GRAPH_API_KEY: str = os.getenv("GRAPH_API_KEY", "")
    GRAPH_ADMIN_EMAIL: str = os.getenv("GRAPH_ADMIN_EMAIL", "")

    # ── Sentinel comment webhook (Logic App) ─────────────────────
    SENTINEL_COMMENT_WEBHOOK_URL: str = os.getenv("SENTINEL_COMMENT_WEBHOOK_URL", "")

    # ── VirusTotal ────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # ── Feature Flags ─────────────────────────────────────────────
    ENABLE_SENTINEL_MCP: bool = os.getenv("ENABLE_SENTINEL_MCP", "true").lower() == "true"
    ENABLE_VIRUSTOTAL_MCP: bool = os.getenv("ENABLE_VIRUSTOTAL_MCP", "true").lower() == "true"
    ENABLE_GRAPH_MCP: bool = os.getenv("ENABLE_GRAPH_MCP", "true").lower() == "true"
    ENABLE_LEARN_MCP: bool = os.getenv("ENABLE_LEARN_MCP", "false").lower() == "true"
    ENABLE_KQL_SEARCH_MCP: bool = os.getenv("ENABLE_KQL_SEARCH_MCP", "true").lower() == "true"
    ENABLE_ADVANCED_SENTINEL_MCP: bool = os.getenv("ENABLE_ADVANCED_SENTINEL_MCP", "true").lower() == "true"
    SHOW_TOKEN_USAGE: bool = os.getenv("SHOW_TOKEN_USAGE", "false").lower() == "true"

    # ── Job & Runtime Settings ────────────────────────────────────
    JOB_TTL_SECONDS: int = int(os.getenv("JOB_TTL_SECONDS", "3600"))
    MAX_AGENT_TURNS: int = int(os.getenv("MAX_AGENT_TURNS", "30"))
    SYNC_TIMEOUT_SECONDS: int = int(os.getenv("SYNC_TIMEOUT_SECONDS", "110"))
    MAX_HISTORY: int = int(os.getenv("MAX_HISTORY", "20"))
    ENRICHMENT_CACHE_TTL_SECONDS: int = int(os.getenv("ENRICHMENT_CACHE_TTL_SECONDS", "3600"))
    ENRICHMENT_THREAD_WORKERS: int = int(os.getenv("ENRICHMENT_THREAD_WORKERS", "4"))

    @classmethod
    def reload(cls) -> None:
        """Reload all values from .env and config.json without restarting."""
        load_dotenv(ROOT / ".env", override=True)
        raw = _load_config_json()

        cls.SENTINEL_WORKSPACE_ID = os.getenv("SENTINEL_WORKSPACE_ID") or raw.get("sentinel_workspace_id", "")
        cls.TENANT_ID = os.getenv("AZURE_TENANT_ID") or os.getenv("TENANT_ID") or raw.get("tenant_id", "")
        cls.SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID") or os.getenv("SUBSCRIPTION_ID") or raw.get("subscription_id", "")

        azure_mcp = raw.get("azure_mcp", {})
        cls.RESOURCE_GROUP = (
            os.getenv("AZURE_LOGIC_APPS_RESOURCE_GROUP")
            or os.getenv("AZURE_RESOURCE_GROUP")
            or os.getenv("RESOURCE_GROUP")
            or azure_mcp.get("resource_group", "")
        )
        cls.WORKSPACE_NAME = (
            os.getenv("AZURE_WORKSPACE_NAME")
            or os.getenv("WORKSPACE_NAME")
            or azure_mcp.get("workspace_name", "")
        )
        cls.LOGIC_APP_NAMES = os.getenv("LOGIC_APP_NAMES", "")

        cls.IPINFO_TOKEN = os.getenv("IPINFO_TOKEN") or raw.get("ipinfo_token") or ""
        cls.ABUSEIPDB_TOKEN = os.getenv("ABUSEIPDB_TOKEN") or raw.get("abuseipdb_token") or ""
        cls.VPNAPI_TOKEN = os.getenv("VPNAPI_TOKEN") or raw.get("vpnapi_token") or ""
        cls.SHODAN_TOKEN = os.getenv("SHODAN_TOKEN") or raw.get("shodan_token") or ""
        cls.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

        cls.OUTPUT_DIR = ROOT / (os.getenv("OUTPUT_DIR") or raw.get("output_dir", "data/reports"))

        cls.SIT_MAPPING = {k: v for k, v in raw.get("sit_mapping", {}).items() if not k.startswith("__")}
        cls.LABEL_MAPPING = {k: v for k, v in raw.get("label_mapping", {}).items() if not k.startswith("__")}

        cls.APP_HOST = os.getenv("HOST") or os.getenv("APP_HOST", "0.0.0.0")
        cls.APP_PORT = int(os.getenv("PORT") or os.getenv("APP_PORT", "8000"))

        cls.API_KEY = os.getenv("API_KEY", "")
        cls.MCP_API_KEY = os.getenv("MCP_API_KEY", "")
        cls.SETTINGS_PASSWORD = os.getenv("SETTINGS_PASSWORD", "changeme")
        cls.APP_USERNAME = os.getenv("APP_USERNAME", "admin")
        cls.APP_PASSWORD = os.getenv("APP_PASSWORD", "PwC@y14")

        cls.DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "claude-sonnet-4-6")
        cls.AUTOMATION_DEFAULT_MODEL = os.getenv("AUTOMATION_DEFAULT_MODEL", "claude-sonnet-4-6")

        cls.GRAPH_MAIL_FROM = os.getenv("GRAPH_MAIL_FROM") or os.getenv("GRAPH_ADMIN_EMAIL", "")
        cls.GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID") or os.getenv("AZURE_CLIENT_ID", "")
        cls.GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET", "")
        cls.GRAPH_API_KEY = os.getenv("GRAPH_API_KEY", "")
        cls.GRAPH_ADMIN_EMAIL = os.getenv("GRAPH_ADMIN_EMAIL", "")

        cls.SENTINEL_COMMENT_WEBHOOK_URL = os.getenv("SENTINEL_COMMENT_WEBHOOK_URL", "")
        cls.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

        cls.ENABLE_SENTINEL_MCP = os.getenv("ENABLE_SENTINEL_MCP", "true").lower() == "true"
        cls.ENABLE_VIRUSTOTAL_MCP = os.getenv("ENABLE_VIRUSTOTAL_MCP", "true").lower() == "true"
        cls.ENABLE_GRAPH_MCP = os.getenv("ENABLE_GRAPH_MCP", "true").lower() == "true"
        cls.ENABLE_LEARN_MCP = os.getenv("ENABLE_LEARN_MCP", "false").lower() == "true"
        cls.ENABLE_KQL_SEARCH_MCP = os.getenv("ENABLE_KQL_SEARCH_MCP", "true").lower() == "true"
        cls.ENABLE_ADVANCED_SENTINEL_MCP = os.getenv("ENABLE_ADVANCED_SENTINEL_MCP", "true").lower() == "true"
        cls.SHOW_TOKEN_USAGE = os.getenv("SHOW_TOKEN_USAGE", "false").lower() == "true"

        cls.JOB_TTL_SECONDS = int(os.getenv("JOB_TTL_SECONDS", "3600"))
        cls.MAX_AGENT_TURNS = int(os.getenv("MAX_AGENT_TURNS", "30"))
        cls.SYNC_TIMEOUT_SECONDS = int(os.getenv("SYNC_TIMEOUT_SECONDS", "110"))
        cls.MAX_HISTORY = int(os.getenv("MAX_HISTORY", "20"))
        cls.ENRICHMENT_CACHE_TTL_SECONDS = int(os.getenv("ENRICHMENT_CACHE_TTL_SECONDS", "3600"))
        cls.ENRICHMENT_THREAD_WORKERS = int(os.getenv("ENRICHMENT_THREAD_WORKERS", "4"))

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
