"""Sentinel workspace restore engine."""
import asyncio
import json
from pathlib import Path
from typing import Optional

from backend.config import settings
from backend.services.sentinel import call_sentinel_mgmt_api_async, call_azure_mgmt_api_async, _api_version
from backend.services.jobs import emit
from backend.services.backup import _find_latest_snapshot
from backend.services.file_tracker import FileTracker


def _rewrite_resource(
    resource: dict,
    source_workspace: str,
    target_workspace: str,
    source_subscription: str = None,
    target_subscription: str = None,
    source_rg: str = None,
    target_rg: str = None,
) -> dict:
    """Replace workspace/subscription/rg references in a resource dict."""
    raw = json.dumps(resource)
    if source_workspace and target_workspace:
        raw = raw.replace(source_workspace, target_workspace)
    if source_subscription and target_subscription:
        raw = raw.replace(source_subscription, target_subscription)
    if source_rg and target_rg:
        raw = raw.replace(source_rg, target_rg)
    return json.loads(raw)


# ── Path map — maps resource type folder names to ARM PUT paths ───────────────

def _put_path(rtype: str, name: str) -> str:
    """Return the ARM path for a PUT restore operation."""
    path_map = {
        "scheduledRules":  f"/alertRules/{name}",
        "nrtRules":        f"/alertRules/{name}",
        "fusionRules":     f"/alertRules/{name}",
        "microsoftRules":  f"/alertRules/{name}",
        "automationRules": f"/automationRules/{name}",
        "watchlists":      f"/watchlists/{name}",
        "huntingQueries":  f"/savedSearches/{name}",
        "summaryRules":    f"/summaryRules/{name}",
        "metadata":        f"/metadata/{name}",
    }
    return path_map.get(rtype, "")


async def _restore_resource(rtype: str, resource: dict, job_id: str):
    """PUT a single resource back to Sentinel via call_sentinel_mgmt_api_async."""
    name = resource.get("name", "")
    path = _put_path(rtype, name)
    if not path:
        raise ValueError(f"Restore not supported for resource type: {rtype}")

    await call_sentinel_mgmt_api_async(
        path,
        method="PUT",
        body=resource,
        resource_type=rtype.lower().rstrip("s"),
    )


async def restore_from_snapshot(
    job_id: str,
    snapshot_path: str,
    resource_types: list[str] = None,
    target_workspace: str = None,
    target_subscription: str = None,
    target_rg: str = None,
    dry_run: bool = False,
) -> dict:
    snap = Path(snapshot_path)

    all_types = resource_types or [
        d.name for d in snap.iterdir()
        if d.is_dir() and d.name not in ("__pycache__",)
    ]

    results: dict = {}
    for rtype in all_types:
        type_dir = snap / rtype
        if not type_dir.exists():
            continue
        files   = list(type_dir.glob("*.json"))
        restored = 0
        errors: list[dict] = []
        for f in files:
            resource = json.loads(f.read_text())
            if target_workspace:
                resource = _rewrite_resource(
                    resource,
                    source_workspace=settings.WORKSPACE_NAME,
                    target_workspace=target_workspace,
                    source_subscription=settings.SUBSCRIPTION_ID,
                    target_subscription=target_subscription or settings.SUBSCRIPTION_ID,
                    source_rg=settings.RESOURCE_GROUP,
                    target_rg=target_rg or settings.RESOURCE_GROUP,
                )
            if dry_run:
                restored += 1
                continue
            try:
                await _restore_resource(rtype, resource, job_id)
                restored += 1
            except Exception as e:
                errors.append({"file": f.name, "error": str(e)})
        results[rtype] = {"restored": restored, "errors": errors}
        await emit(job_id, rtype, f"Restored {restored}/{len(files)} {rtype}")

    return {
        "snapshot_path": snapshot_path,
        "dry_run": dry_run,
        "results": results,
    }
