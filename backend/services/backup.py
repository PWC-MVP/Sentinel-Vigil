"""Sentinel workspace backup engine — extracts 15 resource types."""
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from backend.config import settings
from backend.services.file_tracker import FileTracker
from backend.services.sentinel import (
    call_sentinel_mgmt_api_async,
    call_azure_mgmt_api_async,
    _api_version,
)
from backend.services.jobs import emit


# ── Resource type list ────────────────────────────────────────────────────────

RESOURCE_TYPES = [
    "scheduledRules",
    "nrtRules",
    "fusionRules",
    "microsoftRules",
    "automationRules",
    "workbooks",
    "watchlists",
    "huntingQueries",
    "summaryRules",
    "dataConnectors",
    "threatIntelligence",
    "metadata",
]


# ── Alert-rule extractor (shared by scheduledRules / nrtRules / fusionRules / microsoftRules) ──

async def _extract_alert_rules(
    snapshot_dir: Path,
    tracker: FileTracker,
    rule_kinds: list[str],
    type_label: str,
    job_id: str,
) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/alertRules", resource_type="alertrules"
    )
    rules = data.get("value", [])
    count = 0
    for rule in rules:
        props = rule.get("properties", {})
        if props.get("kind") not in rule_kinds:
            continue
        rid  = rule.get("id", rule.get("name", "unknown"))
        name = rule.get("name", "unnamed")
        if not tracker.is_changed(rid, rule):
            continue
        out_path = snapshot_dir / type_label / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(rule, indent=2))
        tracker.record(rid, type_label, str(out_path), rule)
        count += 1
    await emit(job_id, type_label, f"Backed up {count} {type_label}")
    return count


async def extract_scheduled_rules(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(snapshot_dir, tracker, ["Scheduled"], "scheduledRules", job_id)


async def extract_nrt_rules(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(snapshot_dir, tracker, ["NRT"], "nrtRules", job_id)


async def extract_fusion_rules(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(snapshot_dir, tracker, ["Fusion"], "fusionRules", job_id)


async def extract_microsoft_rules(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(
        snapshot_dir, tracker, ["MicrosoftSecurityIncidentCreation"], "microsoftRules", job_id
    )


async def extract_automation_rules(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/automationRules", resource_type="automationrules"
    )
    rules = data.get("value", [])
    count = 0
    for rule in rules:
        rid  = rule.get("id", rule.get("name", "unknown"))
        name = rule.get("name", "unnamed")
        if not tracker.is_changed(rid, rule):
            continue
        out_path = snapshot_dir / "automationRules" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(rule, indent=2))
        tracker.record(rid, "automationRules", str(out_path), rule)
        count += 1
    await emit(job_id, "automationRules", f"Backed up {count} automation rules")
    return count


async def extract_workbooks(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    sub = settings.SUBSCRIPTION_ID
    rg  = settings.RESOURCE_GROUP
    path = f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/workbooks"
    data = await call_azure_mgmt_api_async(path, api_version=_api_version("workbooks"))
    workbooks = data.get("value", [])
    count = 0
    for wb in workbooks:
        rid  = wb.get("id", wb.get("name", "unknown"))
        name = wb.get("name", "unnamed")
        if not tracker.is_changed(rid, wb):
            continue
        out_path = snapshot_dir / "workbooks" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(wb, indent=2))
        tracker.record(rid, "workbooks", str(out_path), wb)
        count += 1
    await emit(job_id, "workbooks", f"Backed up {count} workbooks")
    return count


async def extract_watchlists(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/watchlists", resource_type="watchlists"
    )
    watchlists = data.get("value", [])
    count = 0
    for wl in watchlists:
        rid   = wl.get("id", wl.get("name", "unknown"))
        alias = wl.get("properties", {}).get("watchlistAlias", wl.get("name", "unnamed"))
        if not tracker.is_changed(rid, wl):
            continue
        out_path = snapshot_dir / "watchlists" / f"{alias}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(wl, indent=2))
        tracker.record(rid, "watchlists", str(out_path), wl)
        count += 1
    await emit(job_id, "watchlists", f"Backed up {count} watchlists")
    return count


async def extract_hunting_queries(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/savedSearches", resource_type="savedSearches"
    )
    queries = data.get("value", [])
    count = 0
    for q in queries:
        props = q.get("properties", {})
        if props.get("category") != "Hunting Queries":
            continue
        rid  = q.get("id", q.get("name", "unknown"))
        name = q.get("name", "unnamed")
        if not tracker.is_changed(rid, q):
            continue
        out_path = snapshot_dir / "huntingQueries" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(q, indent=2))
        tracker.record(rid, "huntingQueries", str(out_path), q)
        count += 1
    await emit(job_id, "huntingQueries", f"Backed up {count} hunting queries")
    return count


async def extract_summary_rules(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/summaryRules", resource_type="summaryrules"
    )
    rules = data.get("value", [])
    count = 0
    for rule in rules:
        rid  = rule.get("id", rule.get("name", "unknown"))
        name = rule.get("name", "unnamed")
        if not tracker.is_changed(rid, rule):
            continue
        out_path = snapshot_dir / "summaryRules" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(rule, indent=2))
        tracker.record(rid, "summaryRules", str(out_path), rule)
        count += 1
    await emit(job_id, "summaryRules", f"Backed up {count} summary rules")
    return count


async def extract_data_connectors(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/dataConnectors", resource_type="dataConnectors"
    )
    connectors = data.get("value", [])
    count = 0
    for conn in connectors:
        rid  = conn.get("id", conn.get("name", "unknown"))
        name = conn.get("name", "unnamed")
        if not tracker.is_changed(rid, conn):
            continue
        out_path = snapshot_dir / "dataConnectors" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(conn, indent=2))
        tracker.record(rid, "dataConnectors", str(out_path), conn)
        count += 1
    await emit(job_id, "dataConnectors", f"Backed up {count} data connectors")
    return count


async def extract_threat_intelligence(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/threatIntelligence/main/indicators", resource_type="threatintelligence"
    )
    indicators = data.get("value", [])
    count = 0
    for ind in indicators:
        rid  = ind.get("id", ind.get("name", "unknown"))
        name = rid.split("/")[-1] if "/" in rid else rid
        if not tracker.is_changed(rid, ind):
            continue
        out_path = snapshot_dir / "threatIntelligence" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(ind, indent=2))
        tracker.record(rid, "threatIntelligence", str(out_path), ind)
        count += 1
    await emit(job_id, "threatIntelligence", f"Backed up {count} threat indicators")
    return count


async def extract_metadata(snapshot_dir: Path, tracker: FileTracker, job_id: str) -> int:
    data = await call_sentinel_mgmt_api_async(
        "/metadata", resource_type="metadata"
    )
    records = data.get("value", [])
    count = 0
    for rec in records:
        rid  = rec.get("id", rec.get("name", "unknown"))
        name = rec.get("name", "unnamed")
        if not tracker.is_changed(rid, rec):
            continue
        out_path = snapshot_dir / "metadata" / f"{name}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(rec, indent=2))
        tracker.record(rid, "metadata", str(out_path), rec)
        count += 1
    await emit(job_id, "metadata", f"Backed up {count} metadata records")
    return count


# ── Orchestrator ──────────────────────────────────────────────────────────────

async def run_backup(
    job_id: str,
    resource_types: list[str] | None = None,
    output_dir: str | None = None,
    incremental: bool = True,
) -> dict:
    """
    Run backup for specified resource types (or all if None).
    Returns summary dict with counts per type and snapshot path.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_dir  = Path(output_dir or settings.OUTPUT_DIR) / "backups" / timestamp
    base_dir.mkdir(parents=True, exist_ok=True)

    tracker = FileTracker(str(base_dir))

    if incremental:
        prev_snapshot = _find_latest_snapshot(Path(output_dir or settings.OUTPUT_DIR) / "backups")
        if prev_snapshot:
            prev_tracker = FileTracker(str(prev_snapshot))
            tracker._manifest = dict(prev_tracker._manifest)

    types_to_run = resource_types or RESOURCE_TYPES

    extractors = {
        "scheduledRules":     extract_scheduled_rules,
        "nrtRules":           extract_nrt_rules,
        "fusionRules":        extract_fusion_rules,
        "microsoftRules":     extract_microsoft_rules,
        "automationRules":    extract_automation_rules,
        "workbooks":          extract_workbooks,
        "watchlists":         extract_watchlists,
        "huntingQueries":     extract_hunting_queries,
        "summaryRules":       extract_summary_rules,
        "dataConnectors":     extract_data_connectors,
        "threatIntelligence": extract_threat_intelligence,
        "metadata":           extract_metadata,
    }

    results: dict = {}
    for rtype in types_to_run:
        if rtype not in extractors:
            continue
        try:
            results[rtype] = await extractors[rtype](base_dir, tracker, job_id)
        except Exception as e:
            results[rtype] = f"ERROR: {e}"
            await emit(job_id, rtype, f"Failed to back up {rtype}: {e}")

    tracker.save()

    summary = {
        "snapshot_path": str(base_dir),
        "timestamp": timestamp,
        "incremental": incremental,
        "results": results,
        "manifest_summary": tracker.get_summary(),
    }

    (base_dir / "backup_summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def _find_latest_snapshot(backups_dir: Path) -> Optional[Path]:
    if not backups_dir.exists():
        return None
    snapshots = sorted(
        [d for d in backups_dir.iterdir() if d.is_dir() and (d / "manifest.json").exists()],
        key=lambda d: d.name,
        reverse=True,
    )
    return snapshots[1] if len(snapshots) > 1 else None


def list_snapshots(output_dir: str | None = None) -> list[dict]:
    backups_dir = Path(output_dir or settings.OUTPUT_DIR) / "backups"
    if not backups_dir.exists():
        return []
    snapshots = []
    for d in sorted(backups_dir.iterdir(), key=lambda x: x.name, reverse=True):
        if not d.is_dir():
            continue
        summary_path  = d / "backup_summary.json"
        manifest_path = d / "manifest.json"
        if summary_path.exists():
            with open(summary_path) as f:
                snapshots.append(json.load(f))
        elif manifest_path.exists():
            tracker = FileTracker(str(d))
            snapshots.append({
                "snapshot_path": str(d),
                "timestamp": d.name,
                "manifest_summary": tracker.get_summary(),
            })
    return snapshots


def compare_snapshots(snapshot_a: str, snapshot_b: str) -> dict:
    tracker_a = FileTracker(snapshot_a)
    tracker_b = FileTracker(snapshot_b)
    return tracker_a.diff(tracker_b)
