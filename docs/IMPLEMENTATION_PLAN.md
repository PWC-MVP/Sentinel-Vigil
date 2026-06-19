# Sentinel Vigil — sentinelExtractor Integration Plan

> **Reference document for implementing 20 features from sentinelExtractor into Sentinel Vigil.**
> Covers 6 phases, 13 new files, 11 modified files, and 5 security hardening fixes.
> Written against codebase snapshot: May 2026.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Gap Analysis](#2-gap-analysis)
3. [Security Findings (Fix First)](#3-security-findings-fix-first)
4. [Phase 1 — Foundation & Infrastructure](#4-phase-1--foundation--infrastructure)
5. [Phase 2 — Backup Engine](#5-phase-2--backup-engine)
6. [Phase 3 — Restore Engine](#6-phase-3--restore-engine)
7. [Phase 4 — ARIA Tools](#7-phase-4--aria-tools)
8. [Phase 5 — Frontend UI](#8-phase-5--frontend-ui)
9. [Phase 6 — Automation & Hardening](#9-phase-6--automation--hardening)
10. [File Change Summary](#10-file-change-summary)
11. [Dependencies](#11-dependencies)
12. [Execution Order](#12-execution-order)

---

## 1. Executive Summary

**What this plan delivers:**

| Category | Before | After |
|---|---|---|
| Sentinel resource types managed | KQL queries only | 15 resource types (rules, workbooks, playbooks, watchlists, etc.) |
| Token acquisition | Fresh token per Graph call | Cached token, proactive refresh 5 min before expiry |
| API versions | Single `2023-02-01` for all | Per-resource-type version map |
| Investigation caching | None (re-runs all KQL every time) | TTL-based cache (30 min default) |
| Backup/restore | Not present | Full backup + restore with content-based change detection |
| Retry on 401/403 | None | Automatic token refresh + retry |
| ARIA tools | 9 tools | 16 tools (+7 backup/restore tools) |
| Frontend pages | 17 pages | 20 pages (+Backup, Restore, Snapshots) |
| Security: token exposure | `/api/config/env` leaks all tokens | Endpoint removed or auth-gated |
| Security: password | Plaintext `"admin"` default | Hashed, configurable, no default |

---

## 2. Gap Analysis

### 2.1 What sentinelExtractor Has That Sentinel Vigil Lacks

#### Token Management
- **`TokenManager` class** with proactive refresh (refreshes 5 min before expiry)
- **Token caching** — current `graph.py:36` calls `credential.get_token()` fresh every single invocation
- **Retry on 401** — current `sentinel.py:175-179` does no retry on auth failure

#### Sentinel Resource Coverage
sentinelExtractor extracts/restores all 15 types. Sentinel Vigil only queries via KQL:

| Resource Type | sentinelExtractor | Sentinel Vigil |
|---|---|---|
| Scheduled analytics rules | ✅ backup + restore | read-only (Analytics Rules page) |
| NRT (near-real-time) rules | ✅ | ❌ |
| Fusion rules | ✅ | ❌ |
| Microsoft security rules | ✅ | ❌ |
| Automation rules | ✅ | ❌ |
| Playbooks (Logic Apps) | ✅ list | ❌ |
| Workbooks | ✅ backup + restore | read-only (Workbook Coverage page) |
| Watchlists | ✅ backup + restore | ❌ |
| Threat intelligence | ✅ backup | query only |
| Data connectors | ✅ list | ❌ |
| Saved searches | ✅ backup | ❌ |
| Custom log tables | ✅ list | ❌ |
| Hunting queries | ✅ backup | read-only |
| Summary rules | ✅ backup | ❌ |
| Metadata records | ✅ | ❌ |

#### Backup Infrastructure
- **Content-based change detection** (SHA-256 hash comparison, skip unchanged)
- **File tracker** (JSON manifest of what was backed up, when, hash)
- **Cross-tenant resource rewriting** (swap workspace/subscription IDs when restoring to new tenant)
- **Incremental backup** (only changed resources since last snapshot)
- **Snapshot comparison** (diff two backup snapshots)

#### API Version Awareness
sentinelExtractor uses per-resource-type API versions:
```python
API_VERSIONS = {
    "alertrules":        "2023-02-01",
    "automationrules":   "2025-01-01-preview",
    "workbooks":         "2022-04-01",
    "watchlists":        "2023-02-01",
    "summaryrules":      "2025-07-01",
    "savedSearches":     "2020-08-01",
    "huntingQueries":    "2023-02-01",
    "threatintelligence":"2024-03-01",
}
```
Sentinel Vigil uses one version for all: `_SENTINEL_API_VERSION = "2023-02-01"` (`sentinel.py:117`).

#### Investigation Caching
Every investigation re-runs all KQL queries and Graph API calls from scratch. A 30-minute TTL cache would eliminate redundant network calls for the same user investigated twice in quick succession.

---

## 3. Security Findings (Fix First)

These should be fixed **before** Phase 1 work begins. They are independent of the feature additions.

### Finding 1 — Token Exposure via `/api/config/env`
**File:** `backend/main.py:89`
**Severity:** CRITICAL

```python
# CURRENT (REMOVE THIS ENTIRE ENDPOINT):
@app.get("/api/config/env")
async def get_env():
    return {k: v for k, v in os.environ.items()}
```

**Fix:** Delete the endpoint entirely, or if needed for debugging, add `require_admin` dependency and filter to non-secret keys only.

### Finding 2 — Default Admin Password
**File:** `backend/config.py:70`
**Severity:** HIGH

```python
# CURRENT:
SETTINGS_PASSWORD: str = "admin"

# FIX — remove default, require explicit env var:
SETTINGS_PASSWORD: str  # no default — pydantic will raise on startup if unset
```

In `.env.template`, add:
```
SETTINGS_PASSWORD=<set-a-strong-password>
```

### Finding 3 — Plaintext Password Compare
**File:** `backend/main.py:119`
**Severity:** MEDIUM

```python
# CURRENT:
if payload.password != config.SETTINGS_PASSWORD:

# FIX — use hmac.compare_digest to prevent timing attacks:
import hmac
if not hmac.compare_digest(payload.password, config.SETTINGS_PASSWORD):
```

### Finding 4 — No Auth on PATCH `/api/config`
**File:** `backend/routers/` (config router)
**Severity:** HIGH

Add a `require_admin` FastAPI dependency that checks a bearer token or the settings password before allowing config writes.

### Finding 5 — ws:// Hardcode Breaks HTTPS
**File:** `frontend/src/api/client.ts:264`
**Severity:** LOW (deployment blocker)

```typescript
// CURRENT:
new WebSocket(`ws://${window.location.host}/api/investigations/ws/${job_id}`)

// FIX:
const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
new WebSocket(`${proto}//${window.location.host}/api/investigations/ws/${job_id}`)
```

---

## 4. Phase 1 — Foundation & Infrastructure

**Goal:** Token caching, per-resource API versions, investigation caching, retry logic.
**Risk:** Low. All changes are internal service layer, no new endpoints.

### 4.1 New File: `backend/services/token_manager.py`

```python
"""Proactive token cache — refresh 5 min before expiry."""
import threading
import time
from typing import Optional
from azure.core.credentials import AccessToken


class TokenManager:
    _instances: dict[str, "TokenManager"] = {}
    _lock = threading.Lock()

    def __init__(self, credential, scope: str):
        self._credential = credential
        self._scope = scope
        self._token: Optional[AccessToken] = None
        self._refresh_lock = threading.Lock()

    @classmethod
    def get(cls, credential, scope: str) -> "TokenManager":
        key = f"{id(credential)}:{scope}"
        with cls._lock:
            if key not in cls._instances:
                cls._instances[key] = cls(credential, scope)
        return cls._instances[key]

    @classmethod
    def invalidate_all(cls) -> None:
        with cls._lock:
            cls._instances.clear()

    def get_token(self) -> str:
        with self._refresh_lock:
            if self._needs_refresh():
                self._token = self._credential.get_token(self._scope)
        return self._token.token

    def _needs_refresh(self) -> bool:
        if self._token is None:
            return True
        # Refresh 5 minutes before expiry
        return time.time() >= (self._token.expires_on - 300)
```

### 4.2 Modify: `backend/services/graph.py`

**Current problem (line 36):** `credential.get_token(GRAPH_SCOPE)` called fresh on every request.

```python
# ADD at top of file:
from .token_manager import TokenManager

GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# REPLACE _get_token function:
def _get_token(credential) -> str:
    return TokenManager.get(credential, GRAPH_SCOPE).get_token()
```

Also add retry on 401:

```python
# REPLACE graph_get():
async def graph_get(credential, path: str, params: dict = None) -> dict:
    loop = asyncio.get_event_loop()
    
    def _do_get(token: str):
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url = f"https://graph.microsoft.com/v1.0{path}"
        return requests.get(url, headers=headers, params=params, timeout=30)
    
    def _fetch():
        token = _get_token(credential)
        resp = _do_get(token)
        if resp.status_code == 401:
            # Force token refresh and retry once
            TokenManager.get(credential, GRAPH_SCOPE)._token = None
            token = _get_token(credential)
            resp = _do_get(token)
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json()
    
    return await loop.run_in_executor(None, _fetch)
```

### 4.3 Modify: `backend/services/sentinel.py`

**Current problem (line 117):** Single API version for all resource types.

```python
# REPLACE the single constant with a version map:
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
```

Update `call_sentinel_mgmt_api()` signature to accept optional resource_type:

```python
def call_sentinel_mgmt_api(
    credential,
    path: str,
    method: str = "GET",
    body: dict = None,
    resource_type: str = None,
    extra_params: dict = None,
) -> list[dict] | dict:
    token_mgr = TokenManager.get(credential, "https://management.azure.com/.default")
    
    def _do_request():
        token = token_mgr.get_token()
        api_ver = _api_version(resource_type) if resource_type else _DEFAULT_API_VERSION
        params = {"api-version": api_ver}
        if extra_params:
            params.update(extra_params)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url = f"https://management.azure.com{path}"
        
        if method == "GET":
            resp = requests.get(url, headers=headers, params=params, timeout=60)
        elif method == "PUT":
            resp = requests.put(url, headers=headers, params=params, json=body, timeout=60)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers, params=params, timeout=30)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        if resp.status_code == 401:
            # Force refresh and retry
            token_mgr._token = None
            return _do_request()
        
        return resp
    
    resp = _do_request()
    # ... rest of pagination logic unchanged
```

### 4.4 New File: `backend/services/investigation_cache.py`

```python
"""TTL-based investigation result cache keyed on (upn, days_back)."""
import asyncio
import time
from typing import Optional

_CACHE: dict[str, tuple[float, dict]] = {}
_LOCK = asyncio.Lock()
DEFAULT_TTL = 1800  # 30 minutes


async def get_cached(upn: str, days_back: int) -> Optional[dict]:
    key = f"{upn.lower()}:{days_back}"
    async with _LOCK:
        entry = _CACHE.get(key)
        if entry and (time.time() - entry[0]) < DEFAULT_TTL:
            return entry[1]
    return None


async def set_cached(upn: str, days_back: int, result: dict) -> None:
    key = f"{upn.lower()}:{days_back}"
    async with _LOCK:
        _CACHE[key] = (time.time(), result)


async def invalidate(upn: str = None) -> int:
    """Invalidate cache for a user, or all if upn is None. Returns count removed."""
    async with _LOCK:
        if upn is None:
            count = len(_CACHE)
            _CACHE.clear()
            return count
        prefix = upn.lower() + ":"
        keys = [k for k in _CACHE if k.startswith(prefix)]
        for k in keys:
            del _CACHE[k]
        return len(keys)


async def list_cached() -> list[dict]:
    """Return cache entries with metadata (for ARIA tool: list_investigation_cache)."""
    now = time.time()
    async with _LOCK:
        return [
            {
                "upn": k.split(":")[0],
                "days_back": int(k.split(":")[1]),
                "cached_at": entry[0],
                "age_seconds": int(now - entry[0]),
                "expires_in_seconds": max(0, int(DEFAULT_TTL - (now - entry[0]))),
            }
            for k, entry in _CACHE.items()
        ]
```

Modify `backend/services/investigation.py` to use the cache:

```python
# At top of run_investigation():
from .investigation_cache import get_cached, set_cached

async def run_investigation(upn: str, days_back: int, ...) -> dict:
    cached = await get_cached(upn, days_back)
    if cached:
        return cached
    
    # ... existing 8-phase investigation logic ...
    
    result = { ... }  # existing result assembly
    await set_cached(upn, days_back, result)
    return result
```

---

## 5. Phase 2 — Backup Engine

**Goal:** Full backup of all 15 Sentinel resource types with content-based change detection.
**Risk:** Medium. Adds ~600 lines of new code, new API surface.

### 5.1 New File: `backend/services/file_tracker.py`

```python
"""Tracks backup manifests and content hashes for change detection."""
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


class FileTracker:
    def __init__(self, snapshot_dir: str):
        self.snapshot_dir = Path(snapshot_dir)
        self.manifest_path = self.snapshot_dir / "manifest.json"
        self._manifest: dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.manifest_path.exists():
            with open(self.manifest_path) as f:
                self._manifest = json.load(f)

    def save(self):
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        with open(self.manifest_path, "w") as f:
            json.dump(self._manifest, f, indent=2, default=str)

    @staticmethod
    def hash_content(content: dict | str) -> str:
        raw = json.dumps(content, sort_keys=True) if isinstance(content, dict) else content
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_changed(self, resource_id: str, content: dict) -> bool:
        """Return True if content has changed since last backup."""
        new_hash = self.hash_content(content)
        existing = self._manifest.get(resource_id, {})
        return existing.get("hash") != new_hash

    def record(self, resource_id: str, resource_type: str, file_path: str, content: dict):
        self._manifest[resource_id] = {
            "resource_type": resource_type,
            "file_path": file_path,
            "hash": self.hash_content(content),
            "backed_up_at": datetime.utcnow().isoformat(),
        }

    def get_summary(self) -> dict:
        by_type: dict[str, int] = {}
        for v in self._manifest.values():
            t = v.get("resource_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "total_resources": len(self._manifest),
            "by_type": by_type,
            "manifest_path": str(self.manifest_path),
        }

    def diff(self, other: "FileTracker") -> dict:
        """Compare two trackers, return added/removed/changed resource IDs."""
        self_ids = set(self._manifest.keys())
        other_ids = set(other._manifest.keys())
        changed = [
            rid for rid in self_ids & other_ids
            if self._manifest[rid]["hash"] != other._manifest[rid]["hash"]
        ]
        return {
            "added": list(other_ids - self_ids),
            "removed": list(self_ids - other_ids),
            "changed": changed,
            "unchanged": len(self_ids & other_ids) - len(changed),
        }
```

### 5.2 New File: `backend/services/backup.py`

This is the core backup engine. Full structure (implement in order):

```python
"""Sentinel workspace backup engine — extracts 15 resource types."""
import asyncio
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..auth import get_credential
from ..config import get_config
from .file_tracker import FileTracker
from .sentinel import call_sentinel_mgmt_api_async
from .jobs import emit


# ── Resource Type Definitions ────────────────────────────────────────────────

RESOURCE_TYPES = [
    "scheduledRules",
    "nrtRules", 
    "fusionRules",
    "microsoftRules",
    "automationRules",
    "playbooks",
    "workbooks",
    "watchlists",
    "savedSearches",
    "huntingQueries",
    "summaryRules",
    "dataConnectors",
    "threatIntelligence",
    "customTables",
    "metadata",
]


# ── Sentinel Base Path Builder ───────────────────────────────────────────────

def _sentinel_base(config) -> str:
    return (
        f"/subscriptions/{config.SUBSCRIPTION_ID}"
        f"/resourceGroups/{config.RESOURCE_GROUP}"
        f"/providers/Microsoft.OperationalInsights"
        f"/workspaces/{config.SENTINEL_WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights"
    )


# ── Individual Extractors ────────────────────────────────────────────────────

async def _extract_alert_rules(credential, config, snapshot_dir: Path, tracker: FileTracker,
                                 rule_kinds: list[str], type_label: str, job_id: str) -> int:
    """Extract analytics rules filtered by kind(s)."""
    base = _sentinel_base(config)
    rules = await call_sentinel_mgmt_api_async(
        credential, f"{base}/alertRules", resource_type="alertrules"
    )
    count = 0
    for rule in rules:
        props = rule.get("properties", {})
        if props.get("kind") not in rule_kinds:
            continue
        rid = rule.get("id", rule.get("name", "unknown"))
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


async def extract_scheduled_rules(credential, config, snapshot_dir: Path,
                                    tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(
        credential, config, snapshot_dir, tracker, ["Scheduled"], "scheduledRules", job_id
    )


async def extract_nrt_rules(credential, config, snapshot_dir: Path,
                               tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(
        credential, config, snapshot_dir, tracker, ["NRT"], "nrtRules", job_id
    )


async def extract_fusion_rules(credential, config, snapshot_dir: Path,
                                  tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(
        credential, config, snapshot_dir, tracker, ["Fusion"], "fusionRules", job_id
    )


async def extract_microsoft_rules(credential, config, snapshot_dir: Path,
                                     tracker: FileTracker, job_id: str) -> int:
    return await _extract_alert_rules(
        credential, config, snapshot_dir, tracker, ["MicrosoftSecurityIncidentCreation"],
        "microsoftRules", job_id
    )


async def extract_automation_rules(credential, config, snapshot_dir: Path,
                                      tracker: FileTracker, job_id: str) -> int:
    base = _sentinel_base(config)
    rules = await call_sentinel_mgmt_api_async(
        credential, f"{base}/automationRules", resource_type="automationrules"
    )
    count = 0
    for rule in rules:
        rid = rule.get("id", rule.get("name", "unknown"))
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


async def extract_workbooks(credential, config, snapshot_dir: Path,
                               tracker: FileTracker, job_id: str) -> int:
    sub = config.SUBSCRIPTION_ID
    rg = config.RESOURCE_GROUP
    path = f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/workbooks"
    workbooks = await call_sentinel_mgmt_api_async(
        credential, path, resource_type="workbooks"
    )
    count = 0
    for wb in workbooks:
        rid = wb.get("id", wb.get("name", "unknown"))
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


async def extract_watchlists(credential, config, snapshot_dir: Path,
                                tracker: FileTracker, job_id: str) -> int:
    base = _sentinel_base(config)
    watchlists = await call_sentinel_mgmt_api_async(
        credential, f"{base}/watchlists", resource_type="watchlists"
    )
    count = 0
    for wl in watchlists:
        rid = wl.get("id", wl.get("name", "unknown"))
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


async def extract_hunting_queries(credential, config, snapshot_dir: Path,
                                     tracker: FileTracker, job_id: str) -> int:
    base = _sentinel_base(config)
    queries = await call_sentinel_mgmt_api_async(
        credential, f"{base}/savedSearches", resource_type="huntingQueries"
    )
    count = 0
    for q in queries:
        props = q.get("properties", {})
        if props.get("category") != "Hunting Queries":
            continue
        rid = q.get("id", q.get("name", "unknown"))
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


async def extract_summary_rules(credential, config, snapshot_dir: Path,
                                    tracker: FileTracker, job_id: str) -> int:
    base = _sentinel_base(config)
    rules = await call_sentinel_mgmt_api_async(
        credential, f"{base}/summaryRules", resource_type="summaryrules"
    )
    count = 0
    for rule in rules:
        rid = rule.get("id", rule.get("name", "unknown"))
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


async def extract_data_connectors(credential, config, snapshot_dir: Path,
                                      tracker: FileTracker, job_id: str) -> int:
    base = _sentinel_base(config)
    connectors = await call_sentinel_mgmt_api_async(
        credential, f"{base}/dataConnectors", resource_type="dataConnectors"
    )
    count = 0
    for conn in connectors:
        rid = conn.get("id", conn.get("name", "unknown"))
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


async def extract_threat_intelligence(credential, config, snapshot_dir: Path,
                                          tracker: FileTracker, job_id: str) -> int:
    base = _sentinel_base(config)
    indicators = await call_sentinel_mgmt_api_async(
        credential, f"{base}/threatIntelligence/main/indicators",
        resource_type="threatintelligence"
    )
    count = 0
    for ind in indicators:
        rid = ind.get("id", ind.get("name", "unknown"))
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


async def extract_metadata(credential, config, snapshot_dir: Path,
                               tracker: FileTracker, job_id: str) -> int:
    base = _sentinel_base(config)
    records = await call_sentinel_mgmt_api_async(
        credential, f"{base}/metadata", resource_type="metadata"
    )
    count = 0
    for rec in records:
        rid = rec.get("id", rec.get("name", "unknown"))
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


# ── Orchestrator ─────────────────────────────────────────────────────────────

async def run_backup(
    job_id: str,
    resource_types: list[str] = None,
    output_dir: str = None,
    incremental: bool = True,
) -> dict:
    """
    Run backup for specified resource types (or all if None).
    Returns summary dict with counts per type and snapshot path.
    """
    config = get_config()
    credential = get_credential()
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_dir = Path(output_dir or config.OUTPUT_DIR) / "backups" / timestamp
    base_dir.mkdir(parents=True, exist_ok=True)
    
    tracker = FileTracker(str(base_dir))
    
    # Load previous tracker if incremental
    prev_tracker = None
    if incremental:
        prev_snapshot = _find_latest_snapshot(Path(output_dir or config.OUTPUT_DIR) / "backups")
        if prev_snapshot:
            prev_tracker = FileTracker(str(prev_snapshot))
            # Copy manifest to new tracker so change detection works
            tracker._manifest = dict(prev_tracker._manifest)
    
    types_to_run = resource_types or RESOURCE_TYPES
    
    extractors = {
        "scheduledRules":    extract_scheduled_rules,
        "nrtRules":          extract_nrt_rules,
        "fusionRules":       extract_fusion_rules,
        "microsoftRules":    extract_microsoft_rules,
        "automationRules":   extract_automation_rules,
        "workbooks":         extract_workbooks,
        "watchlists":        extract_watchlists,
        "huntingQueries":    extract_hunting_queries,
        "summaryRules":      extract_summary_rules,
        "dataConnectors":    extract_data_connectors,
        "threatIntelligence":extract_threat_intelligence,
        "metadata":          extract_metadata,
    }
    
    results = {}
    tasks = []
    for rtype in types_to_run:
        if rtype in extractors:
            tasks.append((rtype, extractors[rtype](credential, config, base_dir, tracker, job_id)))
    
    for rtype, coro in tasks:
        try:
            results[rtype] = await coro
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
    
    # Save summary JSON
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
    return snapshots[1] if len(snapshots) > 1 else None  # skip current (index 0)


def list_snapshots(output_dir: str = None) -> list[dict]:
    config = get_config()
    backups_dir = Path(output_dir or config.OUTPUT_DIR) / "backups"
    if not backups_dir.exists():
        return []
    snapshots = []
    for d in sorted(backups_dir.iterdir(), key=lambda x: x.name, reverse=True):
        if not d.is_dir():
            continue
        summary_path = d / "backup_summary.json"
        manifest_path = d / "manifest.json"
        if summary_path.exists():
            with open(summary_path) as f:
                summary = json.load(f)
            snapshots.append(summary)
        elif manifest_path.exists():
            tracker = FileTracker(str(d))
            snapshots.append({"snapshot_path": str(d), "timestamp": d.name,
                               "manifest_summary": tracker.get_summary()})
    return snapshots


def compare_snapshots(snapshot_a: str, snapshot_b: str) -> dict:
    tracker_a = FileTracker(snapshot_a)
    tracker_b = FileTracker(snapshot_b)
    return tracker_a.diff(tracker_b)
```

### 5.3 New File: `backend/routers/backup.py`

```python
"""Backup endpoints — POST /api/backup, GET /api/backup/snapshots, etc."""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List

from ..services.jobs import create_job, run_job
from ..services.backup import run_backup, list_snapshots, compare_snapshots

router = APIRouter(prefix="/api/backup", tags=["backup"])


class BackupRequest(BaseModel):
    resource_types: Optional[List[str]] = None
    output_dir: Optional[str] = None
    incremental: bool = True


class CompareRequest(BaseModel):
    snapshot_a: str
    snapshot_b: str


@router.post("")
async def start_backup(req: BackupRequest):
    job_id = create_job()
    run_job(
        job_id,
        run_backup,
        job_id=job_id,
        resource_types=req.resource_types,
        output_dir=req.output_dir,
        incremental=req.incremental,
    )
    return {"job_id": job_id}


@router.get("/snapshots")
async def get_snapshots(output_dir: Optional[str] = None):
    return {"snapshots": list_snapshots(output_dir)}


@router.post("/compare")
async def compare_backup_snapshots(req: CompareRequest):
    return compare_snapshots(req.snapshot_a, req.snapshot_b)
```

Register in `backend/main.py`:
```python
from .routers.backup import router as backup_router
app.include_router(backup_router)
```

---

## 6. Phase 3 — Restore Engine

**Goal:** Restore any subset of backed-up resources to the same or different workspace.

### 6.1 Cross-Tenant Rewriting

Before restoring to a different workspace, resource IDs must be rewritten:

```python
# backend/services/restore.py (partial — rewrite helper)

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
```

### 6.2 New File: `backend/services/restore.py`

Full structure (implement extractors as PUTs mirroring backup GETs):

```python
"""Sentinel workspace restore engine."""
import asyncio
import json
from pathlib import Path
from typing import Optional

from ..auth import get_credential
from ..config import get_config
from .sentinel import call_sentinel_mgmt_api_async
from .jobs import emit
from .backup import _sentinel_base, _find_latest_snapshot
from .file_tracker import FileTracker


async def restore_from_snapshot(
    job_id: str,
    snapshot_path: str,
    resource_types: list[str] = None,
    target_workspace: str = None,
    target_subscription: str = None,
    target_rg: str = None,
    dry_run: bool = False,
) -> dict:
    config = get_config()
    credential = get_credential()
    snap = Path(snapshot_path)

    source_workspace = None
    source_subscription = None
    source_rg = None

    # Detect source from manifest
    tracker = FileTracker(str(snap))
    manifest = tracker._manifest
    if manifest:
        sample = next(iter(manifest.values()))
        # Try to parse from file path
        pass

    all_types = resource_types or [
        d.name for d in snap.iterdir() if d.is_dir() and d.name != "__pycache__"
    ]

    results = {}
    for rtype in all_types:
        type_dir = snap / rtype
        if not type_dir.exists():
            continue
        files = list(type_dir.glob("*.json"))
        restored = 0
        errors = []
        for f in files:
            resource = json.loads(f.read_text())
            if target_workspace:
                resource = _rewrite_resource(
                    resource,
                    source_workspace or "",
                    target_workspace,
                    source_subscription,
                    target_subscription or config.SUBSCRIPTION_ID,
                    source_rg,
                    target_rg or config.RESOURCE_GROUP,
                )
            if dry_run:
                restored += 1
                continue
            try:
                await _restore_resource(credential, config, rtype, resource, job_id)
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


async def _restore_resource(credential, config, rtype: str, resource: dict, job_id: str):
    """PUT a single resource back to Sentinel."""
    base = _sentinel_base(config)
    name = resource.get("name", "")
    
    path_map = {
        "scheduledRules":     f"{base}/alertRules/{name}",
        "nrtRules":           f"{base}/alertRules/{name}",
        "fusionRules":        f"{base}/alertRules/{name}",
        "microsoftRules":     f"{base}/alertRules/{name}",
        "automationRules":    f"{base}/automationRules/{name}",
        "watchlists":         f"{base}/watchlists/{name}",
        "huntingQueries":     f"{base}/savedSearches/{name}",
        "summaryRules":       f"{base}/summaryRules/{name}",
        "metadata":           f"{base}/metadata/{name}",
    }
    
    if rtype not in path_map:
        raise ValueError(f"Restore not supported for resource type: {rtype}")
    
    await call_sentinel_mgmt_api_async(
        credential,
        path_map[rtype],
        method="PUT",
        body=resource,
        resource_type=rtype.lower().rstrip("s"),  # simplified mapping
    )
```

### 6.3 New File: `backend/routers/restore.py`

```python
"""Restore endpoints — POST /api/restore"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List

from ..services.jobs import create_job, run_job
from ..services.restore import restore_from_snapshot

router = APIRouter(prefix="/api/restore", tags=["restore"])


class RestoreRequest(BaseModel):
    snapshot_path: str
    resource_types: Optional[List[str]] = None
    target_workspace: Optional[str] = None
    target_subscription: Optional[str] = None
    target_rg: Optional[str] = None
    dry_run: bool = False


@router.post("")
async def start_restore(req: RestoreRequest):
    job_id = create_job()
    run_job(
        job_id,
        restore_from_snapshot,
        job_id=job_id,
        snapshot_path=req.snapshot_path,
        resource_types=req.resource_types,
        target_workspace=req.target_workspace,
        target_subscription=req.target_subscription,
        target_rg=req.target_rg,
        dry_run=req.dry_run,
    )
    return {"job_id": job_id}
```

Register in `backend/main.py`:
```python
from .routers.restore import router as restore_router
app.include_router(restore_router)
```

---

## 7. Phase 4 — ARIA Tools

**Goal:** Expose backup/restore/cache operations as ARIA (LLM) tools so investigators can trigger them via natural language.

### 7.1 Add to `backend/services/tools.py`

#### Tool Definitions (add to `TOOLS` list):

```python
{
    "name": "backup_sentinel_workspace",
    "description": "Back up Sentinel workspace resources (rules, workbooks, watchlists, playbooks, etc.) to a local snapshot. Supports incremental backup (only changed resources). Use this before making configuration changes or for disaster recovery preparation.",
    "input_schema": {
        "type": "object",
        "properties": {
            "resource_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific resource types to back up. If omitted, backs up all types.",
                "enum": ["scheduledRules","nrtRules","fusionRules","microsoftRules",
                         "automationRules","workbooks","watchlists","huntingQueries",
                         "summaryRules","dataConnectors","threatIntelligence","metadata"]
            },
            "incremental": {
                "type": "boolean",
                "description": "Only back up resources that changed since the last snapshot.",
                "default": True
            }
        }
    }
},
{
    "name": "restore_sentinel_resources",
    "description": "Restore Sentinel resources from a backup snapshot. Supports partial restore (specific types) and dry-run mode to preview what would be restored.",
    "input_schema": {
        "type": "object",
        "properties": {
            "snapshot_path": {
                "type": "string",
                "description": "Path to the backup snapshot directory."
            },
            "resource_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific resource types to restore. If omitted, restores all types in the snapshot."
            },
            "dry_run": {
                "type": "boolean",
                "description": "If true, simulate the restore without making changes.",
                "default": False
            }
        },
        "required": ["snapshot_path"]
    }
},
{
    "name": "list_backup_snapshots",
    "description": "List all available backup snapshots with timestamps, resource counts, and types. Use this to see what backups are available before restoring.",
    "input_schema": {
        "type": "object",
        "properties": {}
    }
},
{
    "name": "compare_backup_snapshots",
    "description": "Compare two backup snapshots to see what changed between them (added, removed, modified resources).",
    "input_schema": {
        "type": "object",
        "properties": {
            "snapshot_a": {"type": "string", "description": "Path to the older/baseline snapshot."},
            "snapshot_b": {"type": "string", "description": "Path to the newer snapshot."}
        },
        "required": ["snapshot_a", "snapshot_b"]
    }
},
{
    "name": "get_backup_status",
    "description": "Get the status of a running or completed backup/restore job.",
    "input_schema": {
        "type": "object",
        "properties": {
            "job_id": {"type": "string", "description": "The job ID returned when backup/restore was started."}
        },
        "required": ["job_id"]
    }
},
{
    "name": "invalidate_investigation_cache",
    "description": "Clear cached investigation results for a specific user or all users. Use when you need fresh data after a user's situation has changed.",
    "input_schema": {
        "type": "object",
        "properties": {
            "upn": {
                "type": "string",
                "description": "UPN of the user whose cache to clear. If omitted, clears all cached investigations."
            }
        }
    }
},
{
    "name": "check_permissions",
    "description": "Check what Azure permissions the current service principal/managed identity has on the Sentinel workspace. Useful for diagnosing backup/restore failures.",
    "input_schema": {
        "type": "object",
        "properties": {}
    }
},
```

#### Tool Executor (add to `execute_tool()` elif chain):

```python
elif name == "backup_sentinel_workspace":
    from .backup import run_backup
    from .jobs import create_job, run_job
    job_id = create_job()
    run_job(
        job_id, run_backup,
        job_id=job_id,
        resource_types=inp.get("resource_types"),
        incremental=inp.get("incremental", True),
    )
    return {"job_id": job_id, "message": "Backup started. Use get_backup_status to monitor."}

elif name == "restore_sentinel_resources":
    from .restore import restore_from_snapshot
    from .jobs import create_job, run_job
    job_id = create_job()
    run_job(
        job_id, restore_from_snapshot,
        job_id=job_id,
        snapshot_path=inp["snapshot_path"],
        resource_types=inp.get("resource_types"),
        dry_run=inp.get("dry_run", False),
    )
    return {"job_id": job_id, "message": "Restore started. Use get_backup_status to monitor."}

elif name == "list_backup_snapshots":
    from .backup import list_snapshots
    return {"snapshots": list_snapshots()}

elif name == "compare_backup_snapshots":
    from .backup import compare_snapshots
    return compare_snapshots(inp["snapshot_a"], inp["snapshot_b"])

elif name == "get_backup_status":
    from .jobs import get_job
    job = get_job(inp["job_id"])
    return job.dict() if job else {"error": "Job not found"}

elif name == "invalidate_investigation_cache":
    from .investigation_cache import invalidate
    count = await invalidate(inp.get("upn"))
    return {"invalidated": count}

elif name == "check_permissions":
    from ..auth import get_credential
    from ..config import get_config
    config = get_config()
    # Check role assignments via ARM
    credential = get_credential()
    sub = config.SUBSCRIPTION_ID
    path = f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments"
    from .sentinel import call_sentinel_mgmt_api_async
    try:
        assignments = await call_sentinel_mgmt_api_async(credential, path)
        return {"role_assignments_count": len(assignments), "status": "ok"}
    except Exception as e:
        return {"error": str(e)}
```

---

## 8. Phase 5 — Frontend UI

**Goal:** Add Backup, Restore, and Snapshots pages. Update navigation.

### 8.1 New TypeScript Interfaces in `frontend/src/api/client.ts`

```typescript
// Add after existing interfaces:

export interface BackupRequest {
    resource_types?: string[];
    output_dir?: string;
    incremental?: boolean;
}

export interface RestoreRequest {
    snapshot_path: string;
    resource_types?: string[];
    target_workspace?: string;
    target_subscription?: string;
    target_rg?: string;
    dry_run?: boolean;
}

export interface BackupSnapshot {
    snapshot_path: string;
    timestamp: string;
    incremental?: boolean;
    results?: Record<string, number | string>;
    manifest_summary?: {
        total_resources: number;
        by_type: Record<string, number>;
        manifest_path: string;
    };
}

export interface SnapshotDiff {
    added: string[];
    removed: string[];
    changed: string[];
    unchanged: number;
}
```

### 8.2 New API Methods in `frontend/src/api/client.ts`

```typescript
// Add after existing API methods:

export const startBackup = (req: BackupRequest): Promise<{ job_id: string }> =>
    api.post<{ job_id: string }>('/backup', req).then(r => r.data);

export const listSnapshots = (): Promise<{ snapshots: BackupSnapshot[] }> =>
    api.get<{ snapshots: BackupSnapshot[] }>('/backup/snapshots').then(r => r.data);

export const compareSnapshots = (snapshot_a: string, snapshot_b: string): Promise<SnapshotDiff> =>
    api.post<SnapshotDiff>('/backup/compare', { snapshot_a, snapshot_b }).then(r => r.data);

export const startRestore = (req: RestoreRequest): Promise<{ job_id: string }> =>
    api.post<{ job_id: string }>('/restore', req).then(r => r.data);
```

### 8.3 New Page: `frontend/src/pages/Backup.tsx`

Full component structure:

```tsx
import { useState } from 'react';
import { startBackup, getEnrichment } from '../api/client';

const RESOURCE_TYPES = [
    'scheduledRules', 'nrtRules', 'fusionRules', 'microsoftRules',
    'automationRules', 'workbooks', 'watchlists', 'huntingQueries',
    'summaryRules', 'dataConnectors', 'threatIntelligence', 'metadata',
];

export default function Backup() {
    const [selected, setSelected] = useState<string[]>([]);
    const [incremental, setIncremental] = useState(true);
    const [running, setRunning] = useState(false);
    const [jobId, setJobId] = useState<string | null>(null);
    const [status, setStatus] = useState<string>('');
    const [error, setError] = useState<string | null>(null);

    const toggle = (type: string) =>
        setSelected(s => s.includes(type) ? s.filter(t => t !== type) : [...s, type]);

    const handleStart = async () => {
        setRunning(true);
        setError(null);
        try {
            const { job_id } = await startBackup({
                resource_types: selected.length > 0 ? selected : undefined,
                incremental,
            });
            setJobId(job_id);
            setStatus('Backup started...');
            // Poll for completion
            const poll = setInterval(async () => {
                const job = await getEnrichment(job_id);  // reuse job getter
                if (job.status === 'completed') {
                    setStatus('Backup complete!');
                    clearInterval(poll);
                    setRunning(false);
                } else if (job.status === 'failed') {
                    setError(job.error || 'Backup failed');
                    clearInterval(poll);
                    setRunning(false);
                }
            }, 2000);
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : 'Unknown error');
            setRunning(false);
        }
    };

    return (
        <div className="page-content">
            <h1 className="page-title">Backup Workspace</h1>
            <p className="page-subtitle">
                Create a point-in-time snapshot of your Sentinel workspace configuration.
            </p>

            <div className="card">
                <h2 className="card-title">Resource Types</h2>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {RESOURCE_TYPES.map(t => (
                        <label key={t} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                checked={selected.includes(t)}
                                onChange={() => toggle(t)}
                            />
                            {t}
                        </label>
                    ))}
                </div>
                <p className="hint">Leave all unchecked to back up all resource types.</p>
            </div>

            <div className="card">
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <input
                        type="checkbox"
                        checked={incremental}
                        onChange={e => setIncremental(e.target.checked)}
                    />
                    Incremental (only changed resources since last snapshot)
                </label>
            </div>

            <button
                className="btn btn-primary"
                onClick={handleStart}
                disabled={running}
            >
                {running ? 'Running…' : 'Start Backup'}
            </button>

            {jobId && <p>Job ID: <code>{jobId}</code></p>}
            {status && <p className="status-ok">{status}</p>}
            {error && <p className="status-error">{error}</p>}
        </div>
    );
}
```

### 8.4 New Page: `frontend/src/pages/Snapshots.tsx`

```tsx
import { useEffect, useState } from 'react';
import { listSnapshots, compareSnapshots, BackupSnapshot, SnapshotDiff } from '../api/client';

export default function Snapshots() {
    const [snapshots, setSnapshots] = useState<BackupSnapshot[]>([]);
    const [loading, setLoading] = useState(true);
    const [selected, setSelected] = useState<string[]>([]);
    const [diff, setDiff] = useState<SnapshotDiff | null>(null);

    useEffect(() => {
        listSnapshots()
            .then(r => setSnapshots(r.snapshots))
            .finally(() => setLoading(false));
    }, []);

    const handleSelect = (path: string) => {
        setSelected(s => {
            if (s.includes(path)) return s.filter(p => p !== path);
            if (s.length >= 2) return [s[1], path];
            return [...s, path];
        });
    };

    const handleCompare = async () => {
        if (selected.length !== 2) return;
        const result = await compareSnapshots(selected[0], selected[1]);
        setDiff(result);
    };

    if (loading) return <div className="page-content"><p>Loading snapshots…</p></div>;

    return (
        <div className="page-content">
            <h1 className="page-title">Backup Snapshots</h1>

            <div className="card">
                <p className="hint">Select 2 snapshots to compare them.</p>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th></th>
                            <th>Timestamp</th>
                            <th>Total Resources</th>
                            <th>Incremental</th>
                        </tr>
                    </thead>
                    <tbody>
                        {snapshots.map(s => (
                            <tr key={s.snapshot_path}>
                                <td>
                                    <input
                                        type="checkbox"
                                        checked={selected.includes(s.snapshot_path)}
                                        onChange={() => handleSelect(s.snapshot_path)}
                                    />
                                </td>
                                <td>{s.timestamp}</td>
                                <td>{s.manifest_summary?.total_resources ?? '—'}</td>
                                <td>{s.incremental ? 'Yes' : 'No'}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                <button
                    className="btn btn-secondary"
                    onClick={handleCompare}
                    disabled={selected.length !== 2}
                >
                    Compare Selected
                </button>
            </div>

            {diff && (
                <div className="card">
                    <h2 className="card-title">Diff Result</h2>
                    <p><strong>Added:</strong> {diff.added.length} resources</p>
                    <p><strong>Removed:</strong> {diff.removed.length} resources</p>
                    <p><strong>Changed:</strong> {diff.changed.length} resources</p>
                    <p><strong>Unchanged:</strong> {diff.unchanged} resources</p>
                    {diff.changed.length > 0 && (
                        <details>
                            <summary>Changed resources</summary>
                            <ul>{diff.changed.map(r => <li key={r}>{r}</li>)}</ul>
                        </details>
                    )}
                </div>
            )}
        </div>
    );
}
```

### 8.5 New Page: `frontend/src/pages/Restore.tsx`

```tsx
import { useState, useEffect } from 'react';
import { listSnapshots, startRestore, BackupSnapshot } from '../api/client';

export default function Restore() {
    const [snapshots, setSnapshots] = useState<BackupSnapshot[]>([]);
    const [selected, setSelected] = useState<string>('');
    const [dryRun, setDryRun] = useState(true);
    const [running, setRunning] = useState(false);
    const [result, setResult] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        listSnapshots().then(r => setSnapshots(r.snapshots));
    }, []);

    const handleRestore = async () => {
        if (!selected) return;
        setRunning(true);
        setError(null);
        setResult(null);
        try {
            const { job_id } = await startRestore({
                snapshot_path: selected,
                dry_run: dryRun,
            });
            setResult(`Restore job started: ${job_id}`);
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : 'Unknown error');
        } finally {
            setRunning(false);
        }
    };

    return (
        <div className="page-content">
            <h1 className="page-title">Restore Workspace</h1>

            <div className="card">
                <label className="form-label">Select Snapshot</label>
                <select
                    className="form-input"
                    value={selected}
                    onChange={e => setSelected(e.target.value)}
                >
                    <option value="">— Choose a snapshot —</option>
                    {snapshots.map(s => (
                        <option key={s.snapshot_path} value={s.snapshot_path}>
                            {s.timestamp} ({s.manifest_summary?.total_resources ?? '?'} resources)
                        </option>
                    ))}
                </select>
            </div>

            <div className="card">
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <input
                        type="checkbox"
                        checked={dryRun}
                        onChange={e => setDryRun(e.target.checked)}
                    />
                    Dry Run (preview changes without applying)
                </label>
            </div>

            {!dryRun && (
                <div className="alert alert-warning">
                    Warning: This will overwrite existing Sentinel resources. Make a fresh backup first.
                </div>
            )}

            <button
                className="btn btn-danger"
                onClick={handleRestore}
                disabled={!selected || running}
            >
                {running ? 'Running…' : dryRun ? 'Preview Restore' : 'Restore Now'}
            </button>

            {result && <p className="status-ok">{result}</p>}
            {error && <p className="status-error">{error}</p>}
        </div>
    );
}
```

### 8.6 Update `frontend/src/App.tsx`

```typescript
// Add imports:
import Backup from './pages/Backup';
import Restore from './pages/Restore';
import Snapshots from './pages/Snapshots';

// Extend Page type:
type Page = 'chat' | 'dashboard' | 'investigate' | 'reports' | 'enrich' | 'kql' | 'settings'
    | 'mitre' | 'geomap' | 'analytics' | 'sentinel-health' | 'automation' | 'rules'
    | 'incidents' | 'entities' | 'hunting' | 'workbooks'
    | 'backup' | 'restore' | 'snapshots';  // NEW

// Add cases to renderPage():
case 'backup': return <Backup />;
case 'restore': return <Restore />;
case 'snapshots': return <Snapshots />;
```

### 8.7 Update `frontend/src/components/Layout.tsx`

```typescript
// Add icons import:
import { faCloudArrowUp, faCloudArrowDown, faClock } from '@fortawesome/free-solid-svg-icons';

// Add to NAV array (under SENTINEL OPS section, before settings):
{ id: 'backup',    label: 'Backup Workspace', icon: faCloudArrowUp,   section: 'SENTINEL OPS' },
{ id: 'restore',   label: 'Restore',          icon: faCloudArrowDown, section: 'SENTINEL OPS' },
{ id: 'snapshots', label: 'Snapshots',        icon: faClock,          section: 'SENTINEL OPS' },
```

---

## 9. Phase 6 — Automation & Hardening

### 9.1 Scheduled Backup Job

Add to `backend/main.py` startup:

```python
from contextlib import asynccontextmanager
import asyncio

async def _scheduled_backup_loop():
    """Run daily backup at 02:00 UTC."""
    import datetime
    while True:
        now = datetime.datetime.utcnow()
        next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += datetime.timedelta(days=1)
        wait_seconds = (next_run - now).total_seconds()
        await asyncio.sleep(wait_seconds)
        try:
            from .services.backup import run_backup
            from .services.jobs import create_job, run_job
            job_id = create_job()
            run_job(job_id, run_backup, job_id=job_id, incremental=True)
        except Exception as e:
            print(f"Scheduled backup failed: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_scheduled_backup_loop())
    yield
    task.cancel()

app = FastAPI(lifespan=lifespan)
```

### 9.2 New File: `backend/services/keyvault.py` (optional)

```python
"""Azure Key Vault integration for secure secret management."""
import os
from azure.keyvault.secrets import SecretClient
from ..auth import get_credential

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
```

### 9.3 Updated `.env.template`

```env
# ── Azure Identity ──────────────────────────────────────────────────────────
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<your-client-id>
AZURE_CLIENT_SECRET=<your-client-secret>

# ── Sentinel Workspace ───────────────────────────────────────────────────────
SENTINEL_WORKSPACE_ID=<workspace-id>
SENTINEL_WORKSPACE_NAME=<workspace-name>
AZURE_SUBSCRIPTION_ID=<subscription-id>
AZURE_RESOURCE_GROUP=<resource-group>

# ── Application ──────────────────────────────────────────────────────────────
SETTINGS_PASSWORD=<set-a-strong-password>
OUTPUT_DIR=./output

# ── Optional: Key Vault ──────────────────────────────────────────────────────
# AZURE_KEYVAULT_URL=https://<vault-name>.vault.azure.net/

# ── Optional: Per-resource-type Resource Groups ─────────────────────────────
# WORKBOOKS_RESOURCE_GROUP=<override-rg-for-workbooks>

# ── Threat Intel APIs ────────────────────────────────────────────────────────
IPINFO_TOKEN=<ipinfo-api-token>
ABUSEIPDB_TOKEN=<abuseipdb-api-key>
VPNAPI_TOKEN=<vpnapi-io-token>
SHODAN_TOKEN=<shodan-api-key>

# ── Azure OpenAI ─────────────────────────────────────────────────────────────
AZURE_OPENAI_ENDPOINT=<azure-openai-endpoint>
AZURE_OPENAI_API_KEY=<azure-openai-api-key>
AZURE_OPENAI_DEPLOYMENT=<deployment-name>
AZURE_OPENAI_API_VERSION=2024-02-01

# ── Azure Anthropic ───────────────────────────────────────────────────────────
AZURE_ANTHROPIC_ENDPOINT=<azure-anthropic-endpoint>
AZURE_ANTHROPIC_API_KEY=<azure-anthropic-api-key>
```

---

## 10. File Change Summary

| # | File | Action | Phase | Notes |
|---|---|---|---|---|
| 1 | `backend/services/token_manager.py` | **CREATE** | 1 | Proactive token caching |
| 2 | `backend/services/investigation_cache.py` | **CREATE** | 1 | 30-min TTL investigation cache |
| 3 | `backend/services/file_tracker.py` | **CREATE** | 2 | SHA-256 change detection + diff |
| 4 | `backend/services/backup.py` | **CREATE** | 2 | 12 extractors + orchestrator |
| 5 | `backend/routers/backup.py` | **CREATE** | 2 | 3 backup endpoints |
| 6 | `backend/services/restore.py` | **CREATE** | 3 | Cross-tenant restore engine |
| 7 | `backend/routers/restore.py` | **CREATE** | 3 | 1 restore endpoint |
| 8 | `backend/services/keyvault.py` | **CREATE** | 6 | Key Vault integration |
| 9 | `frontend/src/pages/Backup.tsx` | **CREATE** | 5 | Backup UI page |
| 10 | `frontend/src/pages/Restore.tsx` | **CREATE** | 5 | Restore UI page |
| 11 | `frontend/src/pages/Snapshots.tsx` | **CREATE** | 5 | Snapshot list + diff UI |
| 12 | `backend/services/graph.py` | **MODIFY** | 1 | Add token caching + 401 retry |
| 13 | `backend/services/sentinel.py` | **MODIFY** | 1 | Add API version map + retry |
| 14 | `backend/services/investigation.py` | **MODIFY** | 1 | Add cache read/write |
| 15 | `backend/services/tools.py` | **MODIFY** | 4 | +7 tools + 7 elif cases |
| 16 | `backend/main.py` | **MODIFY** | 2,3,6 | Register routers, remove /env, lifespan |
| 17 | `backend/config.py` | **MODIFY** | 3 (sec) | Remove default password |
| 18 | `frontend/src/App.tsx` | **MODIFY** | 5 | +3 page imports + cases |
| 19 | `frontend/src/components/Layout.tsx` | **MODIFY** | 5 | +3 nav items |
| 20 | `frontend/src/api/client.ts` | **MODIFY** | 5 | +4 interfaces + 4 API methods, fix ws:// |
| 21 | `.env.template` | **MODIFY** | 6 | Add all required variables |
| 22 | `requirements.txt` | **MODIFY** | 2,6 | +2 packages |

**New files: 11 | Modified files: 11 | Total: 22**

---

## 11. Dependencies

### Python (add to `requirements.txt`)

```
azure-storage-blob==12.19.0
azure-keyvault-secrets==4.7.0
```

No new npm packages are needed — the frontend additions use only existing React + FontAwesome packages already in `package.json`.

---

## 12. Execution Order

Follow this sequence to avoid breaking the running app:

```
Phase 1a  — Fix security findings (main.py:89, config.py:70, main.py:119, client.ts:264)
Phase 1b  — Create token_manager.py
Phase 1c  — Create investigation_cache.py
Phase 1d  — Modify graph.py (use TokenManager)
Phase 1e  — Modify sentinel.py (API version map + token_manager + retry)
Phase 1f  — Modify investigation.py (cache read/write)
Phase 1g  — Install new Python deps: pip install azure-storage-blob azure-keyvault-secrets
Phase 1h  — Run tests: all existing investigation and KQL tests should still pass

Phase 2a  — Create file_tracker.py
Phase 2b  — Create backup.py
Phase 2c  — Create routers/backup.py
Phase 2d  — Register backup router in main.py
Phase 2e  — Smoke test: POST /api/backup with resource_types=["metadata"]

Phase 3a  — Create restore.py
Phase 3b  — Create routers/restore.py
Phase 3c  — Register restore router in main.py
Phase 3d  — Smoke test dry_run: POST /api/restore { snapshot_path: "...", dry_run: true }

Phase 4   — Modify tools.py (+7 tools + 7 elif cases)
Phase 4b  — Chat test: ask ARIA "list backup snapshots" — should invoke list_backup_snapshots tool

Phase 5a  — Create Backup.tsx, Restore.tsx, Snapshots.tsx
Phase 5b  — Modify client.ts (+interfaces +methods +ws fix)
Phase 5c  — Modify App.tsx (+3 pages)
Phase 5d  — Modify Layout.tsx (+3 nav items)
Phase 5e  — npm run build — verify no TypeScript errors

Phase 6a  — Create keyvault.py (optional, only if AZURE_KEYVAULT_URL is configured)
Phase 6b  — Add lifespan / scheduled backup to main.py
Phase 6c  — Update .env.template
```

---

*Generated: 2026-05-02 | Codebase: Sentinel Vigil v1.0 | Reference: sentinelExtractor (0xrick-dev)*
