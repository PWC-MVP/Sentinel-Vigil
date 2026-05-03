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
