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
