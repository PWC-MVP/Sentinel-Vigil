"""
Background job manager for long-running investigations.
Uses asyncio tasks + an in-memory registry with JSON file persistence so that
completed jobs survive backend restarts.
"""
import asyncio
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, AsyncGenerator

from pydantic import BaseModel

# Persist completed/failed jobs here (project root / jobs/)
_JOBS_DIR = Path(__file__).parent.parent.parent / "jobs"


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class JobUpdate(BaseModel):
    phase: str
    message: str
    timestamp: str = ""
    data: Any = None

    def __init__(self, **data):
        if not data.get("timestamp"):
            data["timestamp"] = datetime.utcnow().isoformat() + "Z"
        super().__init__(**data)


class Job(BaseModel):
    job_id: str
    status: JobStatus = JobStatus.PENDING
    created_at: str = ""
    completed_at: str | None = None
    error: str | None = None
    result: Any = None
    updates: list[JobUpdate] = []

    def __init__(self, **data):
        if not data.get("created_at"):
            data["created_at"] = datetime.utcnow().isoformat() + "Z"
        super().__init__(**data)


# ── Global job registry ─────────────────────────────────────────────────────

_jobs: dict[str, Job] = {}
_queues: dict[str, asyncio.Queue] = {}


# ── Persistence helpers ──────────────────────────────────────────────────────

def _save_job(job: Job) -> None:
    """Write a completed/failed job to disk as JSON."""
    try:
        _JOBS_DIR.mkdir(parents=True, exist_ok=True)
        (_JOBS_DIR / f"{job.job_id}.json").write_text(job.model_dump_json())
    except Exception:
        pass


def _load_jobs() -> None:
    """Populate the in-memory registry from any persisted JSON files."""
    if not _JOBS_DIR.exists():
        return
    for path in sorted(_JOBS_DIR.glob("*.json")):
        try:
            job = Job.model_validate_json(path.read_text())
            # Only restore terminal states — running/pending jobs are stale after restart
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                _jobs[job.job_id] = job
        except Exception:
            pass


# Load persisted jobs on startup
_load_jobs()


def create_job() -> str:
    """Create a new job and return its ID."""
    job_id = str(uuid.uuid4())
    _jobs[job_id] = Job(job_id=job_id)
    _queues[job_id] = asyncio.Queue()
    return job_id


def get_job(job_id: str) -> Job | None:
    return _jobs.get(job_id)


def list_jobs() -> list[Job]:
    return sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)


async def emit(job_id: str, phase: str, message: str, data: Any = None):
    """Push a progress update to a job."""
    update = JobUpdate(phase=phase, message=message, data=data)
    job = _jobs.get(job_id)
    if job:
        job.updates.append(update)
    q = _queues.get(job_id)
    if q:
        await q.put(update)


async def subscribe(job_id: str) -> AsyncGenerator[JobUpdate, None]:
    """Async generator that yields updates for a job (for WebSocket streaming)."""
    q = _queues.get(job_id)
    if not q:
        return
    while True:
        try:
            update = await asyncio.wait_for(q.get(), timeout=60)
            yield update
            # Stop streaming when job finishes
            job = _jobs.get(job_id)
            if job and job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                if q.empty():
                    break
        except asyncio.TimeoutError:
            # Send a keepalive ping if no updates
            yield JobUpdate(phase="ping", message="")
            break


async def run_job(
    job_id: str,
    coro_factory: Callable[[], Any],
):
    """
    Run a coroutine as a background job, updating status/result.

    Usage:
        job_id = create_job()
        asyncio.create_task(run_job(job_id, lambda: do_work(job_id)))
    """
    job = _jobs.get(job_id)
    if not job:
        return

    job.status = JobStatus.RUNNING
    try:
        result = await coro_factory()
        job.result = result
        job.status = JobStatus.COMPLETED
        job.completed_at = datetime.utcnow().isoformat() + "Z"
        await emit(job_id, "done", "Investigation complete", result)
    except Exception as e:
        job.status = JobStatus.FAILED
        job.error = str(e)
        job.completed_at = datetime.utcnow().isoformat() + "Z"
        await emit(job_id, "error", f"Investigation failed: {e}")
    finally:
        _save_job(job)
