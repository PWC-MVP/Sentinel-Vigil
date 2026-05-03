"""Restore endpoints — POST /api/restore"""
import asyncio
from typing import Optional, List

from fastapi import APIRouter
from pydantic import BaseModel

from backend.services.jobs import create_job, run_job
from backend.services.restore import restore_from_snapshot

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
    asyncio.create_task(
        run_job(
            job_id,
            lambda: restore_from_snapshot(
                job_id=job_id,
                snapshot_path=req.snapshot_path,
                resource_types=req.resource_types,
                target_workspace=req.target_workspace,
                target_subscription=req.target_subscription,
                target_rg=req.target_rg,
                dry_run=req.dry_run,
            ),
        )
    )
    return {"job_id": job_id}
