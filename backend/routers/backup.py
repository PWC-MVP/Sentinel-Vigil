"""Backup endpoints — POST /api/backup, GET /api/backup/snapshots, POST /api/backup/compare"""
import asyncio
from typing import Optional, List

from fastapi import APIRouter
from pydantic import BaseModel

from backend.services.jobs import create_job, run_job
from backend.services.backup import run_backup, list_snapshots, compare_snapshots

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
    asyncio.create_task(
        run_job(
            job_id,
            lambda: run_backup(
                job_id=job_id,
                resource_types=req.resource_types,
                output_dir=req.output_dir,
                incremental=req.incremental,
            ),
        )
    )
    return {"job_id": job_id}


@router.get("/snapshots")
async def get_snapshots(output_dir: Optional[str] = None):
    return {"snapshots": list_snapshots(output_dir)}


@router.post("/compare")
async def compare_backup_snapshots(req: CompareRequest):
    return compare_snapshots(req.snapshot_a, req.snapshot_b)
