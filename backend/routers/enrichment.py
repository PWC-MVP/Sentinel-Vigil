"""
IP Enrichment API router.
Wraps the existing enrich_ips.py module.
"""
import asyncio
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.services import jobs as job_svc

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

router = APIRouter(prefix="/api/enrich", tags=["enrichment"])


class EnrichRequest(BaseModel):
    ips: list[str]


@router.post("/ips")
async def enrich_ips(req: EnrichRequest):
    """
    Asynchronously enrich a list of IP addresses.
    Returns a job_id to poll for results.
    """
    if not req.ips:
        raise HTTPException(status_code=400, detail="At least one IP address required")
    if len(req.ips) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 IPs per request")

    job_id = job_svc.create_job()

    async def run():
        await job_svc.emit(job_id, "start", f"Enriching {len(req.ips)} IP addresses...")
        try:
            import enrich_ips as enrich_module  # type: ignore
            loop = asyncio.get_event_loop()

            await job_svc.emit(job_id, "enriching", "Querying ipinfo.io, AbuseIPDB, vpnapi.io...")
            results = await loop.run_in_executor(
                None,
                lambda: enrich_module.enrich_ips(req.ips, max_workers=5),
            )
            await job_svc.emit(job_id, "done", f"Enriched {len(results)} IPs", results)
            return results
        except Exception as e:
            await job_svc.emit(job_id, "error", f"Enrichment failed: {e}")
            raise

    asyncio.create_task(job_svc.run_job(job_id, run))
    return {"job_id": job_id}


@router.get("/ips/{job_id}")
async def get_enrichment_result(job_id: str):
    """Get the enrichment result for a job."""
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "status": job.status,
        "results": job.result or [],
        "updates": [u.model_dump() for u in job.updates],
        "error": job.error,
    }
