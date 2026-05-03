"""
Investigations API router.
Provides endpoints for launching and monitoring investigations.
"""
import asyncio
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from backend.services import jobs as job_svc
from backend.services import investigation as inv_svc

router = APIRouter(prefix="/api/investigations", tags=["investigations"])


class InvestigationRequest(BaseModel):
    upn: str
    days_back: int = 7
    output_mode: str = "inline"        # "inline" | "html" | "both"
    include_cloud: bool = True        # CloudAppEvents
    include_office: bool = True       # OfficeActivity
    include_audit: bool = True        # AuditLogs
    include_identity: bool = True     # Devices, Risk Profile
    generate_summary: bool = False    # AI Summary


@router.post("")
async def start_investigation(req: InvestigationRequest):
    """Launch a background investigation job and return its ID."""
    job_id = job_svc.create_job()

    # Compute date range
    end_dt = datetime.utcnow()
    start_dt = end_dt - timedelta(days=req.days_back)
    start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    asyncio.create_task(
        job_svc.run_job(
            job_id,
            lambda: inv_svc.run_investigation(
                job_id=job_id,
                upn=req.upn,
                start_date=start_str,
                end_date=end_str,
                output_mode=req.output_mode,
                include_cloud=req.include_cloud,
                include_office=req.include_office,
                include_audit=req.include_audit,
                include_identity=req.include_identity,
                generate_summary=req.generate_summary,
            ),
        )
    )
    return {"job_id": job_id, "status": "pending"}


@router.get("")
async def list_investigations():
    """List all investigation jobs."""
    return {"investigations": [j.model_dump() for j in job_svc.list_jobs()]}


@router.get("/{job_id}")
async def get_investigation(job_id: str):
    """Retrieve the full status and result of an investigation job."""
    job = job_svc.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.model_dump()


@router.websocket("/ws/{job_id}")
async def investigation_ws(websocket: WebSocket, job_id: str):
    """
    WebSocket endpoint that streams real-time investigation progress.
    Connect immediately after POST /api/investigations and receive live phase updates.
    """
    job = job_svc.get_job(job_id)
    if not job:
        await websocket.close(code=4004)
        return

    await websocket.accept()
    try:
        # First send all buffered updates already collected
        for update in job.updates:
            await websocket.send_json(update.model_dump())

        # Then stream new updates
        async for update in job_svc.subscribe(job_id):
            if update.phase == "ping":
                try:
                    await websocket.send_json({"phase": "ping", "message": ""})
                except Exception:
                    break
            else:
                await websocket.send_json(update.model_dump())

    except WebSocketDisconnect:
        pass
    except Exception:
        pass


@router.post("/export-html-report")
async def export_investigation_html(result: dict):
    """Generate and return a styled HTML report from investigation results."""
    from backend.services.investigation import generate_html_report
    try:
        upn = result.get("upn", "unknown")
        # Generate the report using the shared generator
        report_path = await asyncio.get_event_loop().run_in_executor(
            None, generate_html_report, result, upn
        )
        # Read the generated report
        content = report_path.read_text(encoding="utf-8")
        
        return HTMLResponse(
            content=content,
            headers={"Content-Disposition": f'attachment; filename="Investigation_{upn}.html"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")
