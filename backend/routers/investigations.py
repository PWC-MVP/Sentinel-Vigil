"""
Investigations API router.
Provides endpoints for launching and monitoring investigations.
"""
import asyncio
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
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


@router.post("/analyze-incident")
async def analyze_incident(payload: dict):
    """Analyze a specific security incident with LLM and return recommendations."""
    from backend.services import llm as llm_svc

    incident = payload.get("incident", {})
    context = payload.get("context", {})

    system = (
        "You are ARIA, an elite Tier-3 Cyber Security Analyst for the PwC Sentinel Engineering Team. "
        "Analyze the provided Microsoft Sentinel security incident and deliver:\n"
        "1. A concise severity and impact assessment\n"
        "2. Likely attack pattern or MITRE ATT&CK technique\n"
        "3. Immediate recommended response actions (ranked by priority)\n"
        "4. Longer-term remediation steps\n"
        "5. Related indicators or hunting queries to consider\n\n"
        "Use markdown formatting with clear headings. Be direct, evidence-based, and actionable. "
        "Always include a risk summary table."
    )

    risk_factors = context.get("risk_factors", [])
    mitigating_factors = context.get("mitigating_factors", [])
    user_msg = (
        f"Analyze the following Microsoft Sentinel security incident:\n\n"
        f"## Incident Details\n"
        f"- **ID**: {incident.get('ProviderIncidentId', 'N/A')}\n"
        f"- **Title**: {incident.get('Title', 'Unknown')}\n"
        f"- **Severity**: {incident.get('Severity', 'Unknown')}\n"
        f"- **Status**: {incident.get('Status', 'Unknown')}\n"
        f"- **Created**: {incident.get('CreatedTime', 'Unknown')}\n\n"
        f"## Investigation Context\n"
        f"- **User Under Investigation**: {context.get('upn', 'Unknown')}\n"
        f"- **Overall Risk Level**: {context.get('risk_level', 'Unknown')}\n"
        f"- **Risk Factors**: {', '.join(risk_factors) if risk_factors else 'None'}\n"
        f"- **Mitigating Factors**: {', '.join(mitigating_factors) if mitigating_factors else 'None'}\n"
        f"- **Anomalies Detected**: {context.get('anomaly_count', 0)}\n"
        f"- **Total Incidents on User**: {context.get('incident_count', 0)}\n\n"
        "Provide a thorough analysis with actionable recommendations."
    )

    try:
        result = await llm_svc.complete(system, user_msg)
        return {"analysis": result["text"], "usage": result.get("usage", {})}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM analysis failed: {str(e)}")


@router.post("/export-html-report")
async def start_html_report_export(payload: dict):
    """
    Queue an HTML report generation job and return its ID immediately.
    Avoids gateway timeouts on slow report generation — poll the GET endpoint below.
    """
    from backend.services.investigation import generate_html_report

    upn = payload.get("upn", "unknown")
    job_id = job_svc.create_job()

    async def _gen():
        from pathlib import Path
        report_path = await asyncio.get_running_loop().run_in_executor(
            None, generate_html_report, payload, upn
        )
        return {"report_path": str(report_path), "filename": report_path.name, "upn": upn}

    asyncio.create_task(job_svc.run_job(job_id, _gen))
    return {"job_id": job_id, "status": "pending"}


@router.get("/export-html-report/{export_job_id}")
async def poll_html_report_export(export_job_id: str):
    """
    Poll a queued HTML export job.
    Returns the HTML file (Content-Type: text/html) when done, or
    JSON { job_id, status } while still pending/running.
    """
    from pathlib import Path

    job = job_svc.get_job(export_job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Export job not found")

    if job.status == "failed":
        raise HTTPException(status_code=500, detail=f"Report generation failed: {job.error or 'unknown error'}")

    if job.status == "completed" and job.result:
        report_path = Path(job.result.get("report_path", ""))
        upn = job.result.get("upn", "unknown")
        if not report_path.exists():
            raise HTTPException(status_code=500, detail="Report file missing after generation")
        content = report_path.read_text(encoding="utf-8")
        return HTMLResponse(
            content=content,
            headers={"Content-Disposition": f'attachment; filename="Investigation_{upn}.html"'},
        )

    return {"job_id": export_job_id, "status": str(job.status)}
