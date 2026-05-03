import asyncio
import sys
import datetime
from contextlib import asynccontextmanager

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.auth import check_auth
from backend.routers import kql, investigations, reports, enrichment, chat, mitre, geomap, analytics
from backend.routers import sentinel_health, automation, analytics_rules, incident_analytics, entity_exposure, hunting, workbooks
from backend.routers import backup as backup_router_mod, restore as restore_router_mod
from backend.routers import dcr


# ── Scheduled daily backup (02:00 UTC) ───────────────────────────────────────

async def _scheduled_backup_loop():
    while True:
        now      = datetime.datetime.utcnow()
        next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += datetime.timedelta(days=1)
        await asyncio.sleep((next_run - now).total_seconds())
        try:
            from backend.services.backup import run_backup
            from backend.services.jobs import create_job, run_job
            job_id = create_job()
            asyncio.create_task(run_job(job_id, lambda: run_backup(job_id=job_id, incremental=True)))
        except Exception as e:
            print(f"Scheduled backup failed: {e}")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_scheduled_backup_loop())
    yield
    task.cancel()


# ── Init ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Sentinel Vigil API",
    description="Standalone backend for the Sentinel Vigil platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS — allow the Vite dev server and any local frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(kql.router)
app.include_router(investigations.router)
app.include_router(reports.router)
app.include_router(enrichment.router)
app.include_router(chat.router)
app.include_router(mitre.router)
app.include_router(geomap.router)
app.include_router(analytics.router)
app.include_router(sentinel_health.router)
app.include_router(automation.router)
app.include_router(analytics_rules.router)
app.include_router(incident_analytics.router)
app.include_router(entity_exposure.router)
app.include_router(hunting.router)
app.include_router(workbooks.router)
app.include_router(backup_router_mod.router)
app.include_router(restore_router_mod.router)
app.include_router(dcr.router)


# ── System endpoints ──────────────────────────────────────────────────────────

@app.get("/api/config", tags=["system"])
async def get_config():
    """Return current configuration (non-sensitive values) and auth status."""
    auth = await check_auth()
    return JSONResponse({
        **settings.to_public_dict(),
        "auth": auth,
    })


@app.patch("/api/config", tags=["system"])
async def update_config(payload: dict):
    """Update configuration settings dynamically."""
    import json
    from pathlib import Path
    from backend.config import ROOT
    config_path = ROOT / "config.json"

    current = {}
    if config_path.exists():
        with open(config_path, "r") as f:
            current = json.load(f)

    if "output_dir" in payload:
        new_path = payload["output_dir"]
        current["output_dir"] = new_path
        settings.OUTPUT_DIR = Path(new_path)

    with open(config_path, "w") as f:
        json.dump(current, f, indent=4)

    return {"status": "updated", "config": settings.to_public_dict()}


@app.patch("/api/config/env", tags=["system"])
async def update_env_vars(payload: dict):
    """Update .env file and reload configuration in-memory (no restart required)."""
    from backend.config import ROOT
    from backend.auth import reset_credential
    from dotenv import set_key, load_dotenv
    env_path = ROOT / ".env"

    for key, value in payload.items():
        set_key(str(env_path), key, str(value))

    load_dotenv(str(env_path), override=True)
    settings.reload()
    reset_credential()

    return {"status": "updated", "message": "Configuration saved and reloaded successfully."}


@app.post("/api/auth/verify-settings", tags=["system"])
async def verify_settings_password(payload: dict):
    """Verify the settings page access password."""
    import hmac
    password = payload.get("password", "")
    if password and hmac.compare_digest(password, settings.SETTINGS_PASSWORD):
        return {"valid": True}
    return {"valid": False}


@app.get("/api/health", tags=["system"])
async def health():
    return {"status": "ok", "service": "security-investigator"}


# ── Serve React SPA (production container only) ───────────────────────────────
# frontend/dist is present only in the Docker image (built in Stage 1).
# In local dev the Vite dev server handles the frontend instead.
from pathlib import Path as _Path
from fastapi.staticfiles import StaticFiles as _StaticFiles
from fastapi.responses import FileResponse as _FileResponse

_DIST = _Path(__file__).parent.parent / "frontend" / "dist"
if _DIST.exists():
    # Serve Vite's hashed JS/CSS bundles
    app.mount("/assets", _StaticFiles(directory=_DIST / "assets"), name="frontend-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa_fallback(full_path: str):
        # Let unmatched /api/* surface as 404 instead of returning index.html
        if full_path.startswith("api/"):
            from fastapi import HTTPException
            raise HTTPException(status_code=404)
        # Serve static public assets (logos, favicon, etc.) that Vite copies
        # from frontend/public/ into dist/ root — otherwise they get index.html
        static_file = _DIST / full_path
        if static_file.is_file():
            return _FileResponse(static_file)
        return _FileResponse(_DIST / "index.html")


# ── Dev entrypoint (python -m backend.main) ──────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=settings.APP_HOST, port=settings.APP_PORT, reload=True)
