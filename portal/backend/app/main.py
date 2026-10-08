import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.auth import router as auth_router
from app.config import PORTAL_ROOT
from app.db import init_db
from app.routers.device import router as device_router
from app.routers.jobs import router as jobs_router
from app.routers.ws import router as ws_router
from app.services.pipeline import reconcile_orphaned_jobs
from app.worker import start as start_worker

logger = logging.getLogger(__name__)

FRONTEND_DIST = PORTAL_ROOT / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Any job left in an in-flight status from before this process started (backend crash/restart
    # while a scan was running, including one paused at AWAITING_BURP_CONFIRM) has no coroutine
    # left driving it - worker.py's queue is in-memory only and nothing repopulates it from the DB
    # on startup. Mark those jobs FAILED once, up front, rather than let them sit stuck forever.
    reconciled = await reconcile_orphaned_jobs()
    logger.info("Startup reconciliation: %d orphaned job(s) marked FAILED", reconciled)
    start_worker()
    yield


app = FastAPI(title="Mobile PT Automation Portal", lifespan=lifespan)

app.include_router(auth_router)
app.include_router(jobs_router)
app.include_router(device_router)
app.include_router(ws_router)

if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
