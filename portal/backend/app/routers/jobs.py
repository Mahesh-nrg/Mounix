import asyncio
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import update as sa_update
from sqlmodel import Session, select

from app.auth import verify_session
from app.config import UPLOADS_DIR
from app.db import get_session
from app.models import AnalysisMode, Job, JobLogLine, JobStatus, utc_now
from app.worker import enqueue

router = APIRouter(prefix="/api/jobs", tags=["jobs"], dependencies=[Depends(verify_session)])

ALLOWED_SUFFIXES = {".apk", ".xapk", ".apkm", ".apks"}


@router.get("")
def list_jobs(session: Session = Depends(get_session)) -> list[Job]:
    return list(session.exec(select(Job).order_by(Job.created_at.desc())))


@router.get("/{job_id}")
def get_job(job_id: uuid.UUID, session: Session = Depends(get_session)) -> Job:
    job = session.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/{job_id}/logs")
def get_job_logs(job_id: uuid.UUID, session: Session = Depends(get_session)) -> list[JobLogLine]:
    return list(
        session.exec(
            select(JobLogLine).where(JobLogLine.job_id == job_id).order_by(JobLogLine.id)
        )
    )


@router.post("")
async def create_job(file: UploadFile, session: Session = Depends(get_session)) -> Job:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type {suffix!r}; expected one of {sorted(ALLOWED_SUFFIXES)}",
        )

    job_id = uuid.uuid4()
    job_dir = UPLOADS_DIR / str(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)

    # `file.filename` is attacker-controlled (an uploaded APK's filename is never hand-typed by the
    # analyst - samples routinely come from untrusted zoos/shares) - Path.name strips any directory
    # component, and an absolute or `..`-laden filename can otherwise make `job_dir / filename`
    # resolve outside job_dir entirely (pathlib silently discards the left side when the right side
    # is absolute). The is_relative_to check is a defensive backstop, not the primary defense.
    safe_name = Path(file.filename or "").name or f"upload{suffix}"
    stored_path = job_dir / safe_name
    if not stored_path.resolve().is_relative_to(job_dir.resolve()):
        raise HTTPException(status_code=400, detail="Invalid filename")

    # A real APK/XAPK upload is tens to hundreds of MB - doing this copy synchronously on the
    # event loop would stall every other request (including the /ws/jobs/{id} log stream and the
    # worker's own awaits) for the whole write. Push it to a thread.
    def _write() -> None:
        with stored_path.open("wb") as out:
            shutil.copyfileobj(file.file, out)

    await asyncio.to_thread(_write)

    job = Job(
        id=job_id,
        original_filename=file.filename or stored_path.name,
        stored_path=str(stored_path),
        status=JobStatus.AWAITING_MODE,
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    return job


class StartJobRequest(BaseModel):
    mode: AnalysisMode
    # "emulator" | "physical" | "genymotion" - required for DAST modes. "physical" and
    # "genymotion" are both adb-over-network Android targets (adb connect <ip>:<port>, confirm
    # device state) - distinguished in the API/UI because Genymotion's default network is a
    # VirtualBox host-only adapter (typically 192.168.56.x) rather than the user's own LAN, and
    # because it's rootable/writable by design (userdebug build).
    device_target_type: str | None = None
    device_target_ip: str | None = None  # required when device_target_type is "physical" or "genymotion"


_DAST_MODES = {AnalysisMode.SAST_DAST, AnalysisMode.SAST_DAST_BURP}
_NETWORK_ADB_DEVICE_TYPES = ("physical", "genymotion")


@router.post("/{job_id}/start")
async def start_job(
    job_id: uuid.UUID, body: StartJobRequest, session: Session = Depends(get_session)
) -> Job:
    job = session.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if body.mode in _DAST_MODES:
        if body.device_target_type not in ("emulator", *_NETWORK_ADB_DEVICE_TYPES):
            raise HTTPException(
                status_code=400,
                detail=(
                    "device_target_type ('emulator', 'physical', or 'genymotion') is required "
                    "for this mode"
                ),
            )
        if body.device_target_type in _NETWORK_ADB_DEVICE_TYPES and not body.device_target_ip:
            raise HTTPException(
                status_code=400,
                detail=(
                    "device_target_ip is required when device_target_type is "
                    "'physical' or 'genymotion'"
                ),
            )

    device_target_type = body.device_target_type if body.mode in _DAST_MODES else None
    device_target_ip = (
        body.device_target_ip
        if body.mode in _DAST_MODES and body.device_target_type in _NETWORK_ADB_DEVICE_TYPES
        else None
    )

    # Atomic check-and-set, not a check-then-act race: the old code did `session.get()`, checked
    # `job.status != AWAITING_MODE` in Python, then set fields and committed - two concurrent
    # `POST .../start` calls for the same job_id could both pass that check before either commit
    # landed, both call `enqueue()`, and the job would run twice. Folding the status check into the
    # UPDATE's WHERE clause makes the AWAITING_MODE -> QUEUED transition itself the atomicity
    # boundary: only one concurrent UPDATE can match the row (the loser's WHERE matches 0 rows,
    # since the winner already flipped `status` to QUEUED), so at most one caller ever observes
    # `rowcount == 1` - the other gets the existing 409, exactly as if it had lost the old
    # Python-level race, just without the window where both could win.
    result = session.execute(
        sa_update(Job)
        .where(Job.id == job_id, Job.status == JobStatus.AWAITING_MODE)
        .values(
            analysis_mode=body.mode,
            device_target_type=device_target_type,
            device_target_ip=device_target_ip,
            status=JobStatus.QUEUED,
            updated_at=utc_now(),
        )
    )
    if result.rowcount != 1:
        session.rollback()
        raise HTTPException(
            status_code=409, detail=f"Job is not awaiting a mode (status={job.status})"
        )
    session.commit()

    # A Core `update()` doesn't refresh the ORM instance already loaded above in place - re-fetch
    # to return the row's current state to the caller.
    session.expire(job)
    job = session.get(Job, job_id)

    await enqueue(job.id)
    return job


@router.post("/{job_id}/confirm_burp")
async def confirm_burp(job_id: uuid.UUID, session: Session = Depends(get_session)) -> dict:
    job = session.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != JobStatus.AWAITING_BURP_CONFIRM:
        raise HTTPException(
            status_code=409,
            detail=f"Job is not awaiting Burp confirmation (status={job.status})",
        )
    from app.services.pipeline import confirm_burp_restart

    if not confirm_burp_restart(job_id):
        raise HTTPException(
            status_code=409,
            detail=(
                "no pending Burp confirmation for this job - it may have already been "
                "confirmed, or the backend restarted while it was paused"
            ),
        )
    return {"ok": True}
