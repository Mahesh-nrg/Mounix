import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlmodel import Session, select

from app.config import settings
from app.db import engine
from app.events import bus
from app.models import JobLogLine

router = APIRouter()

_serializer = URLSafeTimedSerializer(settings.session_secret, salt="mobile-pt-session")


def _is_authenticated(websocket: WebSocket) -> bool:
    token = websocket.cookies.get(settings.session_cookie_name)
    if not token:
        return False
    try:
        data = _serializer.loads(token, max_age=settings.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return False
    return bool(data.get("authenticated"))


@router.websocket("/ws/jobs/{job_id}")
async def job_log_stream(websocket: WebSocket, job_id: uuid.UUID) -> None:
    if not _is_authenticated(websocket):
        await websocket.close(code=4401)
        return

    await websocket.accept()

    with Session(engine) as session:
        existing = session.exec(
            select(JobLogLine).where(JobLogLine.job_id == job_id).order_by(JobLogLine.id)
        )
        for line in existing:
            await websocket.send_json(
                {"type": "log", "level": line.level, "message": line.message}
            )

    queue = bus.subscribe(job_id)
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(job_id, queue)
