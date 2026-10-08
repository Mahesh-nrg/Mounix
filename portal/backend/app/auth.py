import bcrypt
from fastapi import APIRouter, Cookie, HTTPException, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel

from app.config import settings

router = APIRouter(prefix="/api", tags=["auth"])

_serializer = URLSafeTimedSerializer(settings.session_secret, salt="mobile-pt-session")


def _make_session_token() -> str:
    return _serializer.dumps({"authenticated": True})


def verify_session(mobile_pt_session: str | None = Cookie(default=None)) -> None:
    if not mobile_pt_session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = _serializer.loads(mobile_pt_session, max_age=settings.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    if not data.get("authenticated"):
        raise HTTPException(status_code=401, detail="Not authenticated")


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(body: LoginRequest, response: Response):
    # Generic failure message for both a wrong username and a wrong password - don't reveal
    # which one was incorrect.
    valid_username = body.username == settings.portal_username
    valid_password = bcrypt.checkpw(body.password.encode(), settings.portal_password_hash.encode())
    if not (valid_username and valid_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = _make_session_token()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.session_max_age_seconds,
    )
    return {"ok": True}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(settings.session_cookie_name)
    return {"ok": True}
