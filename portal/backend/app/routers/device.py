from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth import verify_session
from app.services import adb_service, burp_service, device_lifecycle

router = APIRouter(prefix="/api/device", tags=["device"], dependencies=[Depends(verify_session)])


class DeviceCheckRequest(BaseModel):
    target_type: Literal["emulator", "physical", "genymotion"]
    ip: str | None = None


@router.post("/check")
async def check_device(body: DeviceCheckRequest) -> dict:
    """Live adb-connectivity check for whichever device the user is about to pick for a job -
    called from the New Scan UI before `POST /api/jobs/{id}/start`, so a bad IP or an unauthorized
    phone is caught before a job is queued, not partway through the pipeline."""
    if body.target_type == "emulator":
        # Only checks current state - does NOT boot the emulator (that's `ensure_running()`,
        # used later by the pipeline itself if the user actually picks this target).
        try:
            serial = await adb_service.get_running_serial()
        except adb_service.AdbError as e:
            return {"ok": False, "error": str(e)}
        if serial:
            return {"ok": True, "serial": serial}
        return {"ok": False, "error": "emulator not running - launch it via mobile_pt.sh first"}

    # "physical" and "genymotion" are both just adb-over-network Android targets - a Genymotion VM
    # is reached the exact same way (`adb connect <ip>:<port>`, confirm `device` state) as a real
    # phone on the LAN. The only difference is which network the IP is expected to live on
    # (Genymotion's default VirtualBox host-only adapter, typically 192.168.56.x, vs. the user's own
    # LAN for a physical device) and that it's rootable/writable by design (userdebug build) - which
    # is exactly why it's distinguished in the UI/API rather than folded silently into "physical".
    if not body.ip:
        return {"ok": False, "error": "IP address is required for a physical or genymotion device"}
    try:
        serial = await adb_service.connect_and_check_physical(body.ip)
        return {"ok": True, "serial": serial}
    except adb_service.AdbError as e:
        return {"ok": False, "error": str(e)}


@router.get("/status")
async def get_status() -> dict:
    mobile_pt_status = await device_lifecycle.status()
    burp_health = await burp_service.api_health()
    burp_proxy_up = await burp_service.is_proxy_listening()
    return {
        "mobile_pt_status": mobile_pt_status,
        "burp_api": burp_health,
        "burp_proxy_listening": burp_proxy_up,
    }


@router.post("/start")
async def start_device() -> dict:
    await device_lifecycle.ensure_running()
    return {"ok": True}
