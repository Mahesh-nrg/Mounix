"""MobSF REST API client: static analysis (SAST), and - added for the SAST+DAST analysis modes -
MobSF's own Dynamic Analyzer.

`mobsfy()`/the dynamic-analysis endpoints in this module target WHICHEVER device the user picked
for the job - the AVD emulator or a physical Android device connected via adb
(`Job.device_target_type`, chosen per job in the New Scan UI, resolved to a serial by
`pipeline.py`'s `resolve_device_serial()`). MobSF's own device setup requires `/system` mounted
writable; this AVD build cannot safely provide that (`adb disable-verity` reliably prevents the
guest from ever reaching `boot_completed` again on this image, confirmed three independent ways), while a physical device has no such constraint. Picking the emulator for a
DAST mode is still allowed by the API - it will predictably fail here the same way #14 describes,
which is an accepted tradeoff the user makes per job, not something this module or `pipeline.py`
blocks.

MobSF's dynamic analyzer is still never run concurrently with Burp against the same live session -
they'd both want to own the interception proxy (see ARCHITECTURE.md). Instead, for the
`sast_dast_burp` mode, the pipeline runs MobSF's dynamic analysis to completion first (this module),
resets the device (`unset_global_proxy`/`remove_root_ca`), and only then hands off to Burp via the
existing Frida+Burp pipeline in `pipeline.py` - against that same resolved device, not a different
one.

All calls use `Authorization: <api_key>` (no bearer/basic scheme) - same as `upload_and_scan`.

IMPORTANT, confirmed live this session: `mobsfy()` makes MobSF run `adb kill-server` + `adb root` +
`adb remount` against the target device internally (its own `Environment.connect_n_mount()`), then
reconfigures that device's CA trust store, global proxy, and Frida instrumentation. This WILL
disrupt any other concurrent adb session on the host, and when the target is a physical device,
reconfigures real hardware - it isn't a rare failure mode, it's an unconditional side effect of
calling this module's functions. This module does not (and cannot) suppress that; the caller
(`pipeline.py`) is responsible for warning the user before calling `mobsfy()` and for
verifying/recovering device connectivity afterward.
"""

import asyncio
import logging
from pathlib import Path

import httpx

from app.config import REPO_ROOT, settings

logger = logging.getLogger(__name__)


class MobsfError(RuntimeError):
    pass


def _headers() -> dict[str, str]:
    return {"Authorization": settings.mobsf_api_key}


# Must match mobile_pt.sh's own MOBSF_CONTAINER_NAME/MOBSF_IMAGE/MOBSF_DATA_DIR/MOBSF_ADB_HOME_DIR -
# this module recreates the same container mobile_pt.sh manages, just with a different identifier.
_MOBSF_CONTAINER_NAME = "mobsf"
_MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
_MOBSF_DATA_DIR = str(REPO_ROOT / "mobsf_data")
_MOBSF_ADB_HOME_DIR = str(REPO_ROOT / "mobsf_adb_home")


async def _current_container_identifier() -> str | None:
    proc = await asyncio.create_subprocess_exec(
        "docker", "inspect", _MOBSF_CONTAINER_NAME,
        "--format", "{{range .Config.Env}}{{println .}}{{end}}",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await proc.communicate()
    if proc.returncode != 0:
        return None
    for line in out.decode(errors="replace").splitlines():
        if line.startswith("MOBSF_ANALYZER_IDENTIFIER="):
            return line.split("=", 1)[1]
    return None


async def ensure_mobsf_targets(serial: str) -> None:
    """MobSF's `mobsfy()` accepts a per-request `identifier`, but its other device-facing endpoints
    (`root_ca`, `global_proxy`, and presumably the dynamic-analysis endpoints too) do NOT - they
    always resolve "the device" via `Environment()` with no identifier, which falls back to the
    `MOBSF_ANALYZER_IDENTIFIER` env var baked into the container at start time (confirmed live: right
    after a `mobsfy(genymotion_serial)` call correctly targeted Genymotion, the very next
    `global_proxy()` call failed against a stale identifier from an earlier job's device, since env
    vars can't be changed on a running process without restarting it).

    Since this pipeline supports picking a different device per job, the container's baked-in
    identifier has to be kept in sync with whichever device the CURRENT job resolved to, or every
    call after `mobsfy()` silently targets the wrong device. This recreates the container (matching
    `mobile_pt.sh`'s own `start_mobsf()` invocation exactly, just with a different identifier) only
    when it doesn't already match - a no-op most of the time if the same device is used repeatedly.
    """
    current = await _current_container_identifier()
    if current == serial:
        return

    logger.info("Recreating MobSF container to target %s (was %s)", serial, current)
    kill = await asyncio.create_subprocess_exec(
        "docker", "rm", "-f", _MOBSF_CONTAINER_NAME,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await kill.communicate()

    run = await asyncio.create_subprocess_exec(
        "docker", "run", "-d",
        "--name", _MOBSF_CONTAINER_NAME,
        "--network", "host",
        "--restart", "unless-stopped",
        "-v", f"{_MOBSF_DATA_DIR}:/home/mobsf/.MobSF",
        "-v", f"{_MOBSF_ADB_HOME_DIR}:/home/mobsf/.android",
        "-e", f"MOBSF_ANALYZER_IDENTIFIER={serial}",
        "-e", "MOBSF_PLATFORM=",
        _MOBSF_IMAGE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, run_err = await run.communicate()
    if run.returncode != 0:
        raise MobsfError(f"Failed to recreate MobSF container: {run_err.decode(errors='replace')}")

    async with httpx.AsyncClient() as client:
        for _ in range(40):
            try:
                resp = await client.get(settings.mobsf_url, timeout=5)
                if resp.status_code in (200, 302):
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(3)
    raise MobsfError(f"MobSF did not come back up after recreating it to target {serial}")


async def upload_and_scan(apk_path: Path) -> dict:
    # Read off the event loop: an APK/XAPK is easily tens to hundreds of MB, and handing httpx an
    # open file object for `files=` makes it perform blocking reads on this same loop while
    # streaming the multipart body - during a call that's meant to run in the *background*,
    # alongside the dynamic pipeline, without stalling it.
    apk_bytes = await asyncio.to_thread(apk_path.read_bytes)

    async with httpx.AsyncClient(base_url=settings.mobsf_url, timeout=60) as client:
        resp = await client.post(
            "/api/v1/upload",
            headers=_headers(),
            files={"file": (apk_path.name, apk_bytes, "application/octet-stream")},
        )
        resp.raise_for_status()
        upload_info = resp.json()

        scan_resp = await client.post(
            "/api/v1/scan",
            headers=_headers(),
            data={"hash": upload_info["hash"]},
            timeout=300,
        )
        scan_resp.raise_for_status()
        return {"hash": upload_info["hash"], "report_url": f"{settings.mobsf_url}/static_analyzer/{upload_info['hash']}"}


async def _post(path: str, data: dict, timeout: int = 60) -> dict:
    async with httpx.AsyncClient(base_url=settings.mobsf_url, timeout=timeout) as client:
        resp = await client.post(path, headers=_headers(), data=data)
        if resp.status_code >= 400:
            # The raw response body is logged server-side only - it can be long, poorly formatted,
            # or otherwise unsuitable for display, and this exception's message becomes a job's
            # user-facing `failure_reason` in the portal UI (see pipeline.py's `_set_status` calls).
            logger.error(
                "MobSF API call to %s failed (%s): %s", path, resp.status_code, resp.text
            )
            raise MobsfError(f"MobSF API call to {path} failed ({resp.status_code})")
        return resp.json()


async def mobsfy(identifier: str) -> dict:
    """Configure MobSF's dynamic-analysis environment against `identifier` (an adb serial, e.g.
    "emulator-5554"). See this module's docstring: this is the call that runs `adb kill-server` +
    `adb root` + `adb remount` internally - never call this without warning the user first."""
    return await _post("/api/v1/android/mobsfy", {"identifier": identifier}, timeout=90)


async def install_root_ca() -> dict:
    return await _post("/api/v1/android/root_ca", {"action": "install"})


async def remove_root_ca() -> dict:
    return await _post("/api/v1/android/root_ca", {"action": "remove"})


async def set_global_proxy() -> dict:
    return await _post("/api/v1/android/global_proxy", {"action": "set"})


async def unset_global_proxy() -> dict:
    return await _post("/api/v1/android/global_proxy", {"action": "unset"})


async def start_dynamic_analysis(file_hash: str) -> dict:
    return await _post("/api/v1/dynamic/start_analysis", {"hash": file_hash}, timeout=120)


async def instrument_frida(file_hash: str) -> dict:
    return await _post(
        "/api/v1/frida/instrument",
        {
            "hash": file_hash,
            "default_hooks": "true",
            "auxiliary_hooks": "true",
            "frida_code": "",
        },
        timeout=90,
    )


async def run_activity_tester(file_hash: str) -> dict:
    """Best-effort supplementary automated test - never raises. Not a required pipeline step."""
    try:
        return await _post("/api/v1/android/activity", {"test": "dfa", "hash": file_hash}, timeout=120)
    except Exception:
        # Best-effort and never fatal to the pipeline (see docstring above and pipeline.py's caller),
        # but a silent failure here was previously invisible anywhere - log it so a real problem
        # (e.g. a config issue) is still visible in the backend's own logs.
        logger.exception("run_activity_tester failed (non-fatal, continuing without activity report)")
        return {}


async def stop_dynamic_analysis(file_hash: str) -> dict:
    return await _post("/api/v1/dynamic/stop_analysis", {"hash": file_hash}, timeout=180)


async def get_dynamic_report(file_hash: str) -> dict:
    # 60s, then 180s, were both too short - confirmed live:
    # report_json's own report generation includes a malware/Maltrail domain-reputation DB check
    # whose duration is genuinely variable and outside this codebase's control (an external
    # threat-intel source's own availability/speed) - one run took ~187s (barely over the 180s
    # timeout that had already been bumped once for this exact reason), another took ~3m25s. An
    # httpx.ReadTimeout here previously stringified to an EMPTY string too - which made the
    # resulting pipeline failure look like a mysterious blank error ("Pipeline error: ") with no
    # clue what actually happened (also fixed separately, in pipeline.py's outer handler). Given
    # the demonstrated real-world variability, this needs a genuinely generous ceiling, not another
    # incremental bump - 600s comfortably covers even a slow first-time DB fetch.
    report = await _post("/api/v1/dynamic/report_json", {"hash": file_hash}, timeout=600)
    report["report_url"] = f"{settings.mobsf_url}/dynamic_report/{file_hash}"
    return report
