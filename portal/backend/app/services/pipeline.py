"""The job state machine. Branches on `job.analysis_mode` (see ARCHITECTURE.md for the full
design):

  sast            -> PARSING -> MobSF static scan -> DONE
  sast_dast       -> ... -> MobSF static scan -> DEVICE_CHECK -> MOBSF_DAST (MobSF's own dynamic
                     analyzer, via its REST API) -> DONE
  sast_dast_burp  -> ... same MobSF DAST phase ... -> AWAITING_BURP_CONFIRM (paused, waiting for
                     explicit user confirmation - see confirm_burp_restart) -> restart Burp with a
                     fresh per-job project file -> the same Frida+Burp dynamic pipeline proven
                     working earlier this session (CA_TRUST -> PROXY_SET -> FRIDA_ATTACH ->
                     STATIC_PATCH fallback) -> DONE

MOBSF_DAST, CA_TRUST/PROXY_SET/FRIDA_ATTACH (the Burp phase) all target EITHER the AVD emulator or
a physical Android device connected via adb - the user picks per job (`Job.device_target_type` /
`device_target_ip`, set at `POST /api/jobs/{id}/start`), and the New Scan UI runs a live
connectivity check (`POST /api/device/check`) before a job is even queued. Whichever device is
picked drives the *whole* job - `resolve_device_serial()` resolves one serial, used for both the
MOBSF_DAST phase and (mode 3) the Burp phase, never a mix of the two.

Why this choice exists instead of hardcoding one target: MobSF's own `mobsfy()` requires `/system`
writable, which this AVD build cannot safely provide - `disable-verity` reliably prevents the guest
from ever reaching `boot_completed` again on this image (confirmed three independent ways). A
physical device has no such constraint, but requires the analyst to actually have hardware
connected via adb. Picking the emulator for a DAST mode is still allowed - it will predictably fail
`mobsfy()`'s writability check - that tradeoff is the user's to make per job, not hardcoded here.

IMPORTANT: MobSF's own `mobsfy()` call (used in the MOBSF_DAST phase) runs `adb kill-server` +
`adb root` + `adb remount` internally, and then reconfigures the target device's CA trust store,
global proxy, and Frida instrumentation. This WILL disrupt any other concurrent adb session, and
when the target is a physical device, reconfigures real hardware (not just a brief adb blip) - see
mobsf_service.py's docstring. The warning logged before calling it is not optional decoration, it's
the only mitigation there is.
"""

import asyncio
import logging
import uuid
from pathlib import Path

import apkfile
from sqlmodel import Session, select

from app.config import CERTS_DIR
from app.db import engine
from app.events import bus
from app.models import AnalysisMode, Job, JobLogLine, JobStatus, utc_now
from app.services import (
    adb_service,
    apk_inspect,
    apktool_service,
    burp_service,
    device_lifecycle,
    frida_service,
    mobsf_service,
)
from app.services.apk_inspect import ParsedApp

logger = logging.getLogger(__name__)

CA_MARKER_FILE = CERTS_DIR / ".ca_trusted_hash"

# Statuses a job never actively runs under: AWAITING_MODE (uploaded, not started yet) and
# DONE/FAILED (already finished). Every other status means "in-flight, some coroutine is supposed
# to be driving this job" - used by `reconcile_orphaned_jobs()` at startup, see its docstring.
_NOT_IN_FLIGHT_STATUSES = (JobStatus.AWAITING_MODE, JobStatus.DONE, JobStatus.FAILED)

# Keyed by job_id, set by the `POST /api/jobs/{id}/confirm_burp` endpoint (app/routers/jobs.py) to
# unblock a pipeline task paused at AWAITING_BURP_CONFIRM. Same shape as frida_service's
# _active_sessions registry - a small, process-lifetime, per-job dict is an accepted tradeoff for
# this single-user local tool (see that module's docstring for the precedent).
_burp_confirm_events: dict[uuid.UUID, asyncio.Event] = {}


def confirm_burp_restart(job_id: uuid.UUID) -> bool:
    """Unblock a pipeline task paused at AWAITING_BURP_CONFIRM. Returns True if a pending
    confirmation event was actually found and set, False otherwise (no such job_id is registered -
    e.g. it was already confirmed, the job was never paused there, or the backend restarted and
    lost this in-memory registry). Callers must check the return value: silently reporting success
    when nothing happened hides exactly the "already confirmed" / "registry lost on restart" cases
    this is meant to catch (see routers/jobs.py's confirm_burp endpoint)."""
    event = _burp_confirm_events.get(job_id)
    if event is None:
        return False
    event.set()
    return True


async def reconcile_orphaned_jobs() -> int:
    """Called once, automatically, at backend startup (see app/main.py's lifespan). Fixes two
    related "job gets silently stuck forever" bugs that a backend restart otherwise causes:

    1. A job paused at AWAITING_BURP_CONFIRM is waiting on an in-memory `asyncio.Event` in
       `_burp_confirm_events` above - a process restart loses that dict (and the coroutine
       awaiting it) for good, but the DB still shows AWAITING_BURP_CONFIRM forever.
    2. A job left in any other in-flight status (QUEUED, PARSING, DEVICE_CHECK, MOBSF_DAST,
       INSTALLING, CA_TRUST, PROXY_SET, FRIDA_ATTACH, STATIC_PATCH) has no running coroutine either
       - `worker.py`'s job queue is a plain in-memory `asyncio.Queue`, nothing re-populates it from
       the DB on startup - so it's equally stuck.

    Deliberately does NOT attempt to resume any interrupted pipeline step - for a single-user local
    tool, that's not worth the risk of leaving a device half-configured (CA trusted but proxy not
    set, an app installed but Frida never attached, etc.). Instead every such job is simply marked
    FAILED with a reason that tells the user to start over, so the UI never shows a job silently
    frozen mid-status. Returns the number of jobs reconciled (0 on a clean start is expected)."""
    count = 0
    with Session(engine) as session:
        orphaned = session.exec(
            select(Job).where(Job.status.not_in(_NOT_IN_FLIGHT_STATUSES))
        ).all()
        for job in orphaned:
            old_status = job.status
            job.status = JobStatus.FAILED
            job.failure_reason = (
                f"Backend restarted while this job was in progress (status was {old_status}) - "
                "please start a new scan."
            )
            job.updated_at = utc_now()
            session.add(job)
            logger.info("Reconciled orphaned job %s (was %s) -> FAILED", job.id, old_status.value)
            count += 1
        session.commit()
    return count


async def _log(job_id: uuid.UUID, message: str, level: str = "info") -> None:
    with Session(engine) as session:
        session.add(JobLogLine(job_id=job_id, level=level, message=message))
        session.commit()
    await bus.publish(job_id, {"type": "log", "level": level, "message": message})


async def _set_status(job_id: uuid.UUID, status: JobStatus, **fields) -> None:
    with Session(engine) as session:
        job = session.get(Job, job_id)
        job.status = status
        for key, value in fields.items():
            setattr(job, key, value)
        job.updated_at = utc_now()
        session.add(job)
        session.commit()
    await bus.publish(job_id, {"type": "status", "status": status.value, **fields})


async def _save_job_field(job_id: uuid.UUID, **fields) -> None:
    with Session(engine) as session:
        job = session.get(Job, job_id)
        for key, value in fields.items():
            setattr(job, key, value)
        session.add(job)
        session.commit()


async def _run_mobsf_static_scan(job_id: uuid.UUID, apk_path: Path) -> dict:
    """Awaited, not backgrounded: sast_dast/sast_dast_burp need the resulting `hash` before they
    can start MobSF's dynamic analyzer, and mode `sast` needs it as its only step anyway."""
    result = await mobsf_service.upload_and_scan(apk_path)
    await _save_job_field(job_id, mobsf_report_url=result["report_url"])
    await _log(job_id, f"MobSF static report ready: {result['report_url']}")
    return result


async def resolve_device_serial(device_target_type: str, device_target_ip: str | None) -> str:
    """Resolve the actual adb serial for whichever device the user picked for this job
    (`Job.device_target_type`/`device_target_ip`, set at `POST /api/jobs/{id}/start`). Both
    `_run_mobsf_dast_phase` and `_run_burp_dynamic_pipeline` use this one resolved serial - the
    user's per-job choice drives the whole job, never a mix of the two devices.

    `device_target_type` is one of `"physical"`, `"genymotion"`, or `"emulator"`:
    - `"physical"` and `"genymotion"` resolve identically, via
      `adb_service.connect_and_check_physical(device_target_ip)` - a Genymotion VM is just another
      network-adb Android target (`192.168.56.x:5555` rather than a USB serial or a physical
      device's LAN IP), so the same connect-and-verify logic applies unchanged.
    - `"emulator"` boots/reuses the project's own AVD via `device_lifecycle.ensure_running()` and
      resolves its serial with `adb_service.get_running_serial()`.
    Anything else raises `RuntimeError`.
    """
    if device_target_type in ("physical", "genymotion"):
        if not device_target_ip:
            raise RuntimeError(
                f"device_target_ip is required when device_target_type is {device_target_type!r}"
            )
        try:
            return await adb_service.connect_and_check_physical(device_target_ip)
        except adb_service.AdbError as e:
            raise RuntimeError(
                f"Could not connect to {device_target_type} device {device_target_ip}: {e}"
            )

    if device_target_type == "emulator":
        await device_lifecycle.ensure_running()
        serial = await adb_service.get_running_serial()
        if not serial:
            raise RuntimeError("Emulator did not come up")
        return serial

    raise RuntimeError(
        f"Unknown device_target_type {device_target_type!r} - expected 'emulator', 'physical', "
        "or 'genymotion'"
    )


async def _run_mobsf_dast_phase(job_id: uuid.UUID, file_hash: str, serial: str) -> None:
    await _log(
        job_id,
        f"Starting MobSF's dynamic analyzer against {serial} - this restarts adb (disconnecting "
        "any other adb session for a few seconds) and will reconfigure this device's CA trust "
        "store, global proxy, and Frida instrumentation.",
        level="warn",
    )
    await _set_status(job_id, JobStatus.MOBSF_DAST)

    await _log(job_id, "Syncing MobSF's target device configuration...")
    await mobsf_service.ensure_mobsf_targets(serial)

    try:
        await mobsf_service.mobsfy(serial)
    except Exception as e:
        await _log(job_id, f"mobsfy failed ({e}), checking device and retrying once...", level="warn")
        if not await adb_service.is_device_connected(serial):
            raise RuntimeError(
                f"Device {serial} dropped off adb during mobsfy() and did not reconnect - "
                "reconnect it and retry"
            )
        await mobsf_service.mobsfy(serial)  # let a second failure raise for real

    await mobsf_service.install_root_ca()
    await mobsf_service.set_global_proxy()
    await _log(job_id, "MobSF CA trusted and device proxy pointed at MobSF")

    # Everything from here on can raise partway through (start_dynamic_analysis,
    # instrument_frida, stop_dynamic_analysis, get_dynamic_report all call out to MobSF's REST
    # API). Without this try/finally, a failure here left the device with MobSF's CA trusted and
    # its proxy pointed at MobSF *permanently* - silently breaking that device's network traffic
    # for whatever uses it next, including this job's own later Burp/Frida phase in mode
    # sast_dast_burp. unset_global_proxy()/remove_root_ca() must always run, success or failure,
    # to actually deliver on the "leave the device clean" intent below.
    try:
        await mobsf_service.start_dynamic_analysis(file_hash)
        await mobsf_service.instrument_frida(file_hash)
        await _log(job_id, "MobSF Frida instrumentation attached")

        await mobsf_service.run_activity_tester(file_hash)  # best-effort, never raises

        await mobsf_service.stop_dynamic_analysis(file_hash)
        report = await mobsf_service.get_dynamic_report(file_hash)
        await _save_job_field(job_id, mobsf_dynamic_report_url=report.get("report_url"))
        await _log(job_id, f"MobSF dynamic report ready: {report.get('report_url')}")
    finally:
        # Leave the device clean for whoever/whatever uses it next (including our own Burp phase).
        await mobsf_service.unset_global_proxy()
        await mobsf_service.remove_root_ca()


async def _run_burp_dynamic_pipeline(
    job_id: uuid.UUID, apk_path: Path, parsed: ParsedApp, serial: str, device_target_type: str
) -> None:
    """The Frida+Burp path proven working end-to-end earlier this session, reused near-verbatim
    for the sast_dast_burp mode's final phase. Re-installs the app (apkfile's install is a safe,
    idempotent upgrade) since MobSF's own dynamic-analysis phase may have left it in a state we
    don't want to depend on."""
    await _set_status(job_id, JobStatus.INSTALLING)
    await _log(job_id, "Installing app...")
    await asyncio.to_thread(
        parsed.bundle.install, device_id=serial, grant_permissions=True, upgrade=True
    )
    await _log(job_id, "Install complete")

    await _set_status(job_id, JobStatus.CA_TRUST)
    await burp_service.launch_if_not_running()
    await _log(job_id, "Fetching Burp CA certificate...")
    der_path = await burp_service.fetch_ca_der()
    hash_filename = await adb_service.push_ca_cert(serial, der_path)
    await _log(job_id, f"Burp CA trusted on device as {hash_filename}")

    await _set_status(job_id, JobStatus.PROXY_SET)
    await adb_service.set_global_proxy(serial, device_target_type)
    await _log(job_id, "Device global proxy pointed at Burp")

    await _set_status(job_id, JobStatus.FRIDA_ATTACH)
    await _log(job_id, "Attempting Frida SSL-pinning bypass...")
    pem_path = CERTS_DIR / "burp-ca.pem"
    ok, reason = await frida_service.attempt_bypass(
        str(job_id), serial, parsed.package_name, parsed.is_flutter, pem_path, device_target_type
    )

    if ok:
        await _log(job_id, "Frida bypass attached and held - traffic should now reach Burp")
        await _set_status(job_id, JobStatus.DONE, bypass_method="frida")
        return

    await _log(job_id, f"Frida bypass failed: {reason}", level="warn")

    if parsed.is_split:
        await _log(
            job_id,
            "Static-patch fallback is not supported for split-APK/XAPK uploads - failing.",
            level="error",
        )
        await _set_status(
            job_id,
            JobStatus.FAILED,
            bypass_method=None,
            failure_reason=f"Frida failed ({reason}); static-patch fallback unsupported for split APKs",
        )
        return

    await _set_status(job_id, JobStatus.STATIC_PATCH)
    await _log(job_id, "Falling back to apktool static patch...")
    try:
        patched_apk = await apktool_service.patch_and_rebuild(apk_path, str(job_id))
        await adb_service.force_stop(serial, parsed.package_name)
        await asyncio.to_thread(apkfile.uninstall_apks, parsed.package_name, device_id=serial)
        await asyncio.to_thread(
            apkfile.install_apks, str(patched_apk), device_id=serial, grant_permissions=True
        )
        await adb_service.launch_app(serial, parsed.package_name)
        await _log(job_id, "Static-patched app reinstalled and launched")
        await _set_status(job_id, JobStatus.DONE, bypass_method="static_patch")
    except Exception as e:
        await _log(job_id, f"Static patch fallback failed: {e}", level="error")
        await _set_status(
            job_id,
            JobStatus.FAILED,
            bypass_method=None,
            failure_reason=f"Frida failed ({reason}); static patch also failed: {e}",
        )


async def run_job(job_id: uuid.UUID) -> None:
    with Session(engine) as session:
        job = session.get(Job, job_id)
        apk_path = Path(job.stored_path)
        analysis_mode = job.analysis_mode
        device_target_type = job.device_target_type
        device_target_ip = job.device_target_ip

    try:
        await _log(job_id, "Ensuring MobSF is up...")
        await device_lifecycle.ensure_mobsf()

        await _set_status(job_id, JobStatus.PARSING)
        await _log(job_id, f"Parsing {job.original_filename}")
        parsed = await apk_inspect.parse_upload(apk_path)
        await _save_job_field(
            job_id,
            package_name=parsed.package_name,
            is_split_apk=parsed.is_split,
            is_flutter=parsed.is_flutter,
        )
        await _log(
            job_id,
            f"package={parsed.package_name} split={parsed.is_split} flutter={parsed.is_flutter}",
        )

        mobsf_result = await _run_mobsf_static_scan(job_id, apk_path)

        if analysis_mode == AnalysisMode.SAST:
            await _set_status(job_id, JobStatus.DONE)
            return

        await _set_status(job_id, JobStatus.DEVICE_CHECK)
        needs_burp = analysis_mode == AnalysisMode.SAST_DAST_BURP
        if device_target_type == "genymotion" or needs_burp:
            await _log(job_id, "Ensuring Genymotion/Burp are up for this job...")
            await device_lifecycle.ensure_lab_up(device_target_type, with_burp=needs_burp)

        await _log(job_id, f"Checking {device_target_type} device...")
        serial = await resolve_device_serial(device_target_type, device_target_ip)
        await _set_status(job_id, JobStatus.DEVICE_CHECK, device_serial=serial)
        await _log(job_id, f"Device ready: {serial}")

        await _run_mobsf_dast_phase(job_id, mobsf_result["hash"], serial)

        if analysis_mode == AnalysisMode.SAST_DAST:
            await _set_status(job_id, JobStatus.DONE)
            return

        # sast_dast_burp: pause for explicit confirmation before touching Burp at all. On Pro this
        # restarts Burp with a fresh project, closing whatever project is currently open; on
        # Community, Burp is never restarted (it can't reload a project from the CLI), but this
        # phase will still re-point the device's proxy at it, so any uncleared history is still
        # worth flagging.
        await _set_status(job_id, JobStatus.AWAITING_BURP_CONFIRM)
        if burp_service.IS_PRO:
            warning = (
                "Starting this PT session will close Burp's currently open project - unsaved "
                "work there will be lost. Confirm in the UI to continue."
            )
        else:
            warning = (
                "Starting this PT session will route this device's traffic into your current "
                "Burp Community instance - traffic from earlier jobs may still be in its proxy "
                "history. Confirm in the UI to continue."
            )
        await _log(job_id, warning, level="warn")
        event = asyncio.Event()
        _burp_confirm_events[job_id] = event
        try:
            await event.wait()
        finally:
            _burp_confirm_events.pop(job_id, None)

        if burp_service.IS_PRO:
            await _log(job_id, "Restarting Burp with a fresh project for this job...")
        project_file = await burp_service.restart_with_project(str(job_id))
        if project_file is not None:
            await _log(job_id, f"Burp project: {project_file}")

        # MobSF's own DAST phase does heavy adb usage right up to the end (it explicitly restarts
        # its device's adb daemon as part of its own cleanup - "Stopping ADB server" in its logs).
        # Confirmed live: starting this phase's own adb calls immediately
        # afterward can race that in-flight restart and time out with a misleading
        # "Terminated"/exit-143 AdbError, even though the device is fully responsive moments later.
        # NOTE: `adb devices` reporting `device` state (is_device_connected) is NOT sufficient here -
        # confirmed live that it can report `device` while the actual shell transport is still
        # mid-reconnect, so a real `adb shell` round-trip is needed as the readiness signal, not
        # just the server-side device list. Mirrors the same grace-period pattern mobile_pt.sh
        # already uses after the emulator's own post-boot setup.
        for attempt in range(10):
            await asyncio.sleep(2)
            try:
                await adb_service.adb(serial, "shell", "echo ready", timeout=5)
                break
            except adb_service.AdbError:
                continue
        else:
            raise RuntimeError(f"Device {serial} did not settle after MobSF's DAST phase")

        await _run_burp_dynamic_pipeline(job_id, apk_path, parsed, serial, device_target_type)

    except Exception as e:
        # Some exceptions (notably asyncio.TimeoutError/httpx.ReadTimeout) stringify to an EMPTY
        # string, which made failures like "Pipeline error: " look blank and undebuggable (confirmed
        # live). Always include the exception's type name so there's something to
        # go on even when str(e) itself is empty.
        reason = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        await _log(job_id, f"Pipeline error: {reason}", level="error")
        await _set_status(job_id, JobStatus.FAILED, failure_reason=reason)
