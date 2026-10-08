"""Thin wrapper around ../../../mobile_pt.sh - the portal does not reimplement AVD/MobSF lifecycle
management, it just shells out to the script that already does it."""

import asyncio

from app.config import MOBILE_PT_SH


class DeviceLifecycleError(RuntimeError):
    pass


async def _run_script(*args: str, timeout: int = 240) -> str:
    proc = await asyncio.create_subprocess_exec(
        str(MOBILE_PT_SH),
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        # The process can legitimately finish (success or failure) in the small window between
        # wait_for's deadline firing and this kill() call actually running - confirmed live, not
        # theoretical: a real `ensure` run on a genuinely slow Genymotion boot hit this exact race,
        # and proc.kill() raised an uncaught ProcessLookupError that surfaced as an opaque
        # "Pipeline error: ProcessLookupError" (no message) instead of the real
        # "timed out"/underlying-failure reason. The kill's only job here is "make sure it's dead" -
        # already-dead is a success condition for that job, not an error.
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        raise DeviceLifecycleError(f"mobile_pt.sh {' '.join(args)} timed out")
    text = out.decode(errors="replace")
    if proc.returncode != 0:
        raise DeviceLifecycleError(f"mobile_pt.sh {' '.join(args)} failed:\n{text}")
    return text


async def status() -> str:
    return await _run_script("status")


async def ensure_running() -> None:
    from app.services import adb_service

    serial = await adb_service.get_running_serial()
    if serial:
        return
    # mobile_pt.sh's own realistic worst-case for a single `launch` run, read from its constants
    # and fixed sleeps (mobile_pt.sh: BOOT_TIMEOUT=240, MOBSF_TIMEOUT=300):
    #   ~65s  start_emulator_if_needed's adb-registration wait (5s initial sleep + up to 60s
    #         poll loop) before boot-wait even starts
    #   240s  wait_for_boot's BOOT_TIMEOUT
    #    12s  start_emulator_if_needed's fixed post-boot grace sleep (avoids racing the
    #         emulator's own in-flight overlay/broadcast setup - see mobile_pt.sh comment)
    #   300s  start_mobsf's MOBSF_TIMEOUT
    #   ------
    #   617s  summed worst case (240 + 300 for boot+MobSF alone is already 540s)
    # A 300s Python-side timeout would proc.kill() a launch that was still on track, surfacing as
    # a confusing "Emulator did not come up" error. Use a generous margin above the 617s real
    # worst case so this only fires on a genuine hang. If BOOT_TIMEOUT/MOBSF_TIMEOUT ever change
    # in mobile_pt.sh, recompute this comment's math and this value together.
    await _run_script("launch", "--headless", timeout=750)


async def ensure_mobsf() -> None:
    """Every analysis mode needs MobSF for its static scan - call this before anything else in
    a job so a file dropped in the New Scan UI is enough on its own; the user should never have
    to separately run `mobile_pt.sh launch`/`heal` by hand first. Fast no-op (a few seconds) if
    MobSF is already healthy - `mobile_pt.sh ensure`'s own idempotent check, same one `heal` uses.

    Timeout mirrors ensure_running()'s reasoning: cmd_ensure's MobSF section is
    `with_retries 2 5 start_mobsf`, and start_mobsf itself waits up to MOBSF_TIMEOUT=300s per
    attempt (mobile_pt.sh) - worst case 2*300 + 5 = 605s. 700s leaves real margin above that."""
    await _run_script("ensure", timeout=700)


async def ensure_lab_up(device_target_type: str, with_burp: bool) -> None:
    """DAST-mode readiness beyond the MobSF check ensure_mobsf() already did: brings up Genymotion
    (only if device_target_type == 'genymotion' - a physical device or the AVD emulator has no use
    for it) and/or Burp (only if with_burp - only mode sast_dast_burp needs it) via the same
    `mobile_pt.sh ensure` entrypoint. No-op call entirely if this job needs neither.

    Timeout: confirmed live this needs real margin, not a round number - an earlier, tighter 300s
    timeout genuinely fired on a slow-but-otherwise-healthy Genymotion boot (its networking fixup
    just took a while that run), and the resulting proc.kill() raced the process's own natural
    exit and raised an uncaught ProcessLookupError (see _run_script's fix). Worst-case math:
    Burp's own `with_retries 3 5 start_burp_if_needed` (each attempt up to 60s) is ~195s; Genymotion's
    `setup_genymotion` outer 3-attempt loop, each attempt up to
    GENYMOTION_BOOT_TIMEOUT=90s reachability wait + ~45s networking-fixup retries, plus 10s/20s
    inter-attempt backoff, is ~540s. Combined pathological worst case ~735s - 900s leaves real
    margin above that, same "generous margin over real worst case" approach as ensure_running()."""
    args = ["ensure"]
    if device_target_type == "genymotion":
        args += ["--device-type", "genymotion"]
    if with_burp:
        args += ["--burp"]
    if len(args) == 1:
        return
    await _run_script(*args, timeout=900)
