"""Frida-based SSL-pinning bypass, built on the vendored httptoolkit/frida-interception-and-unpinning
scripts (scripts/frida/ - AGPL-3.0-or-later, see scripts/frida/LICENSE). Uses the `frida` Python
bindings directly (not the `objection`/`frida` CLIs) so attach failure/crash can be detected
programmatically and the whole pipeline stays in-process.

Script composition: the upstream toolkit is normally invoked as `frida -l config.js -l a.js -l b.js
...` - each `-l` file shares one script-global scope with the others, executed in order. We get the
same effect by concatenating the file contents into one string for `session.create_script()` (safe:
none of these files use `require`/`module.exports`, confirmed when vendoring them).
`config.js`'s CERT_PEM/PROXY_HOST/PROXY_PORT placeholders are substituted per-run rather than editing
the vendored file, since PROXY_HOST must be the host machine's own address reachable from the target
device (config.js's own default of `127.0.0.1` would resolve to the *device itself* from inside the
app process, not the host running Burp) and CERT_PEM is Burp's CA, fetched fresh each boot by
adb_service.push_ca_cert. Which host address is correct depends on which device the user picked for
this job (`Job.device_target_type`,): the emulator's `10.0.2.2` alias for
host loopback is unreachable from real hardware, and a physical device needs the host's actual
WiFi/LAN address instead - `attempt_bypass`/`_build_script`/`_patch_config` take `device_target_type`
to pick the right one (`settings.burp_proxy_host_emulator` / `burp_proxy_host_physical`).

Flutter apps pin inside libflutter.so's own BoringSSL, bypassing the Android TrustManager entirely,
so `android-disable-flutter-certificate-pinning.js` is *appended* to the same base script set for
Flutter apps (per upstream docs, it's an addon, not an alternative) rather than swapped in.

frida-server binaries are architecture-specific - `_frida_server_local_path()` maps the target
device's actual `ro.product.cpu.abi` to the matching local binary rather than
assuming the AVD's x86_64 build.
"""

import asyncio
import time
from pathlib import Path

import frida

from app.config import DATA_DIR, SCRIPTS_DIR, settings
from app.services import adb_service

FRIDA_DIR = SCRIPTS_DIR / "frida"
ATTACH_GRACE_SECONDS = 8

# Maps `getprop ro.product.cpu.abi` values to frida's own release-asset architecture naming.
# The AVD is x86_64; real hardware (the physical-device DAST/Frida/Burp path
# #17) is almost always arm64-v8a or armeabi-v7a. Pushing the wrong architecture's binary fails
# silently in a confusing way (frida-server just never comes up, no clear error), so the binary
# actually pushed is picked per-device rather than hardcoded.
_ABI_TO_FRIDA_ARCH = {
    "x86_64": "x86_64",
    "x86": "x86",
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
}


def _frida_server_local_path(abi: str) -> Path:
    arch = _ABI_TO_FRIDA_ARCH.get(abi)
    if arch is None:
        raise RuntimeError(f"No frida-server build known for device ABI '{abi}'")
    return DATA_DIR / f"frida-server-{settings.frida_server_version}-android-{arch}"

# frida-python's Session/Script have no lifetime of their own beyond normal Python object
# lifetime - with nothing holding a reference after `attempt_bypass` returns, the garbage
# collector is free to tear the attached script/session down at any point, silently ending the
# bypass sometime after the job was already marked DONE. Keyed by job_id and never proactively
# evicted (this is a single-user local tool - one dict entry per analyzed app for the life of the
# process is not a real memory concern, same tradeoff already made for events.py's subscriber map).
_active_sessions: dict[str, tuple[frida.Device, frida.Session, frida.Script]] = {}

# Load order matches the upstream README's recommended Android command.
_BASE_SCRIPT_ORDER = [
    "config.js",
    "native-connect-hook.js",
    "native-tls-hook.js",
    "android/android-proxy-override.js",
    "android/android-system-certificate-injection.js",
    "android/android-certificate-unpinning.js",
    "android/android-certificate-unpinning-fallback.js",
    "android/android-disable-root-detection.js",
]
_FLUTTER_ADDON = "android/android-disable-flutter-certificate-pinning.js"


def _build_script(cert_pem: str, is_flutter: bool, device_target_type: str) -> str:
    parts: list[str] = []
    for rel_path in _BASE_SCRIPT_ORDER:
        text = (FRIDA_DIR / rel_path).read_text()
        if rel_path == "config.js":
            text = _patch_config(text, cert_pem, device_target_type)
        parts.append(text)
    if is_flutter:
        parts.append((FRIDA_DIR / _FLUTTER_ADDON).read_text())
    return "\n\n".join(parts)


_PROXY_TARGET_BY_TYPE = {
    "physical": lambda: (settings.burp_proxy_host_physical, settings.burp_proxy_port),
    "genymotion": lambda: (settings.burp_proxy_host_genymotion, settings.burp_proxy_port_genymotion),
    "emulator": lambda: (settings.burp_proxy_host_emulator, settings.burp_proxy_port),
}


def _patch_config(config_src: str, cert_pem: str, device_target_type: str) -> str:
    # The emulator's `10.0.2.2` alias, a physical device's real LAN IP, and a Genymotion VM's
    # NAT-reachable path to that LAN IP are three genuinely different targets - and Genymotion
    # specifically needs a different PORT too (8090, not the shared 8080), not just a different host.
    get_target = _PROXY_TARGET_BY_TYPE.get(device_target_type)
    if get_target is None:
        raise ValueError(f"Unknown device_target_type {device_target_type!r} for proxy host")
    proxy_host, proxy_port = get_target()
    escaped_pem = cert_pem.strip().replace("`", "\\`")
    out = []
    for line in config_src.splitlines():
        stripped = line.strip()
        if stripped.startswith("const PROXY_HOST"):
            out.append(f"const PROXY_HOST = '{proxy_host}';")
        elif stripped.startswith("const PROXY_PORT"):
            out.append(f"const PROXY_PORT = {proxy_port};")
        else:
            out.append(line)
    patched = "\n".join(out)
    # CERT_PEM spans multiple lines (the placeholder block) - replace the whole
    # `const CERT_PEM = \`...\`;` template literal rather than trying to patch line-by-line.
    start = patched.index("const CERT_PEM")
    end = patched.index("`;", patched.index("`", start) + 1) + 2
    patched = patched[:start] + f"const CERT_PEM = `{escaped_pem}`;" + patched[end:]
    return patched


def _can_reach_frida_server(serial: str) -> bool:
    """A real client-side readiness probe, not just "is *a* frida-server process running" - a
    `pgrep` match can be a stale/dying process from an earlier job (confirmed hands-on: this raced
    with a job's FRIDA_ATTACH step and produced a misleading `NotSupportedError: need Gadget to
    attach on jailed Android`, even though a process was technically still listed by pgrep at that
    moment). enumerate_processes() only succeeds if the client can actually complete a round trip
    through frida-server."""
    try:
        frida.get_device(serial, timeout=5).enumerate_processes()
        return True
    except Exception:
        return False


async def ensure_frida_server(serial: str) -> None:
    # NOTE: deliberately NOT short-circuiting even if `_can_reach_frida_server` currently reports
    # true - confirmed live that MobSF's own DAST phase (`mobsfy()`/dynamic
    # analysis) starts ITS OWN frida-server on the shared device for its own instrumentation, which
    # this function has no control over the lifecycle of. Treating "something responds to frida
    # right now" as "our frida-server is healthy and safe to reuse" raced MobSF's own cleanup
    # tearing that process down moments later, producing the exact same misleading
    # "NotSupportedError: need Gadget to attach on jailed Android" this function's docstring already
    # describes for the pgrep-race case - just from a different actor. Always kill-and-restart our
    # own instance instead, so what's running is unambiguously ours and under our own control by the
    # time `attempt_bypass()` actually spawns/attaches.
    # Confirmed live: on the Genymotion VM, wrapping this specific pkill in
    # `su`/`su 0 sh -c` hangs indefinitely (a toybox su+pkill interaction), while a plain, unwrapped
    # `pkill -f frida-server` returns instantly on that same device (adbd already runs as root
    # there). Try the fast unwrapped form first; only fall back to the `su`-wrapped form (needed on
    # devices like the physical Magisk phone, where adbd isn't root by default) if that's refused.
    # This was always just best-effort cleanup of a possibly-stale process (the original `|| true`
    # already tolerated "nothing to kill"), so both attempts get a short timeout and any failure is
    # tolerated rather than letting it hang the whole pipeline - a leftover process gets killed by
    # the fresh push+start below overwriting/replacing it anyway.
    try:
        await adb_service.adb(serial, "shell", "pkill -f frida-server", timeout=8)
    except adb_service.AdbError:
        try:
            await adb_service.adb(
                serial, "shell", "su 0 sh -c 'pkill -f frida-server || true'", timeout=8
            )
        except adb_service.AdbError:
            pass
    await asyncio.sleep(1)

    # Always (re)push rather than skip-if-present: this device may previously have had a
    # different-ABI binary pushed to the same on-device path (e.g. from earlier emulator-only
    # testing), and silently reusing that would fail in a confusing way. Pushing a small (~27-
    # 116MB) local-network file is cheap enough that there's no real cost to always doing it.
    abi = (await adb_service.adb(serial, "shell", "getprop ro.product.cpu.abi")).strip()
    frida_server_local = _frida_server_local_path(abi)
    if not frida_server_local.exists():
        raise RuntimeError(
            f"{frida_server_local} missing - run setup.sh to download the matching frida-server "
            f"for this device's ABI ({abi})"
        )
    await adb_service.adb(serial, "push", str(frida_server_local), settings.frida_server_device_path)
    await adb_service.adb(serial, "shell", f"chmod 755 {settings.frida_server_device_path}")

    # Backgrounded on-device via `su 0`, not `adb root` - see adb_service.py's module docstring
    # for why `adb root` (which restarts adbd itself) is avoided entirely on this box.
    await adb_service.adb(
        serial,
        "shell",
        f"su 0 sh -c 'nohup {settings.frida_server_device_path} >/dev/null 2>&1 &'",
        timeout=10,
    )

    for _ in range(15):
        await asyncio.sleep(1)
        if await asyncio.to_thread(_can_reach_frida_server, serial):
            return
    raise RuntimeError("frida-server started but never became reachable within 15s")


def _spawn_and_attach_sync(job_id: str, serial: str, package: str, script_src: str) -> tuple[bool, str]:
    device = frida.get_device(serial, timeout=10)
    state = {"detached": False, "reason": ""}

    def on_detached(reason, crash=None):
        state["detached"] = True
        state["reason"] = str(crash) if crash else reason
        _active_sessions.pop(job_id, None)

    pid: int | None = None
    try:
        pid = device.spawn([package])
        session = device.attach(pid)
        session.on("detached", on_detached)
        script = session.create_script(script_src)
        script.on("message", lambda message, data: None)
        script.load()
        device.resume(pid)
    except Exception as e:  # frida raises its own broad exception hierarchy
        # spawn() leaves the target process alive but suspended - if attach/script-load raised
        # before resume() was reached, that suspended process is otherwise leaked forever (or
        # until the device reboots), and a stale suspended instance can block a later relaunch of
        # the same package. Kill it in its own try/except so a failure to kill never masks or
        # replaces the original attach error being reported below.
        if pid is not None:
            try:
                device.kill(pid)
            except Exception:
                pass
        return False, f"{type(e).__name__}: {e}"

    time.sleep(ATTACH_GRACE_SECONDS)

    if state["detached"]:
        return False, state["reason"] or "Frida session detached unexpectedly"

    # Keep strong references alive for the process lifetime - see _active_sessions' docstring.
    # Without this, nothing outside this function holds `device`/`session`/`script`, so the
    # garbage collector is free to tear the attach down at any point after this returns.
    _active_sessions[job_id] = (device, session, script)
    return True, ""


def _attach_running_sync(job_id: str, serial: str, package: str, script_src: str) -> tuple[bool, str]:
    """Attach to an ALREADY-RUNNING process instead of spawn()+resume()'ing a freshly-forked one.

    Fallback for `_spawn_and_attach_sync`'s "process-terminated" failure mode - confirmed live via
    logcat that frida-server's spawn-gate (suspending the process right at
    zygote fork time to inject before any app code runs) hits SELinux AVC denials trying to
    `sigstop`/read the zygote process on this specific Genymotion image, and the freshly-forked
    child then SEGFAULTs within ~500ms of being forked - a real spawn-time instability, not
    something retries fix. Attaching to a process that's already past its fragile fork/init window
    sidesteps this entirely. The caller is responsible for having already force-stopped and
    relaunched `package` normally (plain `am start`, no suspension) before calling this.
    """
    device = frida.get_device(serial, timeout=10)
    state = {"detached": False, "reason": ""}

    def on_detached(reason, crash=None):
        state["detached"] = True
        state["reason"] = str(crash) if crash else reason
        _active_sessions.pop(job_id, None)

    try:
        proc = device.get_process(package)
        session = device.attach(proc.pid)
        session.on("detached", on_detached)
        script = session.create_script(script_src)
        script.on("message", lambda message, data: None)
        script.load()
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

    time.sleep(ATTACH_GRACE_SECONDS)

    if state["detached"]:
        return False, state["reason"] or "Frida session detached unexpectedly"

    _active_sessions[job_id] = (device, session, script)
    return True, ""


async def attempt_bypass(
    job_id: str,
    serial: str,
    package: str,
    is_flutter: bool,
    cert_pem_path: Path,
    device_target_type: str,
) -> tuple[bool, str]:
    await ensure_frida_server(serial)
    cert_pem = cert_pem_path.read_text()
    script_src = await asyncio.to_thread(_build_script, cert_pem, is_flutter, device_target_type)

    ok, reason = await asyncio.to_thread(_spawn_and_attach_sync, job_id, serial, package, script_src)
    if ok or "process-terminated" not in reason.lower():
        return ok, reason

    # Spawn-gate instability (see _attach_running_sync's docstring) - fall back to launching the
    # app normally (unsuspended) and attaching to the already-running process instead.
    await adb_service.force_stop(serial, package)
    await adb_service.launch_app(serial, package)
    await asyncio.sleep(3)  # let the app clear its own fork/init window before attaching
    return await asyncio.to_thread(_attach_running_sync, job_id, serial, package, script_src)
