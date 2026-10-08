"""Device control via adb: install, CA trust, proxy wiring, app lifecycle.

CA install mechanics:
Android only recognizes a CA pushed into /system/etc/security/cacerts/ if the filename is the
cert's subject-hash-old (OpenSSL's legacy hash algorithm), not any other name. This is still true
on API 30. System-trusted CAs are honored by apps targeting API 24+ without any per-app opt-in
(only *user*-added certs are blocked by default network security config) - so this is the most
reliable way to get an app trusting Burp's CA without touching the APK at all.

**Why this doesn't use `adb root` + `remount` + reboot** (the "textbook" way to write to
/system): confirmed hands-on, extensively, on this box's specific emulator/kernel/AVB build that
every one of `adb root`, `adb remount`'s own auto-reboot, and a bare `adb reboot` reliably wedges
the connection into a permanent "offline" state - or worse, drives the guest into an infinite
"vbmeta digest mismatch" -> `init` abort -> reboot loop (confirmed via `-show-kernel` boot
logging: AVB's vbmeta hash check on /system fails and never recovers without a full `-wipe-data`
cold restart). Any in-guest reboot on this build is unsafe to trigger from a running pipeline.

**What's used instead**: `su 0` (the image is rootable without needing `adbd` itself to restart
as root) to bind-mount a tmpfs directly over `/system/etc/security/cacerts/` - this makes just
that directory writable via the kernel's own mount machinery, without touching the underlying
verity/AVB-protected block device at all, so no reboot is ever needed. The existing system certs
are copied into the tmpfs first (a fresh tmpfs mount starts empty and would otherwise hide all
~138 of them, breaking TLS for everything else on the device), then Burp's CA is added alongside
them. This only needs to happen once per boot (the tmpfs mount doesn't survive a reboot, but nor
does the AVD's writable state in general - see mobile_pt.sh's -wipe-data-on-every-launch policy).
"""

import asyncio
import ipaddress
import re
import subprocess
from pathlib import Path

from app.config import CERTS_DIR, settings

ADB = settings.adb_bin


class AdbError(RuntimeError):
    pass


async def _run(*args: str, timeout: int = 60) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise AdbError(f"Command timed out: {' '.join(args)}")
    text = out.decode(errors="replace")
    if proc.returncode != 0:
        raise AdbError(f"Command failed ({proc.returncode}): {' '.join(args)}\n{text}")
    return text


async def adb(serial: str, *args: str, timeout: int = 60) -> str:
    return await _run(ADB, "-s", serial, *args, timeout=timeout)


async def get_running_serial() -> str | None:
    out = await _run(ADB, "devices")
    for line in out.splitlines():
        if line.startswith("emulator-") and "device" in line:
            return line.split()[0]
    return None


async def is_device_connected(serial: str) -> bool:
    """True if `serial` (emulator or physical) currently shows up in `adb devices` as `device`
    (not `offline`/`unauthorized`/absent). Used to re-check connectivity mid-pipeline without
    caring which kind of target it is."""
    out = await _run(ADB, "devices")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == serial and parts[1] == "device":
            return True
    return False


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-.]*[A-Za-z0-9])?$")


def _validate_device_target(ip: str) -> str:
    """Validate a user-supplied physical-device target before it ever reaches `adb connect`.

    Not a security boundary against injection (adb_service._run uses `create_subprocess_exec`
    with a discrete argv list throughout, never a shell, so injection isn't possible regardless), but this is a real input-validation gap otherwise:
    without it, a malformed/blank value only fails late and confusingly inside `adb connect`'s own
    text output. Fails fast with a clear reason instead.
    """
    candidate = ip.strip()
    if not candidate:
        raise AdbError("IP address is required")

    host, _, port_str = candidate.rpartition(":") if ":" in candidate else (candidate, "", "")
    if not host:
        host = candidate

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise AdbError(f"'{host}' is not a valid IP address or hostname") from None

    if port_str:
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            raise AdbError(f"'{port_str}' is not a valid port (expected 1-65535)")

    return candidate if port_str else f"{host}:5555"


async def connect_and_check_physical(ip: str) -> str:
    """`adb connect` to a WiFi-ADB physical device and confirm it reaches `device` state.

    Appends the default adb-over-WiFi port (5555) if the caller didn't include one. Returns the
    resulting serial (the `ip:port` string, matching what `adb devices` shows) on success; raises
    `AdbError` with a human-readable reason (unauthorized/offline/no route) otherwise. `adb connect`
    itself exits 0 even on failure (it prints "failed to connect"/"cannot connect" to stdout rather
    than a nonzero exit code), so failure has to be detected from the output text and from
    `adb devices`, not from the subprocess's return code.
    """
    target = _validate_device_target(ip)
    connect_out = await _run(ADB, "connect", target, timeout=15)
    lowered = connect_out.lower()
    if "cannot connect" in lowered or "failed to connect" in lowered or "no route to host" in lowered or "connection refused" in lowered or "timed out" in lowered:
        raise AdbError(f"no route to host ({target})")

    devices_out = await _run(ADB, "devices")
    for line in devices_out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == target:
            state = parts[1]
            if state == "device":
                return target
            if state == "unauthorized":
                raise AdbError("unauthorized (needs a fresh tap on the device's screen to allow USB debugging)")
            if state == "offline":
                raise AdbError("offline (device did not come up cleanly - try reconnecting)")
            raise AdbError(f"unexpected state: {state}")
    raise AdbError(f"no route to host ({target}) - device did not appear in `adb devices`")


CACERTS_DIR = "/system/etc/security/cacerts"
_CACERTS_BACKUP = "/data/local/tmp/cacerts_backup"
_CACERTS_TMPFS_MARKER = "/data/local/tmp/.cacerts_tmpfs_mounted"


async def _cacerts_overlay_mounted(serial: str) -> bool:
    out = await adb(serial, "shell", f"ls {_CACERTS_TMPFS_MARKER} 2>/dev/null || true")
    return _CACERTS_TMPFS_MARKER in out


async def _ensure_cacerts_writable(serial: str) -> None:
    """Bind-mount a tmpfs over /system/etc/security/cacerts so new CAs can be added without
    remounting the (verity/AVB-protected, reboot-required-to-unlock) root filesystem at all - see
    this module's docstring for why that's avoided entirely on this box. Idempotent: skips if
    already mounted this boot (tracked via a marker file, since remounting tmpfs-over-tmpfs would
    silently wipe whatever was copied in the first time)."""
    if await _cacerts_overlay_mounted(serial):
        return

    # Preserve the ~138 existing system CAs: a fresh tmpfs mount starts empty and would otherwise
    # shadow all of them, breaking TLS for every other app/system component on the device.
    # NOTE: every `su 0 ...` invocation below uses the `su 0 sh -c '...'` form deliberately, never
    # a bare `su 0 <cmd>` - confirmed live against a real Magisk-rooted physical device that the
    # bare form (works fine on the AVD's toybox `su`) silently no-ops on Magisk's `su` (exit 0, no
    # output, command never actually runs). `sh -c` wrapping works identically on both.
    await adb(serial, "shell", f"su 0 sh -c 'rm -rf {_CACERTS_BACKUP}'")
    await adb(
        serial,
        "shell",
        f"su 0 sh -c 'mkdir -p {_CACERTS_BACKUP} && cp -a {CACERTS_DIR}/. {_CACERTS_BACKUP}/'",
    )
    await adb(serial, "shell", f"su 0 sh -c 'mount -t tmpfs tmpfs {CACERTS_DIR}'")
    await adb(
        serial,
        "shell",
        f"su 0 sh -c 'cp -a {_CACERTS_BACKUP}/. {CACERTS_DIR}/ && chmod 755 {CACERTS_DIR} "
        f"&& chmod 644 {CACERTS_DIR}/*'",
    )
    await adb(serial, "shell", f"su 0 sh -c 'touch {_CACERTS_TMPFS_MARKER}'")

    restored = await adb(serial, "shell", f"su 0 sh -c 'ls {CACERTS_DIR} | wc -l'")
    if int(restored.strip() or 0) < 100:
        raise AdbError(
            f"cacerts tmpfs overlay looks wrong after restore (only {restored.strip()} certs "
            "present, expected 100+) - refusing to proceed with a broken system trust store"
        )


async def cert_already_trusted(serial: str, hash_filename: str) -> bool:
    # `ls` on a missing file is the expected common case, not a failure - adb propagates the
    # remote shell's exit code as its own, so without `|| true` a "not found" would raise AdbError.
    out = await adb(
        serial, "shell", f"ls {CACERTS_DIR}/{hash_filename} 2>/dev/null || true"
    )
    return hash_filename in out


async def push_ca_cert(serial: str, der_cert_path: Path) -> str:
    """Convert Burp's DER cert to Android's subject_hash_old.0 naming and push it into the
    system trust store (via the tmpfs overlay, not a remount). Returns the hash filename used,
    so callers can cache/skip on reruns."""
    hash_proc = await asyncio.create_subprocess_exec(
        "openssl",
        "x509",
        "-inform",
        "DER",
        "-subject_hash_old",
        "-in",
        str(der_cert_path),
        "-noout",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await hash_proc.communicate()
    if hash_proc.returncode != 0:
        raise AdbError(f"openssl subject_hash_old failed: {err.decode(errors='replace')}")
    cert_hash = out.decode().strip()
    hash_filename = f"{cert_hash}.0"

    await _ensure_cacerts_writable(serial)

    if await cert_already_trusted(serial, hash_filename):
        return hash_filename

    pem_path = CERTS_DIR / "burp-ca.pem"
    convert = await asyncio.create_subprocess_exec(
        "openssl",
        "x509",
        "-inform",
        "DER",
        "-in",
        str(der_cert_path),
        "-out",
        str(pem_path),
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await convert.communicate()
    if convert.returncode != 0:
        raise AdbError(f"openssl DER->PEM failed: {err.decode(errors='replace')}")

    device_tmp = f"/data/local/tmp/{hash_filename}"
    await adb(serial, "push", str(pem_path), device_tmp)
    await adb(serial, "shell", f"su 0 sh -c 'cp {device_tmp} {CACERTS_DIR}/{hash_filename} && chmod 644 {CACERTS_DIR}/{hash_filename}'")
    return hash_filename


_PROXY_TARGET_BY_TYPE = {
    "physical": lambda: (settings.burp_proxy_host_physical, settings.burp_proxy_port),
    "genymotion": lambda: (settings.burp_proxy_host_genymotion, settings.burp_proxy_port_genymotion),
    "emulator": lambda: (settings.burp_proxy_host_emulator, settings.burp_proxy_port),
}


async def set_global_proxy(serial: str, device_target_type: str) -> None:
    # The emulator's `10.0.2.2` alias, a physical device's real LAN IP, and a Genymotion VM's
    # NAT-reachable path to that same LAN IP are three genuinely different targets - and Genymotion
    # specifically needs a different PORT too (8090, not the shared 8080
    # #16/#17/#19/#20), not just a different host.
    get_target = _PROXY_TARGET_BY_TYPE.get(device_target_type)
    if get_target is None:
        raise ValueError(f"Unknown device_target_type {device_target_type!r} for proxy host")
    host, port = get_target()
    target = f"{host}:{port}"
    await adb(serial, "shell", "settings", "put", "global", "http_proxy", target)


async def clear_global_proxy(serial: str) -> None:
    await adb(serial, "shell", "settings", "put", "global", "http_proxy", ":0")


async def force_stop(serial: str, package: str) -> None:
    await adb(serial, "shell", "am", "force-stop", package)


async def launch_app(serial: str, package: str) -> None:
    out = await adb(
        serial,
        "shell",
        "cmd",
        "package",
        "resolve-activity",
        "--brief",
        package,
    )
    lines = [l.strip() for l in out.splitlines() if "/" in l and not l.startswith("No activity")]
    component = lines[-1] if lines else None
    if component:
        await adb(serial, "shell", "am", "start", "-n", component)
    else:
        await adb(serial, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
