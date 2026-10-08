"""Burp Suite integration. Works with both Burp Suite Community and Professional
(set BURP_EDITION in .env; default "community").

Burp's built-in REST API (port 1337, Pro only — Community has no REST API at all) only covers
scan orchestration and health/version info - it does NOT expose proxy-listener configuration. So:
  - Proxy listener setup is file-based: `burpsuite --config-file=...`
    (scripts/burp-config-template.json pre-sets the listener). On Pro, `--project-file=...` is
    also passed so the listener and any saved state persist across restarts in one project file;
    Community can't reliably reopen/persist a project file from the CLI, so that flag is skipped
    there and the proxy listener needs re-adding by hand if Burp itself is restarted.
  - The CA certificate is fetched the standard way: the proxy listener answers a direct GET to
    `/cert` on its own host:port with the DER-encoded CA, no separate export step needed.
  - The API key lives in Burp's URL path (`http://host:port/<api_key>/v0.1/...`), not a header -
    that's how Burp's REST API is documented and wired. Leave BURP_API_KEY blank on Community;
    api_health() below already no-ops when it's blank.
  - For AI-driven traffic inspection, install PortSwigger's "MCP Server" BApp (works on both
    editions) instead — see the top-level README's Burp section.
"""

import asyncio
import os
import shutil
import signal
import subprocess
from pathlib import Path

import httpx

from app.config import CERTS_DIR, DATA_DIR, SCRIPTS_DIR, settings

# Fetching the CA is done from the backend (host side), so always hit the loopback listener
# directly - the device-facing 10.0.2.2 alias (used in adb_service.set_global_proxy) only means
# something from inside the emulator.
PROXY_URL = f"http://127.0.0.1:{settings.burp_proxy_port}"
API_URL = f"http://{settings.burp_api_host}:{settings.burp_api_port}"

BURP_PROJECT_FILE = CERTS_DIR.parent / "burp" / "mobile_pt.burp"
BURP_JAR_CANDIDATES = [
    "/opt/BurpSuiteCommunity/burpsuite.jar",
    "/usr/share/burpsuite/burpsuite.jar",  # Kali/Debian `apt install burpsuite` (Community)
    "/opt/BurpSuitePro/burpsuite.jar",
]
BURP_SESSIONS_DIR = DATA_DIR / "burp_sessions"

IS_PRO = settings.burp_edition == "pro"

# A small (~500KB), clean Burp project file that carries the proxy listener(s) this setup needs -
# 127.0.0.1:<BURP_PROXY_PORT> (loopback, used by the emulator's 10.0.2.2 alias) and, if you added
# one, a LAN-bound listener for Genymotion/physical devices. Burp stores listener config as
# project *state*, not something `--config-file` alone reliably injects into a fresh project. On
# Pro, every new per-job project is SEEDED by copying this file as its starting point, so the
# listener survives every restart. Community can't reload a project file from the CLI this way -
# see restart_with_project() below - so this template is only used on Pro.
BURP_TEMPLATE_PROJECT = CERTS_DIR.parent / "burp" / "proxy_template.burp"

# Tracks the Popen handle for the Burp process this module itself last launched, so it can be
# polled/terminated directly instead of only via `pgrep -f burpsuite.jar` (which matches by
# command-line substring, not a tracked PID). Same small process-lifetime-registry tradeoff as
# frida_service.py's `_active_sessions` - accepted here for the same reason (single-user local
# tool). This is only ever set for a process launched in the current backend process's lifetime;
# the pgrep-based fallback in `_kill_running_burp` stays in place to catch Burp instances started
# some other way (a previous backend process, or manually).
_burp_process: subprocess.Popen | None = None


class BurpError(RuntimeError):
    pass


async def is_proxy_listening() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            await client.get(f"{PROXY_URL}/cert")
        return True
    except httpx.TransportError:
        return False


async def fetch_ca_der() -> Path:
    der_path = CERTS_DIR / "burp-ca.der"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{PROXY_URL}/cert")
        resp.raise_for_status()
        der_path.write_bytes(resp.content)
    return der_path


async def api_health() -> dict | None:
    if not settings.burp_api_key or settings.burp_api_key.startswith("REPLACE_ME"):
        return None
    url = f"{API_URL}/{settings.burp_api_key}/v0.1/burp/versions"
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except httpx.TransportError:
        return None
    return None


async def launch_if_not_running() -> None:
    if await is_proxy_listening():
        return

    jar = next((p for p in BURP_JAR_CANDIDATES if Path(p).exists()), None)
    if jar is None:
        raise BurpError("Burp Suite jar not found in known locations")

    config_file = SCRIPTS_DIR / "burp-config-template.json"
    args = ["java", "-jar", jar, f"--config-file={config_file}"]
    if IS_PRO:
        BURP_PROJECT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _seed_project_from_template(BURP_PROJECT_FILE)
        args.append(f"--project-file={BURP_PROJECT_FILE}")

    global _burp_process
    _burp_process = subprocess.Popen(
        args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
    )

    for _ in range(30):
        await asyncio.sleep(2)
        if await is_proxy_listening():
            return
    raise BurpError("Burp did not come up after launch")


async def _kill_running_burp() -> None:
    # Fast/reliable primary check: if this module itself has a tracked handle to a Burp process
    # that's still alive, terminate it directly instead of relying on pgrep's command-line-substring
    # match. Falls through to the pgrep-based sweep below either way, to also catch a Burp instance
    # started by something other than this module in the current process lifetime (a previous
    # backend process, or manually).
    global _burp_process
    if _burp_process is not None and _burp_process.poll() is None:
        _burp_process.terminate()
        for _ in range(10):
            await asyncio.sleep(0.5)
            if _burp_process.poll() is not None:
                break
        else:
            _burp_process.kill()
            for _ in range(10):
                await asyncio.sleep(0.5)
                if _burp_process.poll() is not None:
                    break
    _burp_process = None

    proc = await asyncio.create_subprocess_exec(
        "pgrep", "-f", "burpsuite.jar", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    out, _ = await proc.communicate()
    pids = [int(p) for p in out.decode().split() if p.strip()]
    if not pids:
        return

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    for _ in range(10):
        await asyncio.sleep(0.5)
        if not any(_pid_alive(pid) for pid in pids):
            return
        await asyncio.sleep(0)

    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _seed_project_from_template(project_file: Path) -> None:
    """Copy BURP_TEMPLATE_PROJECT to project_file if project_file doesn't exist yet, so the new
    project starts with the working proxy listeners already configured instead of blank. Never
    overwrites an existing project file (idempotent - safe to call on every launch/restart)."""
    if project_file.exists():
        return
    if not BURP_TEMPLATE_PROJECT.exists():
        return
    project_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(BURP_TEMPLATE_PROJECT, project_file)


async def restart_with_project(job_id: str) -> Path | None:
    """Kill any running Burp process and relaunch it pointed at a fresh, job-specific project
    file under BURP_SESSIONS_DIR/<job_id>/session.burp. Burp's REST API has no way to switch
    projects on a running instance, so a full process restart is the only reliable way to get a
    genuinely new, persistent, on-disk project per job. Caller (pipeline.py) is responsible for
    warning the user and getting explicit confirmation before calling this, since it closes
    whatever Burp project is currently open.

    Community edition: a no-op that returns None. Community can't persist/reload a project file
    from the CLI, and restarting Burp would discard its entire (unsaved) proxy history for no
    benefit - so on Community, every job just keeps reusing the one already-running Burp
    instance instead of getting a fresh, isolated project."""
    if not IS_PRO:
        return None

    await _kill_running_burp()

    for _ in range(10):
        if not await is_proxy_listening():
            break
        await asyncio.sleep(0.5)

    jar = next((p for p in BURP_JAR_CANDIDATES if Path(p).exists()), None)
    if jar is None:
        raise BurpError("Burp Suite jar not found in known locations")

    job_dir = BURP_SESSIONS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    project_file = job_dir / "session.burp"
    _seed_project_from_template(project_file)
    config_file = SCRIPTS_DIR / "burp-config-template.json"

    args = [
        "java",
        "-jar",
        jar,
        f"--project-file={project_file}",
        f"--config-file={config_file}",
    ]
    global _burp_process
    _burp_process = subprocess.Popen(
        args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
    )

    for _ in range(30):
        await asyncio.sleep(2)
        if await is_proxy_listening():
            return project_file
    raise BurpError("Burp did not come up after restart with new project")
