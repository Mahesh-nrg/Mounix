import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

PORTAL_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PORTAL_ROOT.parent
DATA_DIR = PORTAL_ROOT / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
CERTS_DIR = DATA_DIR / "certs"
KEYSTORE_PATH = DATA_DIR / "keystores" / "debug.keystore"
SCRIPTS_DIR = PORTAL_ROOT / "scripts"
MOBILE_PT_SH = REPO_ROOT / "mobile_pt.sh"

# .env lives at the repo root (written by install_mobile_pt.sh), not under portal/data —
# one env file shared by mobile_pt.sh and the portal backend.
load_dotenv(REPO_ROOT / ".env")


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required setting {name} in {REPO_ROOT / '.env'}. Run install_mobile_pt.sh first."
        )
    return value


class Settings:
    database_url: str = _require("DATABASE_URL")
    session_secret: str = _require("SESSION_SECRET")
    portal_username: str = _require("PORTAL_USERNAME")
    portal_password_hash: str = _require("PORTAL_PASSWORD_HASH")

    android_home: str = os.environ.get("ANDROID_HOME", "/usr/lib/android-sdk")
    avd_name: str = os.environ.get("AVD_NAME", "MobSF_Pentest")
    adb_bin: str = f"{android_home}/platform-tools/adb"
    # SSL-pinning bypass uses the `frida` Python bindings directly (see services/frida_service.py),
    # not the `frida`/`objection` CLIs — direct bindings let us detect attach failure/crash
    # programmatically instead of scraping CLI output.

    # "community" (default) or "pro". Burp Community can't persist a project file or reload one
    # from the CLI, so burp_service.py skips project-file seeding/relaunch when this is
    # "community" — see portal/README.md's Burp section for what that trades off.
    burp_edition: str = os.environ.get("BURP_EDITION", "community").strip().lower()

    # Two separate proxy-host aliases, since the Burp phase (mode 3) can target either device:
    # the emulator's `10.0.2.2` alias for host loopback is unreachable from real hardware, and a
    # physical device needs the host's actual LAN IP instead.
    burp_proxy_host_emulator: str = os.environ.get("BURP_PROXY_HOST_EMULATOR", "10.0.2.2")
    burp_proxy_host_physical: str = os.environ.get("BURP_PROXY_HOST_FROM_DEVICE", "10.0.2.2")
    # Genymotion's primary adapter (nic1/hostonly, used for adb) has no outbound route at all.
    # mobile_pt.sh's genymotion_fix_networking() adds a second NAT-only adapter (nic3) with its own
    # in-guest netd/default-route setup, which can reach the host's real LAN IP. That LAN IP is the
    # same one physical devices use, but Burp's listener for it needs its own address:port — set
    # BURP_PROXY_HOST_GENYMOTION to the host's own LAN IP (install_mobile_pt.sh asks for this).
    burp_proxy_host_genymotion: str = os.environ.get("BURP_PROXY_HOST_GENYMOTION", "")
    burp_proxy_port_genymotion: int = int(os.environ.get("BURP_PROXY_PORT_GENYMOTION", "8090"))
    burp_proxy_port: int = int(os.environ.get("BURP_PROXY_PORT", "8080"))
    burp_api_host: str = os.environ.get("BURP_API_HOST", "127.0.0.1")
    burp_api_port: int = int(os.environ.get("BURP_API_PORT", "1337"))
    # Pro-only: Burp Community has no REST API, so leave this blank. The health check in
    # burp_service.py already no-ops when this is empty.
    burp_api_key: str = os.environ.get("BURP_API_KEY", "")

    # Not 127.0.0.1 by default if you run the dashboard from another device: this value is also
    # embedded into mobsf_report_url / mobsf_dynamic_report_url (mobsf_service.py), which the
    # FRONTEND renders as a direct browser link — a loopback address there would only resolve for
    # whoever is on the host itself. MobSF runs with --network host and binds 0.0.0.0:8000, so the
    # host's real LAN IP reaches it just as well as loopback does. Set this to the host's own LAN
    # IP, or leave it as 127.0.0.1 if you only ever open the dashboard from this same machine.
    mobsf_url: str = os.environ.get("MOBSF_URL", "http://127.0.0.1:8000")
    mobsf_api_key: str = os.environ.get("MOBSF_API_KEY", "")

    frida_server_version: str = os.environ.get("FRIDA_SERVER_VERSION", "17.19.0")
    frida_server_device_path: str = "/data/local/tmp/frida-server"

    session_cookie_name: str = "mobile_pt_session"
    session_max_age_seconds: int = 60 * 60 * 12


settings = Settings()


def new_session_secret() -> str:
    return secrets.token_urlsafe(32)
