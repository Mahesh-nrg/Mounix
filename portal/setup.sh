#!/usr/bin/env bash
# One-time setup for the Mobile PT Automation Portal.
# Assumes the top-level install_mobile_pt.sh has already run (installs the Android SDK / AVD /
# MobSF / Burp, and writes the repo-root .env with PORTAL_*, SESSION_SECRET, BURP_BIND_HOST,
# BURP_PROXY_PORT and MCP_PORT already set). This script adds the keys only IT owns - Postgres,
# the MobSF/Burp API wiring, and frida-server - onto that same .env; it never overwrites a key the
# installer already set.
set -euo pipefail

PORTAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${PORTAL_DIR}/.." && pwd)"
DATA_DIR="${PORTAL_DIR}/data"
BACKEND_DIR="${PORTAL_DIR}/backend"
FRONTEND_DIR="${PORTAL_DIR}/frontend"
SCRIPTS_DIR="${PORTAL_DIR}/scripts"
ENV_FILE="${REPO_DIR}/.env"
FRIDA_SCRIPTS_REPO="https://github.com/httptoolkit/frida-interception-and-unpinning"

C_BLUE="\033[34m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_RESET="\033[0m"
info() { echo -e "${C_BLUE}[*]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }

[ -f "$ENV_FILE" ] || {
    warn "${ENV_FILE} not found - run ../install_mobile_pt.sh first (it creates .env and asks for"
    warn "the portal login, Burp ports, and network interface)."
    exit 1
}

mkdir -p "$DATA_DIR"/{uploads,certs,keystores}

# Sets KEY=VALUE in $ENV_FILE only if KEY isn't already present - never clobbers a value
# install_mobile_pt.sh (or a previous run of this script) already wrote.
set_if_absent() {
    local key="$1" value="$2"
    grep -q "^${key}=" "$ENV_FILE" || printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
}

# --- PostgreSQL -------------------------------------------------------------
info "Ensuring PostgreSQL is running..."
systemctl enable --now postgresql >/dev/null 2>&1 || true

if ! su postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='mobile_pt'\"" 2>/dev/null | grep -q 1; then
    DB_PASSWORD="$(openssl rand -hex 16)"
    su postgres -c "psql -c \"ALTER DATABASE template1 REFRESH COLLATION VERSION;\"" >/dev/null 2>&1 || true
    su postgres -c "psql -c \"ALTER DATABASE postgres REFRESH COLLATION VERSION;\"" >/dev/null 2>&1 || true
    su postgres -c "psql -c \"CREATE ROLE mobile_pt WITH LOGIN PASSWORD '${DB_PASSWORD}';\""
    su postgres -c "psql -c \"CREATE DATABASE mobile_pt OWNER mobile_pt;\""
    ok "Created mobile_pt Postgres role + database."
else
    warn "mobile_pt Postgres role already exists - reusing it. If you don't know its password,"
    warn "reset it with: su postgres -c \"psql -c \\\"ALTER ROLE mobile_pt WITH PASSWORD '...';\\\"\""
    DB_PASSWORD="${MOBILE_PT_DB_PASSWORD:-}"
    if [ -z "$DB_PASSWORD" ]; then
        read -rsp "Enter the existing mobile_pt DB password: " DB_PASSWORD
        echo
    fi
fi

# --- Portal/device/Burp/MobSF settings --------------------------------------
# BURP_PROXY_HOST_FROM_DEVICE/_GENYMOTION are used for a physical device's or Genymotion's Burp/
# Frida proxy target - they must be this host's real LAN IP (reachable from the phone/VM), NOT
# 10.0.2.2 (that alias only resolves from inside the AVD emulator). Best-effort auto-detect the
# host's own LAN IP; if detection fails (no network, container, etc.), fall back to the
# emulator-only alias and rely on the comment in .env to flag it for anyone adding a device later.
detected_lan_ip="$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)"
burp_proxy_host_lan="${detected_lan_ip:-10.0.2.2}"

MOBSF_KEY="$(docker logs mobsf 2>&1 | grep -m1 -oP 'REST API Key:\s*\K[0-9a-f]+' || true)"

set_if_absent "DATABASE_URL" "postgresql+psycopg://mobile_pt:${DB_PASSWORD}@localhost:5432/mobile_pt"
set_if_absent "ANDROID_HOME" "/usr/lib/android-sdk"
set_if_absent "AVD_NAME" "MobSF_Pentest"
set_if_absent "BURP_EDITION" "community"
# Emulator-only alias (10.0.2.2) - leave this one alone for physical-device/Genymotion support.
set_if_absent "BURP_PROXY_HOST_EMULATOR" "10.0.2.2"
# MUST be this host's real LAN IP reachable from the phone/VM, never 10.0.2.2. Auto-detected
# above; if this looks wrong (multi-NIC host, VPN, etc.) set it manually to the IP your device
# can reach.
set_if_absent "BURP_PROXY_HOST_FROM_DEVICE" "$burp_proxy_host_lan"
set_if_absent "BURP_PROXY_HOST_GENYMOTION" "$burp_proxy_host_lan"
set_if_absent "BURP_PROXY_PORT_GENYMOTION" "8090"
set_if_absent "BURP_API_HOST" "127.0.0.1"
set_if_absent "BURP_API_PORT" "1337"
# Pro only - Community has no REST API. Leave blank; the dashboard's health check just no-ops.
set_if_absent "BURP_API_KEY" ""
set_if_absent "MOBSF_URL" "http://127.0.0.1:8000"
set_if_absent "MOBSF_API_KEY" "$MOBSF_KEY"
set_if_absent "FRIDA_SERVER_VERSION" "17.19.0"
chmod 600 "$ENV_FILE"
ok "Merged Postgres/device/Burp/MobSF settings into ${ENV_FILE} (existing keys untouched)."

if grep -q '^BURP_EDITION=pro$' "$ENV_FILE" && ! grep -q '^BURP_API_KEY=.\+' "$ENV_FILE"; then
    read -rp "Burp Pro REST API key (Settings > Suite > API, leave blank to set later): " BURP_API_KEY_INPUT
    if [ -n "$BURP_API_KEY_INPUT" ]; then
        tmp="$(mktemp)"
        KEY="BURP_API_KEY" VAL="$BURP_API_KEY_INPUT" awk '
            BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VAL"] }
            index($0, k "=") == 1 { print k "=" v; next }
            { print }
        ' "$ENV_FILE" > "$tmp"
        cat "$tmp" > "$ENV_FILE"
        rm -f "$tmp"
        chmod 600 "$ENV_FILE"
    fi
fi

# --- Backend deps -------------------------------------------------------------
info "Installing backend dependencies (uv)..."
(cd "$BACKEND_DIR" && uv sync)

FRIDA_VERSION="$(cd "$BACKEND_DIR" && uv run python -c 'import frida; print(frida.__version__)')"
FRIDA_SERVER_PATH="${DATA_DIR}/frida-server-${FRIDA_VERSION}-android-x86_64"
if [ ! -f "$FRIDA_SERVER_PATH" ]; then
    info "Downloading matching frida-server ${FRIDA_VERSION} for android-x86_64..."
    curl -sL -o /tmp/frida-server.xz \
        "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz"
    unxz -f /tmp/frida-server.xz
    mv /tmp/frida-server "$FRIDA_SERVER_PATH"
    chmod +x "$FRIDA_SERVER_PATH"
    ok "frida-server ready at ${FRIDA_SERVER_PATH}"
else
    ok "frida-server ${FRIDA_VERSION} already present."
fi

# --- Frida unpinning scripts (fetched, not vendored - keeps this repo MIT) -----
FRIDA_SCRIPTS_DIR="${SCRIPTS_DIR}/frida"
if [ -d "$FRIDA_SCRIPTS_DIR" ] && [ -n "$(ls -A "$FRIDA_SCRIPTS_DIR" 2>/dev/null)" ]; then
    ok "Frida unpinning scripts already present at ${FRIDA_SCRIPTS_DIR}."
else
    info "Fetching Frida unpinning scripts from httptoolkit/frida-interception-and-unpinning..."
    tmp_clone="$(mktemp -d)"
    git clone --depth 1 "$FRIDA_SCRIPTS_REPO" "$tmp_clone" >/dev/null
    mkdir -p "$FRIDA_SCRIPTS_DIR"
    cp -r "$tmp_clone"/. "$FRIDA_SCRIPTS_DIR"/
    rm -rf "$tmp_clone" "${FRIDA_SCRIPTS_DIR}/.git"
    ok "Frida scripts fetched into ${FRIDA_SCRIPTS_DIR} (AGPL-3.0-or-later - see its own LICENSE)."
fi

# --- Debug keystore for the apktool static-patch fallback ----------------------
KEYSTORE="${DATA_DIR}/keystores/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    info "Generating debug keystore for static-patch re-signing..."
    keytool -genkey -v -keystore "$KEYSTORE" \
        -alias mobilept -storepass mobilept123 -keypass mobilept123 \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=MobilePT,OU=Pentest,O=MobilePT,L=Local,S=NA,C=US" >/dev/null
    ok "Keystore created."
else
    ok "Debug keystore already present."
fi

# --- Frontend build -------------------------------------------------------------
info "Installing + building frontend..."
(cd "$FRONTEND_DIR" && npm install && npm run build)

ok "Setup complete. Run ./run.sh to start the portal."
if ! grep -q '^BURP_API_KEY=.\+' "$ENV_FILE"; then
    warn "BURP_API_KEY is blank - fine on Community (the health check just no-ops), but on Pro the"
    warn "dashboard's Burp health check will show unreachable until you set it in ${ENV_FILE}."
fi
