#!/usr/bin/env bash
# install_mobile_pt.sh - one-shot installer for the Mobile PT Automation lab.
#
# Host-side setup: apt packages, Docker + MobSF image, Genymotion (guided), Burp (guided),
# optional GitHub CLI login, then writes .env and burp-mcp-client.json in the repo root.
# Every step checks whether it is already done and skips if so.
#
# Usage: sudo ./install_mobile_pt.sh [--dry-run]
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${REPO_DIR}/.env"
ENV_SAMPLE="${REPO_DIR}/.env.sample"
CLIENT_CFG="${REPO_DIR}/burp-mcp-client.json"
GENY_DROP_DIR="${REPO_DIR}/genymotion_install"
GENY_INSTALL_DIR="/opt/genymotion"
GENY_GMTOOL="${GENY_INSTALL_DIR}/genymotion/gmtool"
GENY_DOWNLOAD_URL="https://www.genymotion.com/product-desktop/download/"
BURP_DOWNLOAD_URL="https://portswigger.net/burp/communitydownload"
MOBSF_IMAGE="opensecurity/mobile-security-framework-mobsf:latest"
APT_PACKAGES=(adb default-jdk-headless python3 python3-venv nodejs npm apktool git curl \
    openssl ca-certificates ffmpeg iproute2 docker.io)
DEFAULT_BURP_PROXY_PORT=8080
DEFAULT_BURP_MCP_PORT=9876
DRY_RUN=0

C_BLUE="\033[34m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_RED="\033[31m"
C_BOLD="\033[1m"; C_RESET="\033[0m"

# All log helpers write to stderr so functions can return values on stdout.
info()    { printf '%b[*]%b %s\n' "$C_BLUE" "$C_RESET" "$*" >&2; }
ok()      { printf '%b[+]%b %s\n' "$C_GREEN" "$C_RESET" "$*" >&2; }
warn()    { printf '%b[!]%b %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()     { printf '%b[x]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()     { err "$*"; exit 1; }
heading() { printf '\n%b== %s ==%b\n' "$C_BOLD" "$*" "$C_RESET" >&2; }

trap 'err "Installer aborted at line ${LINENO}. Fix the problem above and re-run; finished steps are skipped."' ERR

usage() {
    cat >&2 <<EOF
Usage: sudo $0 [--dry-run]

  --dry-run   Print every action (and the prompts' default answers) without installing,
              writing, or downloading anything.
  -h, --help  Show this help.
EOF
}

# Runs a command, or prints it under --dry-run.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %b[dry-run]%b %s\n' "$C_BLUE" "$C_RESET" "$*" >&2
        return 0
    fi
    "$@"
}

# Yes/no question. Dry-run assumes yes so the full path is shown.
confirm() {
    local question="$1" answer=""
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] %s -> assuming yes\n' "$question" >&2
        return 0
    fi
    printf '%b[?]%b %s ' "$C_YELLOW" "$C_RESET" "$question" >&2
    read -r answer || true
    [[ "$answer" =~ ^[Yy]$ ]]
}

# Prompts for a value; prints the value (or the default on empty input) on stdout.
read_input() {
    local label="$1" default="$2" value=""
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] %s -> %s\n' "$label" "$default" >&2
        echo "$default"
        return 0
    fi
    printf '%b[?]%b %s [%s]: ' "$C_YELLOW" "$C_RESET" "$label" "$default" >&2
    read -r value || true
    echo "${value:-$default}"
}

# Prompts for a hidden value; prints it on stdout.
read_secret() {
    local label="$1" value=""
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] %s -> (hidden placeholder)\n' "$label" >&2
        echo "DRY_RUN_PLACEHOLDER_PASSWORD"
        return 0
    fi
    printf '%b[?]%b %s: ' "$C_YELLOW" "$C_RESET" "$label" >&2
    read -rs value || true
    printf '\n' >&2
    echo "$value"
}

wait_for_enter() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] would pause: %s\n' "$1" >&2
        return 0
    fi
    printf '%b[?]%b %s ' "$C_YELLOW" "$C_RESET" "$1" >&2
    read -r _ || true
}

ask_port() {
    local label="$1" default="$2" value
    while true; do
        value="$(read_input "$label" "$default")"
        if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 65535 ]; then
            echo "$value"
            return 0
        fi
        warn "Port must be a number from 1 to 65535."
    done
}

# ---------------------------------------------------------------------------
check_preflight() {
    heading "Preflight"
    if [ "$(id -u)" -ne 0 ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            warn "Not running as root. Dry run continues; a real run needs root."
        else
            die "Run as root or with sudo (sudo $0). Root is needed for apt, systemctl, the docker group, and /opt."
        fi
    fi
    [ -r /etc/os-release ] || die "/etc/os-release not found; cannot identify the distro."
    # shellcheck disable=SC1091
    . /etc/os-release
    case " ${ID:-} ${ID_LIKE:-} " in
        *" debian "*|*" ubuntu "*|*" kali "*) ;;
        *) die "Unsupported distro '${PRETTY_NAME:-unknown}'. This installer supports Debian, Ubuntu and Kali (apt) only." ;;
    esac
    command -v apt-get >/dev/null 2>&1 || die "apt-get not found."
    ok "Distro: ${PRETTY_NAME:-unknown} (apt)."
}

check_kvm() {
    heading "Hardware virtualization (KVM)"
    if [ ! -e /dev/kvm ]; then
        warn "/dev/kvm not found. Enable VT-x/AMD-V in firmware and load kvm_intel or kvm_amd."
        if ! confirm "Continue without KVM? The Android emulator will be very slow. [y/N]"; then
            die "KVM is required for a usable emulator."
        fi
    elif [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        warn "/dev/kvm exists but is not read/writable by this user. Check its group (usually 'kvm')."
    else
        ok "/dev/kvm present and accessible."
    fi
}

install_apt_packages() {
    heading "Apt packages"
    local pkg
    local -a missing=()
    for pkg in "${APT_PACKAGES[@]}"; do
        if [ "$pkg" = "docker.io" ] && command -v docker >/dev/null 2>&1; then
            continue  # Docker already installed by other means (e.g. docker-ce).
        fi
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        ok "All apt packages already installed."
        return 0
    fi
    info "Missing: ${missing[*]}"
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

ensure_uv() {
    heading "uv (Python runner)"
    export PATH="${HOME}/.local/bin:${PATH}"
    if command -v uv >/dev/null 2>&1; then
        ok "uv already installed."
        return 0
    fi
    if apt-cache show uv >/dev/null 2>&1; then
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y uv
    else
        info "uv is not in apt here; using the official installer from astral.sh."
        run sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
    fi
}

ensure_docker() {
    heading "Docker"
    if systemctl is-enabled --quiet docker 2>/dev/null && systemctl is-active --quiet docker; then
        ok "Docker already enabled and running."
    else
        run systemctl enable --now docker
    fi
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] \
        && ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx docker; then
        run usermod -aG docker "$SUDO_USER"
        warn "Added ${SUDO_USER} to the docker group. Log out and back in before using docker without sudo."
    fi
}

pull_mobsf_image() {
    heading "MobSF image"
    if docker image inspect "$MOBSF_IMAGE" >/dev/null 2>&1; then
        ok "${MOBSF_IMAGE} already present."
        return 0
    fi
    run docker pull "$MOBSF_IMAGE"
}

setup_genymotion() {
    heading "Genymotion (manual download)"
    if [ -x "$GENY_GMTOOL" ]; then
        ok "Genymotion already installed (${GENY_GMTOOL})."
        return 0
    fi
    cat >&2 <<EOF
  Genymotion is NOT downloaded by this script.
  1. Open ${GENY_DOWNLOAD_URL}
  2. Create a free Genymotion personal account (personal use) and download the
     Linux 64-bit installer: genymotion-<version>-linux_x64.run
  3. Move that file into: ${GENY_DROP_DIR}/
  Genymotion runs on VirtualBox here; VBoxManage must be installed.
  After installing, sign in once (Genymotion app, or: gmtool config --email ... --password ...).
EOF
    if [ "$DRY_RUN" -eq 1 ]; then
        run chmod +x "${GENY_DROP_DIR}/genymotion-<version>-linux_x64.run"
        run "${GENY_DROP_DIR}/genymotion-<version>-linux_x64.run" -d "$GENY_INSTALL_DIR" -y
        return 0
    fi
    mkdir -p "$GENY_DROP_DIR"
    local answer installer=""
    local -a found
    while true; do
        answer="$(read_input "Press Enter once the .run file is in ${GENY_DROP_DIR}/ (type s to skip)" "")"
        if [ "$answer" = "s" ]; then
            warn "Skipping Genymotion. MobSF-DAST modes that need it will not work until it is installed."
            return 0
        fi
        shopt -s nullglob
        found=("${GENY_DROP_DIR}"/genymotion-*-linux_x64.run)
        shopt -u nullglob
        if [ "${#found[@]}" -gt 0 ]; then
            installer="${found[-1]}"
            break
        fi
        warn "No genymotion-*-linux_x64.run found in ${GENY_DROP_DIR}/."
    done
    if ! command -v VBoxManage >/dev/null 2>&1; then
        warn "VBoxManage not found. Install VirtualBox before using Genymotion."
    fi
    info "Running ${installer} (installs to ${GENY_INSTALL_DIR})..."
    chmod +x "$installer"
    "$installer" -d "$GENY_INSTALL_DIR" -y
    [ -x "$GENY_GMTOOL" ] || die "Genymotion installer finished but ${GENY_GMTOOL} is missing."
    ok "Genymotion installed. Sign in once to activate it."
}

guide_burp() {
    heading "Burp Suite (manual steps)"
    cat >&2 <<EOF
  1. Download Burp Suite Community: ${BURP_DOWNLOAD_URL}
  2. Install it, then launch it once by hand and accept the first-run/JRE dialogs.
  3. In Burp: Extensions > BApp Store > "MCP Server" > Install (enable it).
  4. Open Burp's MCP tab and note its listen address and port.
  5. Bind Burp's proxy listener and the MCP server to the address you choose in the next
     step (default is loopback). Do this in Burp's own settings.
EOF
    wait_for_enter "Press Enter when Burp is installed, launched once, and the MCP Server extension is on."
    while true; do
        CHOSEN_PROXY_PORT="$(ask_port "Burp proxy listener port" "$DEFAULT_BURP_PROXY_PORT")"
        CHOSEN_MCP_PORT="$(ask_port "Burp MCP server port (from the MCP tab)" "$DEFAULT_BURP_MCP_PORT")"
        [ "$CHOSEN_PROXY_PORT" != "$CHOSEN_MCP_PORT" ] && break
        warn "The proxy and MCP ports must be different."
    done
    ok "Burp proxy port ${CHOSEN_PROXY_PORT}, MCP port ${CHOSEN_MCP_PORT}."
}

choose_bind_host() {
    heading "Network interface for Burp and the portal"
    local ifname ip choice
    local -a addrs=("127.0.0.1") descs=("loopback only (recommended)")
    while read -r ifname ip; do
        addrs+=("$ip")
        descs+=("interface ${ifname}")
    done < <(ip -o -4 addr show | awk '$2 != "lo" { split($4, a, "/"); print $2, a[1] }')
    addrs+=("0.0.0.0")
    descs+=("ALL interfaces (reachable from your LAN)")

    local i
    for i in "${!addrs[@]}"; do
        printf '  %d) %-15s %s\n' "$((i + 1))" "${addrs[$i]}" "${descs[$i]}" >&2
    done
    while true; do
        choice="$(read_input "Select an address (1-${#addrs[@]})" "1")"
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#addrs[@]}" ]; then
            break
        fi
        warn "Invalid choice."
    done
    CHOSEN_BIND_HOST="${addrs[$((choice - 1))]}"

    if [ "$CHOSEN_BIND_HOST" = "0.0.0.0" ]; then
        warn "0.0.0.0 makes Burp's proxy, the MCP server and the portal reachable from the LAN."
        warn "Anyone on that network who can reach this host can use them. Firewall the ports or pick one IP."
        if ! confirm "Continue with 0.0.0.0? [y/N]"; then
            die "Re-run the installer and choose a different address."
        fi
    fi
    ok "Bind address: ${CHOSEN_BIND_HOST}"
}

gh_as_login_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        sudo -u "$SUDO_USER" -H "$@"
    else
        "$@"
    fi
}

ensure_gh_installed() {
    if command -v gh >/dev/null 2>&1; then
        ok "gh already installed."
        return 0
    fi
    if apt-cache show gh >/dev/null 2>&1; then
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y gh
        return 0
    fi
    info "gh is not in apt here; adding the official GitHub CLI repository."
    run mkdir -p /etc/apt/keyrings
    run sh -c 'curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg > /etc/apt/keyrings/githubcli-archive-keyring.gpg && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg'
    run sh -c "echo 'deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main' > /etc/apt/sources.list.d/github-cli.list"
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y gh
}

setup_github() {
    heading "GitHub CLI (optional)"
    if ! confirm "Set up GitHub CLI login now? [y/N]"; then
        info "Skipped."
        return 0
    fi
    ensure_gh_installed
    if gh_as_login_user gh auth status >/dev/null 2>&1; then
        ok "gh already authenticated."
        return 0
    fi
    info "Starting browser device login (gh auth login --web)..."
    run gh_as_login_user gh auth login --web
}

# Hashes the password on stdin with bcrypt, the same scheme portal/setup.sh uses
# (bcrypt.hashpw(pw, bcrypt.gensalt()), checked by bcrypt.checkpw in backend/app/auth.py).
hash_password() {
    uv run --quiet --no-project --with bcrypt python3 -I -c \
        'import bcrypt, sys; print(bcrypt.hashpw(sys.stdin.read().encode(), bcrypt.gensalt()).decode())'
}

# Replaces KEY=... in FILE, or appends it. Values go through ENVIRON, not sed, so
# characters like / & $ in a bcrypt hash are safe.
set_env_value() {
    local key="$1" value="$2" file="$3" tmp
    tmp="$(mktemp)"
    KEY="$key" VAL="$value" awk '
        BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VAL"]; done = 0 }
        index($0, k "=") == 1 { print k "=" v; done = 1; next }
        { print }
        END { if (!done) print k "=" v }
    ' "$file" > "$tmp"
    cat "$tmp" > "$file"   # keeps the target file's mode
    rm -f "$tmp"
}

prompt_portal_password() {
    local pw1 pw2
    while true; do
        pw1="$(read_secret "Portal login password (min 8 characters)")"
        if [ "${#pw1}" -lt 8 ]; then
            warn "Password is too short."
            continue
        fi
        pw2="$(read_secret "Repeat portal login password")"
        if [ "$pw1" = "$pw2" ]; then
            break
        fi
        warn "Passwords do not match."
    done
    PORTAL_PASSWORD_VALUE="$pw1"
}

write_env() {
    heading "Writing .env"
    local existed=0 username password_hash session_secret backup
    if [ -f "$ENV_FILE" ]; then
        existed=1
        if ! confirm "A .env already exists at ${ENV_FILE}. Back it up and update the installer's keys? [y/N]"; then
            warn "Leaving .env untouched. Its PORTAL_*, BURP_BIND_HOST and BURP_*_PORT values are not updated."
            return 0
        fi
        backup="${ENV_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
        run cp -p "$ENV_FILE" "$backup"
    fi

    username="$(read_input "Portal login username" "admin")"
    prompt_portal_password

    if [ "$DRY_RUN" -eq 1 ]; then
        password_hash="<bcrypt-hash-of-portal-password>"
        session_secret="<openssl-rand-hex-32>"
    else
        password_hash="$(printf '%s' "$PORTAL_PASSWORD_VALUE" | hash_password)"
        session_secret="$(openssl rand -hex 32)"
    fi
    PORTAL_PASSWORD_VALUE=""

    if [ "$DRY_RUN" -eq 0 ] && [ "$existed" -eq 0 ]; then
        if [ -f "$ENV_SAMPLE" ]; then
            cp "$ENV_SAMPLE" "$ENV_FILE"
        else
            warn ".env.sample not found; creating .env from the installer's values only."
            : > "$ENV_FILE"
        fi
    elif [ "$DRY_RUN" -eq 1 ] && [ "$existed" -eq 0 ]; then
        run cp "$ENV_SAMPLE" "$ENV_FILE"
    fi
    run chmod 600 "$ENV_FILE"

    # Burp Community by default (what guide_burp() above walks through). Set BURP_EDITION=pro in
    # .env yourself if you have a Pro license - portal/setup.sh will then also ask for a REST API key.
    local lan_ip
    lan_ip="$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)"
    lan_ip="${lan_ip:-10.0.2.2}"

    run set_env_value PORTAL_USERNAME "$username" "$ENV_FILE"
    run set_env_value PORTAL_PASSWORD_HASH "'${password_hash}'" "$ENV_FILE"
    run set_env_value SESSION_SECRET "$session_secret" "$ENV_FILE"
    run set_env_value BURP_EDITION "community" "$ENV_FILE"
    run set_env_value BURP_BIND_HOST "$CHOSEN_BIND_HOST" "$ENV_FILE"
    run set_env_value PORTAL_HOST "$CHOSEN_BIND_HOST" "$ENV_FILE"
    run set_env_value BURP_PROXY_PORT "$CHOSEN_PROXY_PORT" "$ENV_FILE"
    run set_env_value MCP_PORT "$CHOSEN_MCP_PORT" "$ENV_FILE"
    # Genymotion needs its own LAN-reachable listener (not loopback) - add it by hand in Burp's
    # GUI (Proxy settings > add a listener bound to this address) once Burp is running.
    run set_env_value GENYMOTION_BURP_HOST "$lan_ip" "$ENV_FILE"
    run set_env_value GENYMOTION_BURP_PORT "8090" "$ENV_FILE"
    ok ".env written (mode 600). The plaintext password was not stored."
}

write_client_config() {
    heading "Burp MCP client config"
    local client_host="$CHOSEN_BIND_HOST" url body
    # 0.0.0.0 is a listen-all address, not a connect target; clients on this host use loopback.
    [ "$client_host" = "0.0.0.0" ] && client_host="127.0.0.1"
    # Base URL as documented in README.md; the README flags that some extension versions want /sse.
    url="http://${client_host}:${CHOSEN_MCP_PORT}"
    body="$(cat <<EOF
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "${url}"
    }
  }
}
EOF
)"
    printf '%s\n' "$body" >&2
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    [dry-run] would write %s\n' "$CLIENT_CFG" >&2
    else
        printf '%s\n' "$body" > "$CLIENT_CFG"
        ok "Wrote ${CLIENT_CFG}"
    fi
    info "Your global MCP client config was NOT edited. Merge this entry into it yourself if you want it."
}

print_summary() {
    local geny_state="NOT installed (re-run after placing the .run file)"
    [ -x "$GENY_GMTOOL" ] && geny_state="installed"
    heading "Summary"
    cat >&2 <<EOF
  Apt packages:  ${APT_PACKAGES[*]} (+ uv)
  Docker:        enabled; image ${MOBSF_IMAGE}
  Genymotion:    ${geny_state}
  Burp:          manual, Community by default. Proxy ${CHOSEN_BIND_HOST}:${CHOSEN_PROXY_PORT}, MCP ${CHOSEN_BIND_HOST}:${CHOSEN_MCP_PORT}
  Files:         ${ENV_FILE}, ${CLIENT_CFG}

  Next commands (first time only runs setup.sh; after that just run.sh):
    cd ${REPO_DIR}/portal
    ./setup.sh   # Postgres, backend deps, frida-server + scripts, frontend build
    ./run.sh     # starts the portal on http://${CHOSEN_BIND_HOST}:8811

  Keep Burp open, with the proxy listening, before you run the portal. If you added a Genymotion
  device, also add a proxy listener in Burp's GUI bound to this host's LAN IP on port 8090.
EOF
}

main() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            --dry-run) DRY_RUN=1 ;;
            -h|--help) usage; exit 0 ;;
            *) err "Unknown argument: ${arg}"; usage; exit 2 ;;
        esac
    done
    if [ "$DRY_RUN" -eq 1 ]; then
        warn "DRY RUN: nothing will be installed, downloaded, or written."
    fi

    check_preflight
    check_kvm
    install_apt_packages
    ensure_uv
    ensure_docker
    pull_mobsf_image
    setup_genymotion
    guide_burp
    choose_bind_host
    setup_github
    write_env
    write_client_config
    print_summary
}

main "$@"
