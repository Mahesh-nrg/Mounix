#!/usr/bin/env bash
#
# mobile_pt.sh - Mobile Pentest Lab Controller (MobSF + Android Emulator AVD)
#
# Usage:
#   ./mobile_pt.sh                       Interactive menu
#   ./mobile_pt.sh setup                 One-time install: Android SDK, system image, AVD, MobSF image
#   ./mobile_pt.sh launch [--gui|--headless] [--avd NAME]
#   ./mobile_pt.sh status
#   ./mobile_pt.sh teardown [--wipe]
#   ./mobile_pt.sh uninstall-genymotion
#   ./mobile_pt.sh help
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# Resolves to the repo root regardless of where it's checked out or how it's invoked (symlink,
# relative path, etc.), so this script works for anyone who clones the repo - not just this box.
BASE_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Load the repo-root .env (written by install_mobile_pt.sh / portal/setup.sh) so GENYMOTION_*,
# BURP_*, etc. below pick up the user's actual values instead of only the hardcoded defaults.
# `set -a` exports every name the file defines so child processes (the portal backend) see them
# too; an already-exported shell variable still wins over anything set here, since every default
# below uses `${VAR:-default}`, not a plain assignment.
if [ -f "${BASE_DIR}/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "${BASE_DIR}/.env"
    set +a
fi

LOG_DIR="${BASE_DIR}/logs"
MOBSF_DATA_DIR="${BASE_DIR}/mobsf_data"
MOBSF_ADB_HOME_DIR="${BASE_DIR}/mobsf_adb_home"
PID_FILE="${BASE_DIR}/.emulator.pid"

AVD_NAME_DEFAULT="MobSF_Pentest"
API_LEVEL="30"
ARCH="x86_64"
# google_apis (non Play Store) image -> supports `adb root` out of the box, which MobSF's
# dynamic analyzer needs. Play-Store images are locked and cannot be rooted this way.
SYSTEM_IMAGE="system-images;android-${API_LEVEL};google_apis;${ARCH}"
DEVICE_PROFILE="pixel_5a"

MOBSF_CONTAINER_NAME="mobsf"
MOBSF_IMAGE="opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_PORT="8000"

BOOT_TIMEOUT=240
MOBSF_TIMEOUT=300

# --- Genymotion (MobSF-DAST target) ---------------
# Genymotion is used specifically because it's the one target whose /system is genuinely writable
# (userdebug build, real remount succeeds) - required for MobSF's own built-in Dynamic Analyzer,
# which neither the AVD (AVB/verity bootloop) nor a real physical device (Magisk systemless root)
# can satisfy. Genymotion's free tier gates network-mode changes (NAT/Bridge) behind a Pro license
# via its own tooling (gmtool admin edit --network-mode, and its GUI) - `nic1` (the adapter its own
# player manages and resets to hostonly on every single start, regardless of external changes) stays
# hostonly, which is what keeps adb reachable at a fixed, predictable address. A SEPARATE adapter
# (`nic3`, additive - left alone by Genymotion's launcher, confirmed live across many restarts) is
# used purely for outbound app traffic: NAT gives it a real route out, but the guest's own Android
# netd never automatically activates a newly-appeared interface or picks it as the default network,
# so every boot needs a short in-guest fixup (bring the link up, request a DHCP lease via the
# Android-native `dhcptool`, then register it as a real netd network via `ndc` and set it default).
# None of this touches nic1/adb reachability - it's purely additive.
GENYMOTION_VM_NAME="${GENYMOTION_VM_NAME:-Google Pixel 5a}"
GENYMOTION_GMTOOL="/opt/genymotion/genymotion/gmtool"
GENYMOTION_NAT_NIC="nic3"
GENYMOTION_NAT_IFACE="eth2"
GENYMOTION_NETD_ID="100"
GENYMOTION_BOOT_TIMEOUT=90
# The host's own real LAN IP and a dedicated Burp listener port, reachable from a Genymotion guest
# once nic3/NAT+netd is set up (10.0.2.2, the emulator alias, and the plain loopback 8080 listener
# do NOT work for this target). Set by install_mobile_pt.sh from the interface you pick; override
# here or in .env (GENYMOTION_BURP_HOST / GENYMOTION_BURP_PORT) if you change networks later.
GENYMOTION_BURP_HOST="${GENYMOTION_BURP_HOST:-}"
GENYMOTION_BURP_PORT="${GENYMOTION_BURP_PORT:-8090}"

# --- Burp Suite (default/persistent project - matches portal/backend/app/services/burp_service.py
# exactly, so a job started through the portal reuses this same running instance rather than
# fighting over the launched process) ------------------------------------------------------------
# "community" (default, free) or "pro". Community can't reload a project file from the CLI, so the
# --project-file flag below is skipped for it - see portal/README.md's Burp section.
BURP_EDITION="${BURP_EDITION:-community}"
BURP_JAR_CANDIDATES=(
    "/opt/BurpSuiteCommunity/burpsuite.jar"
    "/usr/share/burpsuite/burpsuite.jar"  # Kali/Debian `apt install burpsuite` (Community)
    "/opt/BurpSuitePro/burpsuite.jar"
)
BURP_PROJECT_FILE="${BASE_DIR}/portal/data/burp/mobile_pt.burp"
BURP_CONFIG_FILE="${BASE_DIR}/portal/scripts/burp-config-template.json"
BURP_PROXY_PORT="${BURP_PROXY_PORT:-8080}"
BURP_API_PORT="${BURP_API_PORT:-1337}"

# --- Portal dashboard (FastAPI backend + Vite-served React frontend) ---------------------------
# Defaults to loopback-only; set PORTAL_HOST=0.0.0.0 in .env (install_mobile_pt.sh offers this as
# an interactive choice) to make the dashboard reachable from other devices on the LAN (e.g. a
# teammate's laptop). Only the bind address changes - the backend's own session-cookie login still
# gates every page and API call regardless of where the request originates from (see auth.py).
# vite.config.ts's own `server.host`/`port`/`strictPort` mirror these same values, so `npm run dev`
# picks this up with no extra flags needed here.
PORTAL_DIR="${BASE_DIR}/portal"
PORTAL_BACKEND_DIR="${PORTAL_DIR}/backend"
PORTAL_FRONTEND_DIR="${PORTAL_DIR}/frontend"
PORTAL_HOST="${PORTAL_HOST:-127.0.0.1}"
PORTAL_BACKEND_PORT="8811"
PORTAL_FRONTEND_PORT="5173"

mkdir -p "$LOG_DIR" "$MOBSF_DATA_DIR"

# ---------------------------------------------------------------------------
# Colors / logging
# ---------------------------------------------------------------------------
C_RESET="\033[0m"; C_RED="\033[31m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_BLUE="\033[34m"; C_BOLD="\033[1m"

# All four go to stderr, not just err() - these are human-readable progress messages, and several
# functions (start_emulator_if_needed, in particular) are called as `x="$(fn ...)"` to capture a
# real return value (the device serial) from their final `echo`. Before this fix, info()/ok()/warn()
# printed to stdout like everything else, so that capture silently picked up every progress message
# too - confirmed in production: MOBSF_ANALYZER_IDENTIFIER ended up containing literal text like
# "[*] Starting emulator 'MobSF_Pentest' (headless)..." instead of "emulator-5554", breaking every
# MobSF dynamic-analysis API call that depends on that env var targeting the right device.
info()  { echo -e "${C_BLUE}[*]${C_RESET} $*" >&2; }
ok()    { echo -e "${C_GREEN}[+]${C_RESET} $*" >&2; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $*" >&2; }
err()   { echo -e "${C_RED}[-]${C_RESET} $*" >&2; }

# with_retries <max_attempts> <backoff_seconds> <description> <fn> [args...]
# Runs <fn> up to <max_attempts> times with a growing delay between attempts (backoff * attempt
# number), only warning (not erroring) on intermediate failures - the caller decides what a final
# failure after all attempts means. This is what makes `launch`/`heal` genuinely autonomous: every
# step that's shown transient real-world flakiness (gmtool's own license/session hiccups, a guest
# still settling network state right after boot) gets retried automatically, in place, with no
# separate manual re-run ever required for those known-transient cases.
with_retries() {
    local max_attempts="$1" backoff="$2" desc="$3"
    shift 3
    local attempt=1
    while [ "$attempt" -le "$max_attempts" ]; do
        if "$@"; then
            return 0
        fi
        if [ "$attempt" -lt "$max_attempts" ]; then
            warn "${desc}: attempt ${attempt}/${max_attempts} failed, retrying in $((backoff * attempt))s..."
            sleep $((backoff * attempt))
        fi
        attempt=$((attempt + 1))
    done
    err "${desc}: failed after ${max_attempts} attempts."
    return 1
}

# ---------------------------------------------------------------------------
# SDK discovery / environment
# ---------------------------------------------------------------------------
detect_sdk_root() {
    for candidate in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" /usr/lib/android-sdk /root/Android/Sdk /opt/android-sdk; do
        if [ -n "${candidate:-}" ] && [ -d "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

setup_env() {
    SDK_ROOT="$(detect_sdk_root)" || { err "Android SDK not found. Run: $0 setup"; return 1; }
    export ANDROID_HOME="$SDK_ROOT"
    export ANDROID_SDK_ROOT="$SDK_ROOT"

    CMDLINE_BIN="$(find "$SDK_ROOT/cmdline-tools" -maxdepth 2 -type d -name bin 2>/dev/null | sort -V | tail -1)"
    EMULATOR_BIN="$SDK_ROOT/emulator/emulator"
    PLATFORM_TOOLS="$SDK_ROOT/platform-tools"

    export PATH="${CMDLINE_BIN:-}:${PLATFORM_TOOLS}:${SDK_ROOT}/emulator:${PATH}"

    SDKMANAGER="$(command -v sdkmanager || echo "${CMDLINE_BIN}/sdkmanager")"
    AVDMANAGER="$(command -v avdmanager || echo "${CMDLINE_BIN}/avdmanager")"
    ADB="$(command -v adb || echo "${PLATFORM_TOOLS}/adb")"
    EMULATOR="$EMULATOR_BIN"
    return 0
}

check_kvm() {
    if [ ! -e /dev/kvm ]; then
        warn "/dev/kvm not found - emulator will fall back to slow software rendering."
        return 1
    fi
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        warn "/dev/kvm exists but is not read/writable by this user."
        return 1
    fi
    ok "KVM hardware acceleration available."
    return 0
}

# ---------------------------------------------------------------------------
# Genymotion cleanup (defensive - user requested removal if present)
# ---------------------------------------------------------------------------
cmd_uninstall_genymotion() {
    info "Checking for Genymotion installation..."
    local found=0

    if dpkg -l 2>/dev/null | grep -qi genymotion; then
        found=1
        warn "Found Genymotion apt package(s) - purging."
        apt-get purge -y '*genymotion*' 2>&1 | tail -20
        apt-get autoremove -y 2>&1 | tail -10
    fi

    for path in /opt/genymotion* /opt/*Genymotion* "$HOME/.Genymobile" "$HOME/.local/share/Genymobile" /usr/share/applications/genymotion*.desktop; do
        if compgen -G "$path" > /dev/null 2>&1; then
            found=1
            warn "Removing $path"
            rm -rf $path
        fi
    done

    if [ "$found" -eq 0 ]; then
        ok "Genymotion is not installed on this system - nothing to remove."
    else
        ok "Genymotion removed."
    fi
}

# ---------------------------------------------------------------------------
# Setup (one-time)
# ---------------------------------------------------------------------------
cmd_setup() {
    info "=== Mobile PT Lab: One-time setup ==="

    check_kvm

    info "Installing Android SDK components via apt (cmdline-tools, platform-tools, emulator, platform ${API_LEVEL})..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        google-android-cmdline-tools-22.0-installer \
        google-android-platform-tools-installer \
        google-android-emulator-installer \
        "google-android-platform-${API_LEVEL}-installer" \
        google-android-build-tools-30.0.3-installer \
        2>&1 | tee -a "${LOG_DIR}/setup.log" | tail -40

    setup_env || { err "SDK environment setup failed after install."; return 1; }

    if [ ! -x "$SDKMANAGER" ]; then
        err "sdkmanager not found at $SDKMANAGER after install."
        return 1
    fi

    info "Accepting Android SDK licenses..."
    yes | "$SDKMANAGER" --licenses >> "${LOG_DIR}/setup.log" 2>&1

    info "Downloading system image: ${SYSTEM_IMAGE} (this can take a while)..."
    "$SDKMANAGER" --install "$SYSTEM_IMAGE" "platform-tools" "emulator" 2>&1 | tee -a "${LOG_DIR}/setup.log" | tail -40

    local avd_name="${1:-$AVD_NAME_DEFAULT}"
    if "$AVDMANAGER" list avd | grep -q "Name: ${avd_name}$"; then
        ok "AVD '${avd_name}' already exists - skipping creation."
    else
        info "Creating AVD '${avd_name}'..."
        echo "no" | "$AVDMANAGER" create avd \
            -n "$avd_name" \
            -k "$SYSTEM_IMAGE" \
            -d "$DEVICE_PROFILE" \
            --force >> "${LOG_DIR}/setup.log" 2>&1
        ok "AVD '${avd_name}' created."
    fi

    # Persist env vars for interactive shells
    for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
        [ -f "$rc" ] || continue
        grep -q "MOBILE_PT_ANDROID_HOME" "$rc" 2>/dev/null || cat >> "$rc" <<EOF

# MOBILE_PT_ANDROID_HOME - added by mobile_pt.sh setup
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
export PATH="\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/emulator:\$PATH"
EOF
    done

    info "Pulling MobSF docker image..."
    docker pull "$MOBSF_IMAGE" 2>&1 | tail -10

    cmd_uninstall_genymotion

    ok "Setup complete. Run '$0 launch' to start the lab."
}

# ---------------------------------------------------------------------------
# Launch (daily use)
# ---------------------------------------------------------------------------
wait_for_boot() {
    local serial="$1"
    local waited=0
    info "Waiting for emulator to finish booting (timeout ${BOOT_TIMEOUT}s)..."
    "$ADB" -s "$serial" wait-for-device
    while true; do
        local boot_completed
        boot_completed="$("$ADB" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n')"
        if [ "$boot_completed" = "1" ]; then
            ok "Emulator booted."
            return 0
        fi
        if [ "$waited" -ge "$BOOT_TIMEOUT" ]; then
            err "Timed out waiting for emulator boot."
            return 1
        fi
        sleep 3
        waited=$((waited + 3))
    done
}

start_emulator_if_needed() {
    local avd_name="$1"
    local mode="$2" # gui|headless

    setup_env || return 1

    local running_serial
    # Must require the "device" state specifically, not just a line starting with "emulator-":
    # an "offline" or "unauthorized" entry means adb can't actually talk to it, so treating that
    # as "already running - reuse it" (confirmed hands-on: this is exactly what happened after a
    # wedged `adb reboot` left a device stuck offline) skips straight past the boot-wait and
    # writability check below, silently handing every subsequent job a broken device.
    running_serial="$("$ADB" devices 2>/dev/null | awk '/^emulator-.*[[:space:]]device$/{print $1; exit}')"
    if [ -n "$running_serial" ]; then
        ok "Emulator already running as $running_serial - reusing it."
        echo "$running_serial"
        return 0
    fi

    if [ ! -f "${SDK_ROOT}/system-images/android-${API_LEVEL}/google_apis/${ARCH}/system.img" ] && \
       ! "$AVDMANAGER" list avd | grep -q "Name: ${avd_name}$"; then
        err "AVD '${avd_name}' not found. Run: $0 setup"
        return 1
    fi

    local extra_flags=()
    if [ "$mode" = "headless" ]; then
        extra_flags+=(-no-window -no-audio)
    fi

    info "Starting emulator '${avd_name}' (${mode})..."
    # No -wipe-data: installed apps, pushed files, and Frida/CA state persist across
    # teardown+launch cycles by design, so a pentest session can be resumed instead of starting
    # from scratch every time. This is safe specifically *because* nothing in this codebase ever
    # remounts the root filesystem read-write or issues an in-guest reboot anymore (adb_service.py
    # uses a `su 0`-mounted tmpfs overlay over just /system/etc/security/cacerts/ instead) - on at
    # least one build, `adb root`/`adb remount`/`adb reboot` were each
    # found to reliably corrupt the running instance (an in-guest reboot risks an infinite AVB
    # "vbmeta digest mismatch" loop; `adb root` wedges the connection by racing the emulator's own
    # post-boot setup). Never add any of those three commands back without re-reading that section
    # first. If the AVD's state ever does get corrupted some other way, recover with:
    #   mobile_pt.sh teardown && rm -rf ~/.android/avd/MobSF_Pentest.avd/*.lock && \
    #   emulator -avd MobSF_Pentest -wipe-data -no-snapshot -writable-system -no-window (one-off, manual)
    nohup "$EMULATOR" -avd "$avd_name" -no-boot-anim -no-snapshot -writable-system \
        "${extra_flags[@]}" > "${LOG_DIR}/emulator.log" 2>&1 &
    echo $! > "$PID_FILE"

    sleep 5
    running_serial="$("$ADB" devices 2>/dev/null | awk '/^emulator-/{print $1; exit}')"
    local waited=0
    while [ -z "$running_serial" ] && [ "$waited" -lt 60 ]; do
        sleep 2
        waited=$((waited + 2))
        running_serial="$("$ADB" devices 2>/dev/null | awk '/^emulator-/{print $1; exit}')"
    done

    if [ -z "$running_serial" ]; then
        err "Emulator did not register with adb. Check ${LOG_DIR}/emulator.log"
        return 1
    fi

    wait_for_boot "$running_serial" || return 1

    # `sys.boot_completed=1` fires *before* the emulator's own internal post-boot setup (overlay
    # config, multidisplay broadcast, etc - visible in emulator.log as several
    # `adb shell cmd overlay ...` / `am broadcast ...` calls) has finished. Confirmed hands-on:
    # issuing our own adb commands (even just `adb root`) while those are still in flight loses
    # the race and wedges the connection into a permanent "offline" state that never recovers.
    # A short grace period avoids this - cheap insurance against a very sticky failure mode.
    sleep 12

    # No `adb root` / `adb remount` / `adb reboot` here on purpose - see adb_service.py's module
    # docstring (portal/backend/app/services/adb_service.py) for the full story: on this box's
    # specific emulator/kernel/AVB build, every one of those reliably either wedges the adb
    # connection permanently or drives the guest into an infinite "vbmeta digest mismatch" reboot
    # loop. The portal writes to /system (for Burp's CA) via a `su 0`-mounted tmpfs overlay over
    # just /system/etc/security/cacerts instead, which needs no reboot and never touches the
    # verity/AVB-protected block device. Confirm the device is at least rootable via `su`:
    if ! "$ADB" -s "$running_serial" shell "su 0 id" 2>/dev/null | grep -q "uid=0"; then
        err "Device is not rootable via 'su 0' - is this the google_apis (non-Play-Store) image?"
        return 1
    fi

    echo "$running_serial"
}

start_mobsf() {
    local serial="$1"

    info "(Re)configuring MobSF container..."
    docker rm -f "$MOBSF_CONTAINER_NAME" >/dev/null 2>&1

    # Any older ad-hoc containers from the same image, not under our managed name
    for cid in $(docker ps -aq --filter "ancestor=${MOBSF_IMAGE}"); do
        docker rm -f "$cid" >/dev/null 2>&1
    done

    # The image runs as its own unprivileged `mobsf` user (uid/gid 9901), not root - a bind-mounted
    # host directory created by this script (owned by root) would otherwise make MobSF crash-loop
    # on startup with PermissionError writing into /home/mobsf/.MobSF. Match ownership up front.
    chown -R 9901:9901 "$MOBSF_DATA_DIR" 2>/dev/null || true

    # Bind-mount a copy of THIS host's already-authorized adb key into the container's $HOME/.android.
    # Without this, MobSF auto-generates its own adbkey on first run; when mobsfy() calls
    # `adb kill-server` (unconditional, every call) the adb server that respawns afterward is the
    # one MobSF's own process spawns, presenting THAT key - a real physical device has never seen it
    # before and drops to "unauthorized" (confirmed live: a Moto G6 that was already `device` over
    # WiFi adb went `unauthorized` the instant mobsfy() ran, needing a manual re-tap on the phone to
    # recover). Pre-seeding the container with the SAME key this host's adb
    # already uses (which the phone already trusts) avoids the re-authorization prompt entirely. The
    # AVD emulator never showed this symptom because AVD images don't enforce the RSA-key
    # authorization dialog the way real hardware does - so this was invisible until testing against
    # a physical device specifically.
    mkdir -p "$MOBSF_ADB_HOME_DIR"
    if [ -f "${HOME}/.android/adbkey" ] && [ -f "${HOME}/.android/adbkey.pub" ]; then
        cp -f "${HOME}/.android/adbkey" "${HOME}/.android/adbkey.pub" "$MOBSF_ADB_HOME_DIR/"
    else
        warn "No adb key found at ${HOME}/.android/adbkey - MobSF's container will generate its " \
             "own, which physical devices will need to freshly authorize on first dynamic-analysis use."
    fi
    chown -R 9901:9901 "$MOBSF_ADB_HOME_DIR" 2>/dev/null || true

    # --network host: simplest way for the MobSF container to reach the host's adb
    # server (127.0.0.1:5037) and the emulator's console, required for dynamic analysis.
    #
    # MOBSF_PLATFORM= (blank, overriding the image's own "docker" default): MobSF's
    # docker_translate_localhost() rewrites an "emulator-NNNN" identifier to
    # "host.docker.internal:<port>" whenever MOBSF_PLATFORM=docker - correct for a bridge-network
    # container, but wrong here: with --network host, "emulator-5554" is already directly reachable
    # via the shared host adb server, and that translation makes every MobSF dynamic-analysis API
    # call fail on its very first adb command instead. Confirmed live: POST /api/v1/android/mobsfy
    # failed with "adb -s host.docker.internal:5555 root" until this was blanked out.
    docker run -d \
        --name "$MOBSF_CONTAINER_NAME" \
        --network host \
        --restart unless-stopped \
        -v "${MOBSF_DATA_DIR}:/home/mobsf/.MobSF" \
        -v "${MOBSF_ADB_HOME_DIR}:/home/mobsf/.android" \
        -e "MOBSF_ANALYZER_IDENTIFIER=${serial}" \
        -e "MOBSF_PLATFORM=" \
        "$MOBSF_IMAGE" >> "${LOG_DIR}/mobsf.log" 2>&1

    info "Waiting for MobSF to come up (timeout ${MOBSF_TIMEOUT}s)..."
    local waited=0
    while [ "$waited" -lt "$MOBSF_TIMEOUT" ]; do
        if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MOBSF_PORT}/" 2>/dev/null | grep -qE '^(200|302)$'; then
            ok "MobSF is up."
            return 0
        fi
        sleep 3
        waited=$((waited + 3))
    done
    warn "MobSF did not respond within timeout - check 'docker logs ${MOBSF_CONTAINER_NAME}'"
    return 1
}

# ---------------------------------------------------------------------------
# Genymotion (MobSF-DAST target) - lifecycle + self-healing NAT/netd fixup
# ---------------------------------------------------------------------------
genymotion_available() {
    [ -x "$GENYMOTION_GMTOOL" ]
}

genymotion_vm_state() {
    # Prints "On" or "Off" (gmtool's own vocabulary), empty if the VM doesn't exist at all.
    "$GENYMOTION_GMTOOL" admin list 2>/dev/null | awk -v name="$GENYMOTION_VM_NAME" \
        -F'\\|' '$0 ~ name {gsub(/^[ \t]+|[ \t]+$/, "", $1); print $1}'
}

genymotion_adb_serial() {
    # Prints the adb serial gmtool itself reports for the VM (its nic1/hostonly address - fixed and
    # predictable specifically because nic1 is never touched, unlike nic3).
    "$GENYMOTION_GMTOOL" admin list 2>/dev/null | awk -v name="$GENYMOTION_VM_NAME" \
        -F'\\|' '$0 ~ name {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}'
}

_genymotion_gmtool_start_once() {
    "$GENYMOTION_GMTOOL" admin start "$GENYMOTION_VM_NAME" >>"${LOG_DIR}/genymotion.log" 2>&1
}

_genymotion_wait_reachable() {
    local serial waited=0
    while [ "$waited" -lt "$GENYMOTION_BOOT_TIMEOUT" ]; do
        serial="$(genymotion_adb_serial)"
        if [ -n "$serial" ]; then
            "$ADB" connect "$serial" >/dev/null 2>&1
            if "$ADB" -s "$serial" shell "echo ready" 2>/dev/null | grep -q "ready"; then
                ok "Genymotion reachable at $serial"
                echo "$serial"
                return 0
            fi
        fi
        sleep 3
        waited=$((waited + 3))
    done
    return 1
}

start_genymotion_if_needed() {
    genymotion_available || { err "Genymotion not installed (expected ${GENYMOTION_GMTOOL})"; return 1; }

    local state
    state="$(genymotion_vm_state)"
    if [ -z "$state" ]; then
        err "Genymotion VM '${GENYMOTION_VM_NAME}' not found - create it first."
        return 1
    fi

    if [ "$state" != "On" ]; then
        info "Starting Genymotion VM '${GENYMOTION_VM_NAME}'..."
        # Confirmed live: gmtool admin start occasionally fails once right after a cold host boot or
        # a rapid stop/start cycle (a transient Genymotion license/session hiccup, not a real VM
        # fault) and succeeds cleanly on a retry.
        with_retries 2 3 "gmtool admin start" _genymotion_gmtool_start_once || return 1
    else
        ok "Genymotion VM already running."
    fi

    local serial
    if serial="$(_genymotion_wait_reachable)"; then
        echo "$serial"
        return 0
    fi

    # Confirmed live: gmtool can report "On" for a VM whose guest network
    # never actually came up reachable - only a real stop/start power-cycle recovers it, not more
    # waiting. Autonomous recovery: cycle it once and give the boot wait one more full attempt.
    warn "Genymotion showed 'On' but never became reachable - power-cycling to recover..."
    "$GENYMOTION_GMTOOL" admin stop "$GENYMOTION_VM_NAME" >>"${LOG_DIR}/genymotion.log" 2>&1
    sleep 3
    with_retries 2 3 "gmtool admin start (recovery)" _genymotion_gmtool_start_once || return 1
    if serial="$(_genymotion_wait_reachable)"; then
        echo "$serial"
        return 0
    fi
    err "Genymotion did not become reachable even after a power-cycle - check ${LOG_DIR}/genymotion.log"
    return 1
}

genymotion_ensure_nat_nic() {
    # nic3 is additive and NOT reset by Genymotion's own launcher (confirmed across many restarts -
    # unlike nic1, which its player unconditionally resets to hostonly every single start). Adding a
    # brand-new adapter requires the VM to be OFF, so this only runs the stop/modify/start cycle the
    # first time (idempotent - skipped once nic3 is already "nat").
    local current
    current="$(VBoxManage showvminfo "$GENYMOTION_VM_NAME" --machinereadable 2>/dev/null | \
        grep -i "^${GENYMOTION_NAT_NIC}=" | cut -d'"' -f2)"
    if [ "$current" = "nat" ]; then
        return 0
    fi

    info "One-time setup: adding a NAT-only network adapter (${GENYMOTION_NAT_NIC}) to Genymotion..."
    "$GENYMOTION_GMTOOL" admin stop "$GENYMOTION_VM_NAME" >>"${LOG_DIR}/genymotion.log" 2>&1
    sleep 3
    if ! VBoxManage modifyvm "$GENYMOTION_VM_NAME" "--${GENYMOTION_NAT_NIC}" nat >>"${LOG_DIR}/genymotion.log" 2>&1; then
        err "Could not add ${GENYMOTION_NAT_NIC} as NAT - see ${LOG_DIR}/genymotion.log"
        return 1
    fi
    start_genymotion_if_needed >/dev/null
}

_genymotion_can_reach_burp() {
    local serial="$1"
    "$ADB" -s "$serial" shell "echo | nc -w 3 ${GENYMOTION_BURP_HOST} ${GENYMOTION_BURP_PORT}; echo EXIT=\$?" 2>/dev/null | grep -q "EXIT=0"
}

_genymotion_apply_networking_once() {
    # One attempt at the fixup + verification - the unit with_retries below repeats autonomously.
    # Every step here is idempotent/safe to re-issue (ip link set up on an already-up link, ndc
    # network create against an already-existing id, etc.), which is exactly what makes blind
    # retries safe rather than something that could compound into a worse state.
    #
    # IMPORTANT: the real "is this already done" signal is the connectivity check at the end, NOT
    # "does the interface have an IP" - confirmed live that eth2 can already
    # have a valid IP (e.g. surviving from a prior boot's partial attempt) while the `ndc network`
    # registration was never actually applied this boot, since that registration doesn't survive a
    # guest reboot any more than the IP lease does. Checking "has an IP" as a skip condition
    # silently skipped the one step that actually matters. So: check real connectivity FIRST, and
    # only skip the fixup steps entirely if that already passes.
    local serial="$1"

    if _genymotion_can_reach_burp "$serial"; then
        ok "Genymotion already configured and can reach Burp."
        return 0
    fi

    info "Configuring Genymotion's NAT interface (${GENYMOTION_NAT_IFACE}) for outbound traffic..."
    "$ADB" -s "$serial" shell "su 0 sh -c 'ip link set ${GENYMOTION_NAT_IFACE} up'" >/dev/null 2>&1
    sleep 2
    # dhcptool can fail to acquire a *new* lease if the interface already has one from a prior
    # attempt this boot (its own idempotency quirk, separate from the netd-registration gap above)
    # - only treat it as fatal if the interface still has no IP at all afterward.
    "$ADB" -s "$serial" shell "su 0 sh -c 'dhcptool ${GENYMOTION_NAT_IFACE}'" >/dev/null 2>&1
    if ! "$ADB" -s "$serial" shell "su 0 sh -c 'ip addr show ${GENYMOTION_NAT_IFACE}'" 2>/dev/null | grep -q "inet "; then
        err "dhcptool failed on ${GENYMOTION_NAT_IFACE} and it still has no IP - is nic3 actually NAT? (genymotion_ensure_nat_nic)"
        return 1
    fi

    local gw
    gw="$("$ADB" -s "$serial" shell "ip route" 2>/dev/null | \
        awk -v ifc="$GENYMOTION_NAT_IFACE" '$0 ~ ("dev "ifc) && /^default/ {print $3}')"
    # Registering as an actual netd network (not just a kernel route) is what makes Android's
    # own policy routing (`ip rule`) stop sending this interface's traffic to its final
    # catch-all "unreachable" rule - confirmed live this is the real gate, not the routing table
    #. `network create` legitimately fails with "already exists" on a repeat
    # run against the same ID - harmless, the following interface/route/default calls are what
    # matter and are safe (and necessary) to re-issue every time this function actually runs.
    "$ADB" -s "$serial" shell "su 0 sh -c 'ndc network create ${GENYMOTION_NETD_ID}'" >/dev/null 2>&1
    "$ADB" -s "$serial" shell "su 0 sh -c 'ndc network interface add ${GENYMOTION_NETD_ID} ${GENYMOTION_NAT_IFACE}'" >/dev/null 2>&1
    "$ADB" -s "$serial" shell "su 0 sh -c 'ndc network route add ${GENYMOTION_NETD_ID} ${GENYMOTION_NAT_IFACE} 0.0.0.0/0 ${gw}'" >/dev/null 2>&1
    "$ADB" -s "$serial" shell "su 0 sh -c 'ndc network default set ${GENYMOTION_NETD_ID}'" >/dev/null 2>&1

    # Real end-to-end proof, not just "a route exists" - confirmed live this is the only reliable
    # signal.
    if _genymotion_can_reach_burp "$serial"; then
        ok "Genymotion can reach Burp (${GENYMOTION_BURP_HOST}:${GENYMOTION_BURP_PORT})."
        return 0
    fi
    return 1
}

genymotion_fix_networking() {
    # Per-boot fixup: nic3 exists at the VirtualBox level, but the guest's own Android network stack
    # never automatically brings up a newly-appeared interface, requests a lease on it, or picks it
    # as netd's default network - none of that survives a guest reboot, so this has to run every
    # time, even though the underlying nic3=nat VM config is one-time (see genymotion_ensure_nat_nic).
    # Confirmed live: nic1/hostonly stays completely untouched throughout - adb
    # reachability never depends on any of this succeeding. Retried autonomously (idempotent steps,
    # safe to re-issue) since the guest's network stack can need a moment to settle right after boot.
    local serial="$1"
    with_retries 3 5 "Genymotion networking fixup" _genymotion_apply_networking_once "$serial"
}

setup_genymotion() {
    genymotion_available || { warn "Genymotion not installed - skipping (MobSF-DAST modes needing it will fail clearly)."; return 1; }
    local serial attempt
    for attempt in 1 2 3; do
        serial="$(start_genymotion_if_needed)" && genymotion_ensure_nat_nic && genymotion_fix_networking "$serial" && {
            echo "$serial"
            return 0
        }
        if [ "$attempt" -lt 3 ]; then
            warn "Genymotion full setup attempt ${attempt}/3 failed, retrying from scratch..."
            sleep $((10 * attempt))
        fi
    done
    err "Genymotion setup failed after 3 full attempts - see ${LOG_DIR}/genymotion.log"
    return 1
}

# ---------------------------------------------------------------------------
# Burp Suite (default/persistent project)
# ---------------------------------------------------------------------------
burp_jar_path() {
    for jar in "${BURP_JAR_CANDIDATES[@]}"; do
        [ -f "$jar" ] && { echo "$jar"; return 0; }
    done
    return 1
}

burp_proxy_listening() {
    # Loopback:8080 is the one listener guaranteed to exist regardless of what's saved in the
    # project file (config-file always provides it) - the right thing to poll for "is Burp up".
    # A LAN listener (used by Genymotion/physical devices) lives in the persisted project state on
    # Pro, or needs adding by hand in Burp's own GUI on Community - either way it isn't reflected
    # here, so this check only ever confirms the loopback listener.
    (exec 3<>"/dev/tcp/127.0.0.1/${BURP_PROXY_PORT}") 2>/dev/null && exec 3>&- 3<&-
}

start_burp_if_needed() {
    if pgrep -f "burpsuite.jar" >/dev/null 2>&1 && burp_proxy_listening; then
        ok "Burp Suite already running."
        return 0
    fi

    local jar
    jar="$(burp_jar_path)" || { err "Burp Suite jar not found - install Burp Suite Community (apt install burpsuite, or download from portswigger.net) and re-run"; return 1; }

    local -a burp_args=(-jar "$jar" "--config-file=${BURP_CONFIG_FILE}")
    if [ "$BURP_EDITION" = "pro" ]; then
        mkdir -p "$(dirname "$BURP_PROJECT_FILE")"
        burp_args+=("--project-file=${BURP_PROJECT_FILE}")
        info "Starting Burp Suite Pro (project: ${BURP_PROJECT_FILE})..."
    else
        info "Starting Burp Suite Community (no persistent project - add any extra listeners by hand after it starts)..."
    fi
    nohup java "${burp_args[@]}" >>"${LOG_DIR}/burp.log" 2>&1 &

    local waited=0
    while [ "$waited" -lt 90 ]; do
        burp_proxy_listening && { ok "Burp Suite is up."; return 0; }
        sleep 2
        waited=$((waited + 2))
    done
    err "Burp Suite did not come up within 90s - check ${LOG_DIR}/burp.log"
    return 1
}

portal_backend_listening() {
    (exec 3<>"/dev/tcp/127.0.0.1/${PORTAL_BACKEND_PORT}") 2>/dev/null && exec 3>&- 3<&-
}

portal_frontend_listening() {
    (exec 3<>"/dev/tcp/127.0.0.1/${PORTAL_FRONTEND_PORT}") 2>/dev/null && exec 3>&- 3<&-
}

start_portal_backend_if_needed() {
    if pgrep -f "uvicorn app.main:app" >/dev/null 2>&1 && portal_backend_listening; then
        ok "Portal backend already running."
        return 0
    fi

    local uvicorn_bin="${PORTAL_BACKEND_DIR}/.venv/bin/uvicorn"
    if [ ! -x "$uvicorn_bin" ]; then
        err "Portal backend venv not found at ${uvicorn_bin} - run the portal's own setup first"
        return 1
    fi

    info "Starting portal backend (http://${PORTAL_HOST}:${PORTAL_BACKEND_PORT})..."
    (
        cd "$PORTAL_BACKEND_DIR" || exit 1
        nohup "$uvicorn_bin" app.main:app --host "$PORTAL_HOST" --port "$PORTAL_BACKEND_PORT" \
            >>"${LOG_DIR}/portal_backend.log" 2>&1 &
    )

    local waited=0
    while [ "$waited" -lt 60 ]; do
        portal_backend_listening && { ok "Portal backend is up."; return 0; }
        sleep 2
        waited=$((waited + 2))
    done
    err "Portal backend did not come up within 60s - check ${LOG_DIR}/portal_backend.log"
    return 1
}

start_portal_frontend_if_needed() {
    if pgrep -f "node_modules/.bin/vite" >/dev/null 2>&1 && portal_frontend_listening; then
        ok "Portal frontend (Vite dev server) already running."
        return 0
    fi

    if [ ! -d "${PORTAL_FRONTEND_DIR}/node_modules" ]; then
        info "Frontend dependencies not installed yet - running npm install..."
        if ! (cd "$PORTAL_FRONTEND_DIR" && npm install >>"${LOG_DIR}/portal_frontend.log" 2>&1); then
            err "npm install failed - check ${LOG_DIR}/portal_frontend.log"
            return 1
        fi
    fi

    info "Starting portal frontend (http://${PORTAL_HOST}:${PORTAL_FRONTEND_PORT})..."
    (
        cd "$PORTAL_FRONTEND_DIR" || exit 1
        nohup npm run dev >>"${LOG_DIR}/portal_frontend.log" 2>&1 &
    )

    local waited=0
    while [ "$waited" -lt 60 ]; do
        portal_frontend_listening && { ok "Portal frontend is up."; return 0; }
        sleep 2
        waited=$((waited + 2))
    done
    err "Portal frontend did not come up within 60s - check ${LOG_DIR}/portal_frontend.log"
    return 1
}

start_portal_if_needed() {
    start_portal_backend_if_needed && start_portal_frontend_if_needed
}

cmd_launch() {
    local mode="gui"
    local avd_name="$AVD_NAME_DEFAULT"
    local with_genymotion=1
    local with_burp=1
    local with_portal=1

    while [ $# -gt 0 ]; do
        case "$1" in
            --gui) mode="gui" ;;
            --headless) mode="headless" ;;
            --avd) avd_name="$2"; shift ;;
            --no-genymotion) with_genymotion=0 ;;
            --no-burp) with_burp=0 ;;
            --no-portal) with_portal=0 ;;
            *) err "Unknown launch option: $1"; return 1 ;;
        esac
        shift
    done

    info "=== Mobile PT Lab: Launch (${mode}, avd=${avd_name}) ==="
    setup_env || return 1

    local serial
    serial="$(start_emulator_if_needed "$avd_name" "$mode")" || return 1

    # Every step below already retries autonomously internally (start_mobsf itself is fast/simple
    # enough that with_retries wraps it directly; setup_genymotion/start_burp_if_needed have their
    # own internal retry logic already, since they need finer-grained control - e.g. setup_genymotion
    # needs to retry the whole start+nat+network sequence as one unit, which a generic wrapper around
    # its echoed return value can't do cleanly). Nothing here just warns-once-and-moves-on anymore -
    # a final failure after all retries is a real, clearly-reported problem, not a silently degraded
    # launch.
    with_retries 2 5 "MobSF container" start_mobsf "$serial"

    # Burp MUST come up before Genymotion's networking fixup runs below - that fixup's own
    # success signal is a live connectivity check against Burp's LAN listener
    # (_genymotion_can_reach_burp), so on a first-ever launch (or any time Burp isn't already
    # running) checking Genymotion first would make every attempt fail this check for a reason
    # that has nothing to do with Genymotion, burning through all its retries pointlessly.
    if [ "$with_burp" -eq 1 ]; then
        with_retries 3 5 "Burp Suite" start_burp_if_needed || warn "Burp Suite failed after autonomous retries - manual-PT modes will fail until '$0 heal' succeeds."
    fi

    local geny_serial=""
    if [ "$with_genymotion" -eq 1 ]; then
        geny_serial="$(setup_genymotion)" || warn "Genymotion setup failed after autonomous retries - MobSF-DAST modes targeting it will fail clearly until '$0 heal' succeeds."
    fi

    if [ "$with_portal" -eq 1 ]; then
        with_retries 2 5 "Portal backend" start_portal_backend_if_needed || warn "Portal backend failed after autonomous retries - the dashboard will be unreachable until '$0 heal' succeeds."
        with_retries 2 5 "Portal frontend" start_portal_frontend_if_needed || warn "Portal frontend failed after autonomous retries - the dashboard will be unreachable until '$0 heal' succeeds."
    fi

    echo
    ok "Lab is up."
    echo -e "  ${C_BOLD}Emulator:${C_RESET}   $serial"
    [ -n "$geny_serial" ] && echo -e "  ${C_BOLD}Genymotion:${C_RESET} $geny_serial (Burp-reachable: ${GENYMOTION_BURP_HOST}:${GENYMOTION_BURP_PORT})"
    echo -e "  ${C_BOLD}MobSF:${C_RESET}      http://127.0.0.1:${MOBSF_PORT}  (default creds: mobsf/mobsf)"
    echo -e "  ${C_BOLD}Burp proxy:${C_RESET} 127.0.0.1:${BURP_PROXY_PORT} (loopback) / ${GENYMOTION_BURP_HOST}:${GENYMOTION_BURP_PORT} (LAN)"
    echo -e "  ${C_BOLD}Dashboard:${C_RESET}  http://${GENYMOTION_BURP_HOST}:${PORTAL_FRONTEND_PORT}  (LAN-accessible, login required)"
    echo -e "  ${C_BOLD}Logs:${C_RESET}       ${LOG_DIR}/"
    echo
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
cmd_status() {
    echo -e "${C_BOLD}== Emulator ==${C_RESET}"
    if setup_env 2>/dev/null; then
        "$ADB" devices 2>/dev/null || echo "adb not available"
    else
        warn "SDK not set up yet."
    fi

    echo
    echo -e "${C_BOLD}== MobSF container ==${C_RESET}"
    if docker ps -a --filter "name=${MOBSF_CONTAINER_NAME}" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -q .; then
        docker ps -a --filter "name=${MOBSF_CONTAINER_NAME}" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
    else
        echo "not running"
    fi

    echo
    echo -e "${C_BOLD}== Genymotion ==${C_RESET}"
    if genymotion_available; then
        local state serial
        state="$(genymotion_vm_state)"
        echo "VM state: ${state:-not found}"
        if [ "$state" = "On" ]; then
            serial="$(genymotion_adb_serial)"
            echo "adb serial: ${serial:-unknown}"
            local nic3_mode
            nic3_mode="$(VBoxManage showvminfo "$GENYMOTION_VM_NAME" --machinereadable 2>/dev/null | \
                grep -i "^${GENYMOTION_NAT_NIC}=" | cut -d'"' -f2)"
            echo "NAT adapter (${GENYMOTION_NAT_NIC}): ${nic3_mode:-not configured}"
            if [ -n "$serial" ] && "$ADB" -s "$serial" shell "echo | nc -w 3 ${GENYMOTION_BURP_HOST} ${GENYMOTION_BURP_PORT}; echo EXIT=\$?" 2>/dev/null | grep -q "EXIT=0"; then
                ok "Can reach Burp (${GENYMOTION_BURP_HOST}:${GENYMOTION_BURP_PORT})"
            else
                warn "Cannot reach Burp - run '$0 heal' to fix"
            fi
        fi
    else
        echo "not installed"
    fi

    echo
    echo -e "${C_BOLD}== Burp Suite ==${C_RESET}"
    if pgrep -f "burpsuite.jar" >/dev/null 2>&1; then
        if burp_proxy_listening; then
            ok "Running, loopback proxy up (127.0.0.1:${BURP_PROXY_PORT})"
        else
            warn "Process running but proxy not listening yet"
        fi
    else
        echo "not running"
    fi

    echo
    echo -e "${C_BOLD}== Portal dashboard ==${C_RESET}"
    if pgrep -f "uvicorn app.main:app" >/dev/null 2>&1 && portal_backend_listening; then
        ok "Backend up (${PORTAL_HOST}:${PORTAL_BACKEND_PORT})"
    else
        echo "backend: not running"
    fi
    if pgrep -f "node_modules/.bin/vite" >/dev/null 2>&1 && portal_frontend_listening; then
        ok "Frontend up - http://${GENYMOTION_BURP_HOST}:${PORTAL_FRONTEND_PORT} (LAN-accessible)"
    else
        echo "frontend: not running"
    fi
}

# ---------------------------------------------------------------------------
# Ensure: narrow, non-interactive readiness check+fix for exactly what a caller needs, meant to
# be shelled out to by the portal backend itself (pipeline.py) right before a job actually uses
# a given service - so dropping a file in the frontend is enough on its own to bring the whole lab
# up; the user should never have to separately run `launch`/`heal` by hand first. Mirrors cmd_heal's
# per-component idempotent checks, but scoped to only what's requested (MobSF is always ensured -
# every analysis mode needs it for the static scan; Genymotion/Burp are opt-in per call via flags,
# since a plain SAST-only job or a physical-device job has no need to boot a VM or launch Burp) and
# exits non-zero with a clear stderr reason on the FIRST genuine failure instead of checking every
# component and summarizing at the end - the caller needs a fast, unambiguous yes/no per call.
# ---------------------------------------------------------------------------
cmd_ensure() {
    local device_type="" want_burp=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --device-type) device_type="$2"; shift ;;
            --burp) want_burp=1 ;;
            *) err "Unknown ensure option: $1"; return 1 ;;
        esac
        shift
    done

    setup_env || { err "SDK/env not set up"; return 1; }

    if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MOBSF_PORT}/" 2>/dev/null | grep -qE '^(200|302)$'; then
        ok "MobSF already healthy."
    else
        info "MobSF not responding - starting it..."
        local serial
        serial="$("$ADB" devices 2>/dev/null | awk '/^emulator-.*[[:space:]]device$/{print $1; exit}')"
        with_retries 2 5 "MobSF container" start_mobsf "$serial" || { err "MobSF failed to start - see ${LOG_DIR}/mobsf.log"; return 1; }
    fi

    if [ "$want_burp" -eq 1 ]; then
        with_retries 3 5 "Burp Suite" start_burp_if_needed || { err "Burp failed to start - see ${LOG_DIR}/burp.log"; return 1; }
    fi

    if [ "$device_type" = "genymotion" ]; then
        genymotion_available || { err "Genymotion not installed - cannot target it for this job"; return 1; }
        setup_genymotion >/dev/null || { err "Genymotion failed to start/network - see ${LOG_DIR}/genymotion.log"; return 1; }
    fi

    ok "Ensure complete."
    return 0
}

# ---------------------------------------------------------------------------
# Self-healing: re-check and repair each component without a full teardown
# ---------------------------------------------------------------------------
cmd_heal() {
    info "=== Mobile PT Lab: Self-heal ==="
    setup_env || return 1

    local any_failed=0

    echo -e "${C_BOLD}-- MobSF --${C_RESET}"
    if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MOBSF_PORT}/" 2>/dev/null | grep -qE '^(200|302)$'; then
        ok "MobSF healthy."
    else
        warn "MobSF not responding - recreating container..."
        local serial
        serial="$("$ADB" devices 2>/dev/null | awk '/^emulator-.*[[:space:]]device$/{print $1; exit}')"
        if [ -n "$serial" ] && with_retries 2 5 "MobSF container" start_mobsf "$serial"; then
            ok "MobSF recovered."
        else
            err "MobSF still not healthy - check ${LOG_DIR}/mobsf.log"
            any_failed=1
        fi
    fi

    echo
    echo -e "${C_BOLD}-- Burp Suite --${C_RESET}"
    # Must run before Genymotion below - Genymotion's own networking-fixup success check is a
    # live connectivity test against Burp's LAN listener, so if Burp isn't up yet that check
    # fails for a reason that has nothing to do with Genymotion itself.
    if with_retries 3 5 "Burp Suite" start_burp_if_needed; then
        ok "Burp healthy."
    else
        err "Burp still unhealthy - check ${LOG_DIR}/burp.log"
        any_failed=1
    fi

    echo
    echo -e "${C_BOLD}-- Genymotion --${C_RESET}"
    if genymotion_available; then
        if setup_genymotion >/dev/null; then
            ok "Genymotion healthy (reachable + can reach Burp)."
        else
            err "Genymotion still unhealthy - check ${LOG_DIR}/genymotion.log"
            any_failed=1
        fi
    else
        echo "not installed - skipping"
    fi

    echo
    echo -e "${C_BOLD}-- Portal dashboard --${C_RESET}"
    if with_retries 2 5 "Portal backend" start_portal_backend_if_needed && \
        with_retries 2 5 "Portal frontend" start_portal_frontend_if_needed; then
        ok "Portal healthy - http://${GENYMOTION_BURP_HOST}:${PORTAL_FRONTEND_PORT}"
    else
        err "Portal still unhealthy - check ${LOG_DIR}/portal_backend.log / portal_frontend.log"
        any_failed=1
    fi

    echo
    if [ "$any_failed" -eq 0 ]; then
        ok "All components healthy."
        return 0
    else
        err "One or more components still unhealthy - see above."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
cmd_teardown() {
    local wipe=0
    [ "${1:-}" = "--wipe" ] && wipe=1

    info "=== Mobile PT Lab: Teardown ==="

    info "Stopping MobSF container..."
    docker stop "$MOBSF_CONTAINER_NAME" >/dev/null 2>&1 || true
    [ "$wipe" -eq 1 ] && docker rm -f "$MOBSF_CONTAINER_NAME" >/dev/null 2>&1

    if setup_env 2>/dev/null; then
        local serial
        serial="$("$ADB" devices 2>/dev/null | awk '/^emulator-/{print $1; exit}')"
        if [ -n "$serial" ]; then
            info "Stopping emulator ($serial)..."
            "$ADB" -s "$serial" emu kill >/dev/null 2>&1 || true
        fi
    fi

    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" >/dev/null 2>&1 || true
        rm -f "$PID_FILE"
    fi

    if [ "$wipe" -eq 1 ]; then
        warn "Wiping MobSF persistent data (${MOBSF_DATA_DIR})..."
        rm -rf "${MOBSF_DATA_DIR:?}"/*
    fi

    ok "Teardown complete."
}

# ---------------------------------------------------------------------------
# Menu / arg parsing
# ---------------------------------------------------------------------------
print_help() {
    cat <<EOF
Mobile PT Lab Controller

Usage:
  $0                          Interactive menu
  $0 setup                    One-time install (Android SDK, AVD, MobSF image)
  $0 launch [--gui|--headless] [--avd NAME] [--no-genymotion] [--no-burp] [--no-portal]
                               Starts the AVD emulator + MobSF, and by default also Genymotion
                               (with its NAT/netd Burp-reachability fixup) + Burp Suite + the
                               portal dashboard (backend + frontend, bound to 0.0.0.0 - reachable
                               from other devices on the LAN, not just this host).
  $0 status                   Show what's running, including Genymotion/Burp connectivity and the
                               portal dashboard's LAN URL
  $0 heal                     Re-check every component and repair what's unhealthy, without a
                               full teardown (MobSF container, Genymotion NAT/netd, Burp process,
                               portal backend/frontend)
  $0 ensure [--device-type emulator|physical|genymotion] [--burp]
                               Narrow readiness check+fix for exactly what's requested (always
                               MobSF; Genymotion/Burp only if asked) - what the portal backend
                               itself calls before a job uses these, so it never has to be run
                               by hand for the portal to work.
  $0 teardown [--wipe]
  $0 uninstall-genymotion
  $0 help
EOF
}

interactive_menu() {
    echo -e "${C_BOLD}=== Mobile Pentest Lab (MobSF + Android Emulator AVD) ===${C_RESET}"
    echo "1) Setup      - one-time install of Android SDK / AVD / MobSF image"
    echo "2) Launch     - start emulator + MobSF + Genymotion + Burp"
    echo "3) Status     - show what's running"
    echo "4) Heal       - re-check and repair any unhealthy component"
    echo "5) Teardown   - stop emulator + MobSF"
    echo "6) Teardown + wipe data"
    echo "7) Uninstall Genymotion (if present)"
    echo "8) Quit"
    read -rp "Select an option [1-8]: " choice
    case "$choice" in
        1) cmd_setup ;;
        2)
            read -rp "Mode [gui/headless] (default gui): " m
            m="${m:-gui}"
            cmd_launch "--${m}"
            ;;
        3) cmd_status ;;
        4) cmd_heal ;;
        5) cmd_teardown ;;
        6) cmd_teardown --wipe ;;
        7) cmd_uninstall_genymotion ;;
        8) exit 0 ;;
        *) err "Invalid choice" ;;
    esac
}

main() {
    if [ $# -eq 0 ]; then
        interactive_menu
        exit 0
    fi

    local action="$1"; shift
    case "$action" in
        setup) cmd_setup "$@" ;;
        launch) cmd_launch "$@" ;;
        status) cmd_status ;;
        heal) cmd_heal ;;
        ensure) cmd_ensure "$@" ;;
        teardown) cmd_teardown "$@" ;;
        uninstall-genymotion) cmd_uninstall_genymotion ;;
        help|-h|--help) print_help ;;
        *) err "Unknown command: $action"; print_help; exit 1 ;;
    esac
}

main "$@"
