#!/usr/bin/env bash
# Starts the Mobile PT Automation Portal backend (serves the built frontend too - see
# backend/app/main.py's StaticFiles mount). Run setup.sh first if you haven't already.
set -euo pipefail

PORTAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${PORTAL_DIR}/.." && pwd)"
BACKEND_DIR="${PORTAL_DIR}/backend"
FRONTEND_DIST="${PORTAL_DIR}/frontend/dist"
ENV_FILE="${REPO_DIR}/.env"
PORT="${MOBILE_PT_PORTAL_PORT:-8811}"

if [ ! -f "$ENV_FILE" ]; then
    echo "No .env found at ${ENV_FILE} - run ../install_mobile_pt.sh then ./setup.sh first." >&2
    exit 1
fi

# PORTAL_HOST comes from .env (install_mobile_pt.sh's interactive network choice); default to
# loopback-only if it's unset for some reason.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
HOST="${PORTAL_HOST:-127.0.0.1}"

if [ ! -d "$FRONTEND_DIST" ]; then
    echo "Frontend not built yet - running npm run build..."
    (cd "${PORTAL_DIR}/frontend" && npm install && npm run build)
fi

cd "$BACKEND_DIR"
exec uv run uvicorn app.main:app --host "$HOST" --port "$PORT"
