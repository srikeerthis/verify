#!/usr/bin/env bash
# Boots the whole Verify stack from this repo:
#
#   web app   zipsign/   (Node, http://localhost:3000) — upload/OTP/signing UI
#   pipeline  app/       (FastAPI, http://localhost:8000) — scan/sign/notify
#
# First run installs dependencies and generates the shared secrets in .env
# (WEBAPP_API_KEY / LINQ_WEBHOOK_SECRET). Ctrl-C stops both servers.
#
# Env overrides: WEB_PORT=3000 API_PORT=8000 DEV_MODE=1 ./start.sh

set -euo pipefail
cd "$(dirname "$0")"

WEB_PORT="${WEB_PORT:-3000}"
API_PORT="${API_PORT:-8000}"

# --- stop anything already sitting on our ports (a stale server serving
# old code is the classic "Cannot GET" mystery) --------------------------
for port in "$WEB_PORT" "$API_PORT"; do
  pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo ">> killing stale process on port $port (pid $(echo $pids | tr '\n' ' '))"
    kill $pids 2>/dev/null || true
    sleep 0.5
  fi
done

# --- web app dependencies ------------------------------------------------
if [ ! -d zipsign/node_modules ]; then
  echo ">> installing web app dependencies (first run)..."
  (cd zipsign && npm install)
fi

# --- pipeline dependencies -----------------------------------------------
PY=python3.11
command -v "$PY" >/dev/null 2>&1 || PY=python3
if [ ! -x .venv/bin/python ]; then
  echo ">> creating venv with $PY (first run)..."
  "$PY" -m venv .venv
fi
if [ ! -x .venv/bin/uvicorn ]; then
  echo ">> installing pipeline dependencies (first run)..."
  .venv/bin/pip install -q -r requirements.txt
fi

# --- shared config: generate secrets into .env on first use --------------
[ -f .env ] || cp .env.example .env

set_kv() { # set_kv KEY VALUE — fill in when empty, append when missing entirely
  if ! grep -q "^$1=.." .env; then
    if grep -q "^$1=" .env; then
      sed -i '' -e "s|^$1=.*|$1=$2|" .env
    else
      printf '%s=%s\n' "$1" "$2" >> .env
    fi
  fi
}
env_get() { grep "^$1=" .env | head -1 | cut -d= -f2-; }

set_kv WEBAPP_API_KEY "$(openssl rand -hex 24)"
set_kv LINQ_WEBHOOK_SECRET "whsec_$(openssl rand -base64 24 | tr -d '\n')"
INTEGRATION_KEY=$(env_get WEBAPP_API_KEY)

# --- run both --------------------------------------------------------------
echo
echo "  web app (zipsign)   http://localhost:$WEB_PORT"
echo "  pipeline (FastAPI)  http://localhost:$API_PORT   POST /packages"
echo "  Ctrl-C stops both"
echo

INTEGRATION_API_KEY="$INTEGRATION_KEY" PORT="$WEB_PORT" \
  PIPELINE_URL="http://127.0.0.1:$API_PORT" node zipsign/server.js &
WEB_PID=$!
.venv/bin/uvicorn app.main:app --port "$API_PORT" &
API_PID=$!

cleanup() {
  kill "$WEB_PID" "$API_PID" 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

wait "$WEB_PID" "$API_PID"
