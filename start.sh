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
# On by default: no SMTP is configured locally, so without this the login code
# only appears in this terminal and testing on a phone is impossible. Set
# DEV_MODE=0 to send codes by email only.
DEV_MODE="${DEV_MODE:-1}"

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

env_get() { grep "^$1=" .env | head -1 | cut -d= -f2-; }

put_kv() { # put_kv KEY VALUE — overwrite in place, or append when missing.
  # python rather than sed: `sed -i ''` is BSD-only and `sed -i` is GNU-only,
  # and this repo is edited on both.
  KEY="$1" VALUE="$2" python3 - <<'PY'
import os, pathlib
key, value = os.environ["KEY"], os.environ["VALUE"]
p = pathlib.Path(".env")
lines = p.read_text().splitlines()
for i, line in enumerate(lines):
    if line.startswith(f"{key}="):
        lines[i] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
p.write_text("\n".join(lines) + "\n")
PY
}

set_kv() { # set_kv KEY VALUE — only when the key is missing or empty
  grep -q "^$1=.." .env || put_kv "$1" "$2"
}

set_kv WEBAPP_API_KEY "$(openssl rand -hex 24)"
INTEGRATION_KEY=$(env_get WEBAPP_API_KEY)

# --- Linq inbound webhook --------------------------------------------------
# Candidate replies arrive as webhooks, so Linq needs a subscription pointing at
# a publicly reachable URL. The signing secret is shown once at creation and can
# never be retrieved again, so when we do not have it, the only fix is to delete
# the subscription and make a new one.
#
# Never generate this secret ourselves — it has to be the one Linq issued, or
# every inbound delivery fails its signature check.
ensure_webhook() {
  LINQ_KEY=$(env_get LINQ_API_KEY)
  BASE=$(env_get PUBLIC_BASE_URL)
  API_BASE=$(env_get LINQ_API_BASE)
  [ -n "$API_BASE" ] || API_BASE="https://api.linqapp.com/api/partner/v3"

  if [ -z "$LINQ_KEY" ]; then
    echo ">> no LINQ_API_KEY — skipping webhook setup (outbound SMS is off too)"
    return
  fi
  case "$BASE" in
    ""|*localhost*|*127.0.0.1*)
      echo ">> PUBLIC_BASE_URL is '$BASE' — Linq cannot reach it, so candidate"
      echo "   replies will not arrive. Set it to your tunnel URL and rerun."
      return ;;
  esac

  TARGET="${BASE%/}/webhooks/linq"
  HAVE_SECRET=$(grep -q "^LINQ_WEBHOOK_SECRET=.." .env && echo yes || echo no)

  EXISTING=$(curl -sS "$API_BASE/webhook-subscriptions" \
    -H "Authorization: Bearer $LINQ_KEY" 2>/dev/null | TARGET="$TARGET" python3 -c '
import json, os, sys
try:
    body = json.load(sys.stdin)
except Exception:
    sys.exit(0)
subs = body if isinstance(body, list) else (body.get("data") or body.get("subscriptions") or [])
for s in subs:
    if s.get("target_url") == os.environ["TARGET"]:
        print(s.get("id", ""))
        break
' 2>/dev/null || true)

  if [ -n "$EXISTING" ] && [ "$HAVE_SECRET" = yes ]; then
    echo ">> Linq webhook already points at $TARGET"
    return
  fi

  # Either it does not exist, or it does and we lost the secret. Delete any
  # subscription on this path (ours or a stale tunnel's) and start clean.
  curl -sS "$API_BASE/webhook-subscriptions" -H "Authorization: Bearer $LINQ_KEY" 2>/dev/null |
    python3 -c '
import json, sys
try:
    body = json.load(sys.stdin)
except Exception:
    sys.exit(0)
subs = body if isinstance(body, list) else (body.get("data") or body.get("subscriptions") or [])
for s in subs:
    if str(s.get("target_url", "")).endswith("/webhooks/linq"):
        print(s.get("id", ""))
' 2>/dev/null | while read -r id; do
      [ -n "$id" ] || continue
      echo ">> removing stale webhook subscription $id"
      curl -sS -X DELETE "$API_BASE/webhook-subscriptions/$id" \
        -H "Authorization: Bearer $LINQ_KEY" >/dev/null 2>&1 || true
    done

  echo ">> creating Linq webhook -> $TARGET"
  SECRET=$(curl -sS -X POST "$API_BASE/webhook-subscriptions" \
    -H "Authorization: Bearer $LINQ_KEY" -H "Content-Type: application/json" \
    -d "{\"target_url\":\"$TARGET\",\"subscribed_events\":[\"message.received\"]}" \
    2>/dev/null | python3 -c '
import json, sys
try:
    body = json.load(sys.stdin)
except Exception:
    sys.exit(0)
data = body.get("data") if isinstance(body, dict) and "data" in body else body
print((data or {}).get("signing_secret", ""))
' 2>/dev/null || true)

  if [ -n "$SECRET" ]; then
    put_kv LINQ_WEBHOOK_SECRET "$SECRET"
    echo ">> webhook ready, signing secret saved to .env"
  else
    echo ">> WARNING: could not create the webhook subscription."
    echo "   Outbound texts still work; candidate replies will not arrive."
  fi
}

ensure_webhook

# --- run both --------------------------------------------------------------
echo
echo "  web app (zipsign)   http://localhost:$WEB_PORT"
echo "  pipeline (FastAPI)  http://localhost:$API_PORT   POST /packages"
echo "  Ctrl-C stops both"
echo

INTEGRATION_API_KEY="$INTEGRATION_KEY" PORT="$WEB_PORT" DEV_MODE="$DEV_MODE" \
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
