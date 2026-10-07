# run "bun install" first

# printf "show\n" | nc 127.0.0.1 9000

#!/usr/bin/env bash
set -euo pipefail

# Config
export TOKEN="${TOKEN:-h4eueow8038244x0r}"
export REPL_HOST="${REPL_HOST:-127.0.0.1}"
export REPL_PORT="${REPL_PORT:-9000}"
export BUN_HOST="${BUN_HOST:-127.0.0.1}"
export BUN_PORT="${BUN_PORT:-3000}"
BUN_ENTRY="${BUN_ENTRY:-BunServe.ts}"

TCP_LOG="/tmp/wikiscan_tcp.log"
BUN_LOG="/tmp/wikiscan_bun.log"

TCP_PID=""
BUN_PID=""

cleanup() {
  echo ""
  echo "Shutting down services..."
  if [[ -n "${BUN_PID}" ]] && kill -0 "${BUN_PID}" 2>/dev/null; then
    echo "Stopping Bun (${BUN_PID})"
    kill "${BUN_PID}" 2>/dev/null || true
    wait "${BUN_PID}" 2>/dev/null || true
  fi
  if [[ -n "${TCP_PID}" ]] && kill -0 "${TCP_PID}" 2>/dev/null; then
    echo "Stopping Rust TCP REPL (${TCP_PID})"
    kill "${TCP_PID}" 2>/dev/null || true
    wait "${TCP_PID}" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT

echo "Launching Backend (Rust TCP REPL) on ${REPL_HOST}:${REPL_PORT} ..."
# Option A: run via cargo (dev)
cargo run -- --tcp:"${REPL_HOST}:${REPL_PORT}" >"${TCP_LOG}" 2>&1 &
TCP_PID=$!

# Option B (recommended for prod): build then run the binary directly
# cargo build --release
# target/release/wikiscan --tcp:"${REPL_HOST}:${REPL_PORT}" >"${TCP_LOG}" 2>&1 &
# TCP_PID=$!

sleep 1

echo "Launching Middle (Bun HTTP) on ${BUN_HOST}:${BUN_PORT} ..."
BUN_HOST="${BUN_HOST}" BUN_PORT="${BUN_PORT}" REPL_HOST="${REPL_HOST}" REPL_PORT="${REPL_PORT}" \
  bun run "${BUN_ENTRY}" >"${BUN_LOG}" 2>&1 &
BUN_PID=$!

# Simple readiness wait for Bun
for i in {1..30}; do
  if curl -sSf "http://${BUN_HOST}:${BUN_PORT}/app.html" >/dev/null; then
    break
  fi
  sleep 0.3
done

open_browser() {
  local url="http://${BUN_HOST}:${BUN_PORT}/app.html?token=${TOKEN}"
  case "${OSTYPE:-}" in
    linux-gnu*) xdg-open "$url" ;;
    darwin*)    open "$url" ;;
    cygwin*|msys*|win32*) start "$url" ;;
    *) echo "Open ${url} in your browser." ;;
  esac
}

echo "Launching Frontend ..."
open_browser

echo "Logs: tail -f ${TCP_LOG} ${BUN_LOG}"
# Wait for background jobs; Ctrl-C will trigger cleanup()
wait