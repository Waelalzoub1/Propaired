#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/wael/Desktop/helper"
VENV_DIR="$ROOT_DIR/venv"
SERVER_DIR="$ROOT_DIR/Server"

HOST="${SERVER_HOST:-0.0.0.0}"
PORT="${SERVER_PORT:-80}"

if [ ! -d "$VENV_DIR" ]; then
  echo "Missing venv at $VENV_DIR"
  exit 1
fi

if [ ! -f "$VENV_DIR/bin/activate" ]; then
  echo "Missing venv activation script at $VENV_DIR/bin/activate"
  exit 1
fi

if [ "$PORT" -lt 1024 ] && [ "$EUID" -ne 0 ]; then
  echo "Port $PORT requires sudo. Run with sudo or set SERVER_PORT to 1024+"
  exit 1
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
cd "$SERVER_DIR"

CMD=(uvicorn main:app --host "$HOST" --port "$PORT")
if [ -n "${SSL_CERT_FILE:-}" ] && [ -n "${SSL_KEY_FILE:-}" ]; then
  CMD+=(--ssl-certfile "$SSL_CERT_FILE" --ssl-keyfile "$SSL_KEY_FILE")
fi

echo "Starting server on ${HOST}:${PORT}"
exec "${CMD[@]}"
