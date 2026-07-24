#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
BUILD_IMAGES="${BUILD_IMAGES:-0}"

if ! command -v docker >/dev/null 2>&1; then
  echo "warning: Docker was not found on PATH. Static scanning will work, but dynamic sandbox runs require Docker." >&2
fi

if [ ! -d ".venv" ]; then
  "$PYTHON" -m venv .venv
fi

".venv/bin/python" -m pip install --upgrade pip
".venv/bin/python" -m pip install -r requirements.txt

if [ "$BUILD_IMAGES" = "1" ]; then
  for dockerfile in docker/images/*/Dockerfile; do
    name="$(basename "$(dirname "$dockerfile")")"
    case "$name" in
      python) tag="aegisagent-python:3.12-bookworm" ;;
      node) tag="aegisagent-node:22-bookworm" ;;
      go) tag="aegisagent-go:1.24-bookworm" ;;
      rust) tag="aegisagent-rust:1-bookworm" ;;
      java) tag="aegisagent-java:21-bookworm" ;;
      universal) tag="aegisagent-universal:linux" ;;
      *) continue ;;
    esac
    docker build -t "$tag" -f "$dockerfile" .
  done
fi

cat <<'MSG'

AegisAgent setup complete.
Start the server with:
  .venv/bin/python -m agent_sandbox
Then open http://127.0.0.1:8000
MSG
