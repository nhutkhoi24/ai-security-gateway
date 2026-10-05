#!/usr/bin/env bash
set -euo pipefail
GATEWAY_URL="${GATEWAY_URL:-http://10.10.10.1:8080}"

echo "[1/3] Health"
curl -fsS "${GATEWAY_URL}/health"; echo

echo "[2/3] DLP inspect"
curl -fsS -X POST "${GATEWAY_URL}/api/inspect" \
  -H 'Content-Type: application/json' \
  -d '{"text":"Email test@example.com, phone 0912345678"}'; echo

echo "[3/3] Chat pipeline (AI disabled by default)"
curl -fsS -X POST "${GATEWAY_URL}/api/chat" \
  -H 'Content-Type: application/json' \
  -d '{"text":"Send test@example.com to the AI"}'; echo
