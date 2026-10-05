#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../deploy/vm02-gateway"
[ -f .env ] || cp .env.example .env
docker compose up -d --build
docker compose ps
