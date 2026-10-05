#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../deploy/vm04-monitoring"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Edit $(pwd)/.env and change GRAFANA_ADMIN_PASSWORD, then run this script again."
  exit 1
fi
docker compose up -d
docker compose ps
