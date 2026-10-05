#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../deploy/vm03-dlp-data"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Edit $(pwd)/.env and change POSTGRES_PASSWORD, then run this script again."
  exit 1
fi
docker compose up -d --build
docker compose ps
