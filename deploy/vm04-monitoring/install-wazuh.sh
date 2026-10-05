#!/usr/bin/env bash
set -euo pipefail

# Wazuh is intentionally installed AFTER the main VM01 -> VM02 -> VM03 pipeline is stable.
# This script uses the official wazuh-docker repository rather than duplicating its
# certificate-sensitive stack inside this lab repository.

WAZUH_REF="${WAZUH_REF:-master}"
BASE_DIR="${HOME}/wazuh-docker"

sudo sysctl -w vm.max_map_count=262144
if ! grep -q '^vm.max_map_count=262144$' /etc/sysctl.conf; then
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf >/dev/null
fi

if ! command -v git >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y git
fi

if [ ! -d "${BASE_DIR}/.git" ]; then
  git clone https://github.com/wazuh/wazuh-docker.git "${BASE_DIR}"
fi

git -C "${BASE_DIR}" fetch --all --tags
if [ "${WAZUH_REF}" != "master" ]; then
  git -C "${BASE_DIR}" checkout "${WAZUH_REF}"
fi

cd "${BASE_DIR}/single-node"
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d

echo "Wazuh stack started from ${BASE_DIR}/single-node"
