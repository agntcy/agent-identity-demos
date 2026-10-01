#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v docker >/dev/null
command -v grpcurl >/dev/null
command -v python3 >/dev/null
command -v openssl >/dev/null

export POC_DB_PASSWORD="${POC_DB_PASSWORD:-$(openssl rand -hex 24)}"
export POC_VAULT_TOKEN="${POC_VAULT_TOKEN:-$(openssl rand -hex 24)}"
export POC_SECRETS_CRYPTO_KEY="${POC_SECRETS_CRYPTO_KEY:-$(openssl rand -hex 32)}"

"${SCRIPT_DIR}/build-directory.sh"

docker compose -f "${POC_DIR}/docker-compose.yml" up -d --wait

POC_VAULT_TOKEN="${POC_VAULT_TOKEN}" \
  python3 "${SCRIPT_DIR}/validate.py" | tee "${POC_DIR}/validation-report.json"

echo
echo "Validation complete. Runtime report: ${POC_DIR}/validation-report.json"
echo "Stop services with: docker compose -f ${POC_DIR}/docker-compose.yml down -v"
