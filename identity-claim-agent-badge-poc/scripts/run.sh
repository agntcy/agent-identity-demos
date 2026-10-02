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
export POC_VERIFIER_KEY_DIR="${POC_DIR}/.work/verifier-keys"

mkdir -p "${POC_VERIFIER_KEY_DIR}"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${POC_VERIFIER_KEY_DIR}/private.pem" >/dev/null 2>&1
openssl pkey -in "${POC_VERIFIER_KEY_DIR}/private.pem" -pubout -out "${POC_VERIFIER_KEY_DIR}/public.pem" >/dev/null 2>&1
chmod 600 "${POC_VERIFIER_KEY_DIR}/private.pem"
chmod 644 "${POC_VERIFIER_KEY_DIR}/public.pem"

"${SCRIPT_DIR}/build-directory.sh"

docker compose -f "${POC_DIR}/docker-compose.yml" down -v --remove-orphans
docker compose -f "${POC_DIR}/docker-compose.yml" up -d --wait

POC_VAULT_TOKEN="${POC_VAULT_TOKEN}" \
  POC_VERIFIER="http://127.0.0.1:4040" \
  POC_VERIFIER_PUBLIC_KEY="${POC_VERIFIER_KEY_DIR}/public.pem" \
  python3 "${SCRIPT_DIR}/validate.py" | tee "${POC_DIR}/validation-report.json"

echo
echo "Validation complete. Runtime report: ${POC_DIR}/validation-report.json"
echo "Stop services with: docker compose -f ${POC_DIR}/docker-compose.yml down -v"
