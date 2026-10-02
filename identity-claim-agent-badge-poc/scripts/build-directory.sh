#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PATCH_FILE="${POC_DIR}/patches/directory-pr2125-agntcy-identity.patch"
DIRECTORY_COMMIT="08c86a4b39c554a0f2eacb7391684fff6f0bd002"
PATCH_DIGEST="$(shasum -a 256 "${PATCH_FILE}" | awk '{print substr($1, 1, 12)}')"
SOURCE_DIR="${POC_DIR}/.work/dir-pr2125-${PATCH_DIGEST}"
STOCK_IMAGE="${STOCK_DIRECTORY_IMAGE:-agntcy-dir-identity-claim-stock:pr2125}"
PATCHED_IMAGE="${DIRECTORY_IMAGE:-agntcy-dir-identity-claim-badge-poc:pr2125}"
VERIFIER_IMAGE="${VERIFIER_IMAGE:-agntcy-external-identity-verifier-poc:pr2125}"

mkdir -p "${POC_DIR}/.work"

if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
  git init "${SOURCE_DIR}"
  git -C "${SOURCE_DIR}" remote add origin https://github.com/agntcy/dir.git
  git -C "${SOURCE_DIR}" fetch --depth 1 origin "${DIRECTORY_COMMIT}"
  git -C "${SOURCE_DIR}" checkout --detach FETCH_HEAD
fi

if [[ "$(git -C "${SOURCE_DIR}" rev-parse HEAD)" != "${DIRECTORY_COMMIT}" ]]; then
  echo "Cached source is not pinned to ${DIRECTORY_COMMIT}; remove ${SOURCE_DIR} and retry." >&2
  exit 1
fi

if git -C "${SOURCE_DIR}" apply --unidiff-zero --reverse --check "${PATCH_FILE}" >/dev/null 2>&1; then
  git -C "${SOURCE_DIR}" apply --unidiff-zero --reverse "${PATCH_FILE}"
fi

if ! git -C "${SOURCE_DIR}" diff --quiet || ! git -C "${SOURCE_DIR}" diff --cached --quiet; then
  echo "Cached Directory source has unrelated changes; remove ${SOURCE_DIR} and retry." >&2
  exit 1
fi

docker build --target production -t "${STOCK_IMAGE}" -f "${SOURCE_DIR}/server/Dockerfile" "${SOURCE_DIR}"

git -C "${SOURCE_DIR}" apply --unidiff-zero --check "${PATCH_FILE}"
git -C "${SOURCE_DIR}" apply --unidiff-zero "${PATCH_FILE}"
git -C "${SOURCE_DIR}" diff --check

docker build --target production -t "${PATCHED_IMAGE}" -f "${SOURCE_DIR}/server/Dockerfile" "${SOURCE_DIR}"
docker build -t "${VERIFIER_IMAGE}" -f "${POC_DIR}/verifier/Dockerfile" "${SOURCE_DIR}"

echo "Built stock Directory, patched Directory, and external AGNTCY verifier images from identity.v1 commit ${DIRECTORY_COMMIT}."
