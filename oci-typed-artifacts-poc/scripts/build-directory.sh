#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${POC_DIR}/.work"
SOURCE_DIR="${WORK_DIR}/dir-v1.7.1"
PATCH_FILE="${POC_DIR}/patches/directory-v1.7.1-agent-badge.patch"
IMAGE_NAME="${DIRECTORY_IMAGE:-agntcy-dir-agent-badge-poc:v1.7.1}"

mkdir -p "${WORK_DIR}"

if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
  git clone --depth 1 --branch v1.7.1 https://github.com/agntcy/dir.git "${SOURCE_DIR}"
fi

if git -C "${SOURCE_DIR}" apply --reverse --check "${PATCH_FILE}" >/dev/null 2>&1; then
  echo "Directory patch is already applied."
elif git -C "${SOURCE_DIR}" diff --quiet && git -C "${SOURCE_DIR}" diff --cached --quiet; then
  git -C "${SOURCE_DIR}" apply --check "${PATCH_FILE}"
  git -C "${SOURCE_DIR}" apply "${PATCH_FILE}"
else
  echo "The cached Directory source has unrelated local changes. Remove ${SOURCE_DIR} and retry." >&2
  exit 1
fi

docker run --rm \
  -v "${SOURCE_DIR}:/workspace" \
  -w /workspace/proto \
  bufbuild/buf:1.66.1 generate

git -C "${SOURCE_DIR}" diff --check
docker build --target production -t "${IMAGE_NAME}" -f "${SOURCE_DIR}/server/Dockerfile" "${SOURCE_DIR}"

echo "Built ${IMAGE_NAME} from AGNTCY Directory v1.7.1 with the minimal Agent Badge referrer patch."
