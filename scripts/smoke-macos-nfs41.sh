#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOUNT_DIR="${MOUNT_DIR:-/tmp/embednfs-smoke}"
LOG_FILE="${LOG_FILE:-/tmp/embednfs-smoke-server.log}"
SERVER_CMD="${SERVER_CMD:-cargo run -p embednfsd --release}"
SERVER_PID=""

cleanup() {
  set +e
  if mount | grep -q " on ${MOUNT_DIR} "; then
    umount "${MOUNT_DIR}" >/dev/null 2>&1 || diskutil unmount force "${MOUNT_DIR}" >/dev/null 2>&1
  fi
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This smoke test currently targets macOS only." >&2
  exit 1
fi

if ! command -v mount_nfs >/dev/null 2>&1; then
  echo "mount_nfs is required but was not found." >&2
  exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
  echo "nc is required but was not found." >&2
  exit 1
fi

mkdir -p "${MOUNT_DIR}"

if mount | grep -q " on ${MOUNT_DIR} "; then
  echo "${MOUNT_DIR} is already mounted; choose a different MOUNT_DIR." >&2
  exit 1
fi

rm -f "${LOG_FILE}"

(
  cd "${ROOT_DIR}"
  exec bash -lc "${SERVER_CMD}"
) >"${LOG_FILE}" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if nc -z 127.0.0.1 2049 >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

if ! nc -z 127.0.0.1 2049 >/dev/null 2>&1; then
  echo "Server did not start listening on 127.0.0.1:2049." >&2
  tail -n 50 "${LOG_FILE}" >&2 || true
  exit 1
fi

mount_nfs -o vers=4.1,tcp,port=2049 127.0.0.1:/ "${MOUNT_DIR}"

SMOKE_FILE="${MOUNT_DIR}/hello.txt"
SMOKE_DIR="${MOUNT_DIR}/subdir"
RENAMED_FILE="${SMOKE_DIR}/renamed.txt"

printf 'hello\n' > "${SMOKE_FILE}"
test -f "${SMOKE_FILE}"
grep -q '^hello$' "${SMOKE_FILE}"

mkdir "${SMOKE_DIR}"
mv "${SMOKE_FILE}" "${RENAMED_FILE}"
test -f "${RENAMED_FILE}"
grep -q '^hello$' "${RENAMED_FILE}"

rm "${RENAMED_FILE}"
rmdir "${SMOKE_DIR}"

echo "smoke ok: create/write/read/rename/remove/rmdir over mounted NFSv4.1"
