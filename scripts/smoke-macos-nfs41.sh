#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${MOUNT_DIR:-}" ]]; then
  MOUNT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/embednfs-smoke.XXXXXX")"
  CREATED_MOUNT_DIR=1
else
  CREATED_MOUNT_DIR=0
fi
MOUNT_DIR="$(cd "${MOUNT_DIR}" && pwd -P)"
LOG_FILE="${LOG_FILE:-/tmp/embednfs-smoke-server.log}"
SERVER_CMD="${SERVER_CMD:-cargo run -p embednfsd --release}"
MOUNT_OPTS="${MOUNT_OPTS:-vers=4.1,tcp,port=2049,nobrowse}"
SERVER_PID=""
MOUNT_ACTIVE=0

log() {
  printf '==> %s\n' "$*"
}

is_mounted() {
  mount | grep -Fq " on ${MOUNT_DIR} "
}

cleanup() {
  set +e
  if [[ "${MOUNT_ACTIVE}" == "1" ]]; then
    log "Unmounting ${MOUNT_DIR}"
    umount "${MOUNT_DIR}" >/dev/null 2>&1 || diskutil quiet unmount "${MOUNT_DIR}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SERVER_PID}" ]]; then
    log "Stopping server pid ${SERVER_PID}"
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${CREATED_MOUNT_DIR}" == "1" ]]; then
    log "Removing mount directory ${MOUNT_DIR}"
    rmdir "${MOUNT_DIR}" >/dev/null 2>&1 || true
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

if is_mounted; then
  echo "${MOUNT_DIR} is already mounted; choose a different MOUNT_DIR." >&2
  exit 1
fi

rm -f "${LOG_FILE}"

log "Starting server with: ${SERVER_CMD}"
log "Server log: ${LOG_FILE}"
(
  cd "${ROOT_DIR}"
  exec bash -lc "${SERVER_CMD}"
) >"${LOG_FILE}" 2>&1 &
SERVER_PID=$!

log "Waiting for 127.0.0.1:2049"
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

log "Mounting 127.0.0.1:/ at ${MOUNT_DIR}"
mount_nfs -o "${MOUNT_OPTS}" 127.0.0.1:/ "${MOUNT_DIR}"
MOUNT_ACTIVE=1

SMOKE_FILE="${MOUNT_DIR}/hello.txt"
SMOKE_DIR="${MOUNT_DIR}/subdir"
RENAMED_FILE="${SMOKE_DIR}/renamed.txt"

log "Writing ${SMOKE_FILE}"
printf 'hello\n' > "${SMOKE_FILE}"
test -f "${SMOKE_FILE}"
grep -q '^hello$' "${SMOKE_FILE}"

log "Creating ${SMOKE_DIR}"
mkdir "${SMOKE_DIR}"
log "Renaming ${SMOKE_FILE} -> ${RENAMED_FILE}"
mv "${SMOKE_FILE}" "${RENAMED_FILE}"
test -f "${RENAMED_FILE}"
grep -q '^hello$' "${RENAMED_FILE}"

log "Removing test files"
rm "${RENAMED_FILE}"
rmdir "${SMOKE_DIR}"

log "smoke ok: create/write/read/rename/remove/rmdir over mounted NFSv4.1"
