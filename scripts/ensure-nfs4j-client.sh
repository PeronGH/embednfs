#!/usr/bin/env bash
set -euo pipefail

NFS4J_REPO_URL="${NFS4J_REPO_URL:-https://github.com/PeronGH/nfs4j.git}"
NFS4J_REF="${NFS4J_REF:-9d433b98bf56ea6d5cf791388c9d75ad32d5d0f2}"
NFS4J_CACHE_DIR="${NFS4J_CACHE_DIR:-/tmp/nfs4j}"

log() {
  printf '==> %s\n' "$*" >&2
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command not found: $1"
  fi
}

require_cmd git
require_cmd mvn

if [[ -e "${NFS4J_CACHE_DIR}" && ! -d "${NFS4J_CACHE_DIR}/.git" ]]; then
  fail "${NFS4J_CACHE_DIR} exists but is not a git checkout; choose a different NFS4J_CACHE_DIR"
fi

if [[ ! -d "${NFS4J_CACHE_DIR}/.git" ]]; then
  log "Cloning ${NFS4J_REPO_URL} into ${NFS4J_CACHE_DIR}"
  git clone "${NFS4J_REPO_URL}" "${NFS4J_CACHE_DIR}" 1>&2
fi

origin_url="$(git -C "${NFS4J_CACHE_DIR}" remote get-url origin 2>/dev/null || true)"
if [[ -z "${origin_url}" ]]; then
  fail "${NFS4J_CACHE_DIR} has no origin remote"
fi
if [[ "${origin_url}" != "${NFS4J_REPO_URL}" ]]; then
  fail "${NFS4J_CACHE_DIR} points at ${origin_url}, expected ${NFS4J_REPO_URL}; override NFS4J_CACHE_DIR or clean the cache"
fi

if [[ -n "$(git -C "${NFS4J_CACHE_DIR}" status --porcelain)" ]]; then
  fail "${NFS4J_CACHE_DIR} has uncommitted changes; clean it or choose a different NFS4J_CACHE_DIR"
fi

current_ref="$(git -C "${NFS4J_CACHE_DIR}" rev-parse HEAD)"
if [[ "${current_ref}" != "${NFS4J_REF}" ]]; then
  if ! git -C "${NFS4J_CACHE_DIR}" cat-file -e "${NFS4J_REF}^{commit}" 2>/dev/null; then
    log "Fetching ${NFS4J_REPO_URL}"
    git -C "${NFS4J_CACHE_DIR}" fetch --tags origin 1>&2
  fi
  if ! git -C "${NFS4J_CACHE_DIR}" cat-file -e "${NFS4J_REF}^{commit}" 2>/dev/null; then
    fail "pinned ref ${NFS4J_REF} is not available in ${NFS4J_CACHE_DIR}"
  fi
  log "Checking out ${NFS4J_REF}"
  git -C "${NFS4J_CACHE_DIR}" checkout --detach "${NFS4J_REF}" 1>&2
fi

log "Building nfs4j basic-client"
(
  cd "${NFS4J_CACHE_DIR}"
  mvn -pl basic-client -am -DskipTests package 1>&2
)

jar_path="$(find "${NFS4J_CACHE_DIR}/basic-client/target" -maxdepth 1 -type f -name '*-jar-with-dependencies.jar' | sort | head -n 1)"
if [[ -z "${jar_path}" ]]; then
  fail "failed to locate nfs4j basic-client jar-with-dependencies"
fi

printf '%s\n' "${jar_path}"
