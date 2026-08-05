#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${SFM_STAGING_PROJECT:-sfm-staging}"
ENV_FILE="${SFM_STAGING_ENV:-${ROOT}/data/staging.env}"
BASE_URL="${SFM_STAGING_BASE_URL:-http://127.0.0.1:5190}"

compose() {
  docker compose \
    --env-file "${ENV_FILE}" \
    -p "${PROJECT}" \
    --profile malware \
    --profile s3 \
    "$@"
}

ensure_docker() {
  docker info >/dev/null 2>&1 || {
    echo "Docker ist nicht erreichbar. Bitte Docker Desktop starten." >&2
    exit 1
  }
}

ensure_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    return
  fi

  mkdir -p "$(dirname "${ENV_FILE}")"
  umask 077
  local database_password admin_password file_key storage_password
  database_password="$(openssl rand -hex 32)"
  admin_password="$(openssl rand -hex 32)"
  file_key="$(openssl rand -hex 32)"
  storage_password="$(openssl rand -hex 32)"

  {
    printf 'SFM_HTTP_PORT=5190\n'
    printf 'SFM_MINIO_PORT=9190\n'
    printf 'SFM_MINIO_CONSOLE_PORT=9191\n'
    printf 'SFM_FRONTEND_DIR=%s/frontend-current\n' "${ROOT}"
    printf 'SFM_CLAMAV_PLATFORM=linux/amd64\n'
    printf 'POSTGRES_DB=sfm_staging\n'
    printf 'POSTGRES_USER=sfm_staging\n'
    printf 'POSTGRES_PASSWORD=%s\n' "${database_password}"
    printf 'DATABASE_URL=postgresql://sfm_staging:%s@postgres:5432/sfm_staging\n' "${database_password}"
    printf 'ISMS_PUBLIC_URL=%s\n' "${BASE_URL}"
    printf 'ISMS_COOKIE_SECURE=0\n'
    printf 'ISMS_HSTS=0\n'
    printf 'ISMS_ADMIN_PASSWORD=%s\n' "${admin_password}"
    printf 'ISMS_FILE_KEY=%s\n' "${file_key}"
    printf 'MINIO_ROOT_USER=sfm_staging_storage\n'
    printf 'MINIO_ROOT_PASSWORD=%s\n' "${storage_password}"
    printf 'ISMS_STORAGE_BACKEND=s3\n'
    printf 'ISMS_S3_ENDPOINT=http://minio:9000\n'
    printf 'ISMS_S3_BUCKET=sfm-staging-evidence\n'
    printf 'ISMS_S3_PREFIX=uploads\n'
    printf 'ISMS_S3_REGION=eu-central-1\n'
    printf 'ISMS_S3_ACCESS_KEY=sfm_staging_storage\n'
    printf 'ISMS_S3_SECRET_KEY=%s\n' "${storage_password}"
    printf 'ISMS_S3_ADDRESSING_STYLE=path\n'
    printf 'ISMS_S3_AUTO_CREATE_BUCKET=1\n'
    printf 'ISMS_MALWARE_SCAN_MODE=clamav\n'
    printf 'ISMS_MALWARE_SCAN_REQUIRED=1\n'
    printf 'ISMS_CLAMAV_HOST=clamav\n'
    printf 'ISMS_CLAMAV_PORT=3310\n'
    printf 'ISMS_CLAMAV_TIMEOUT_SECONDS=30\n'
    printf 'ISMS_OPERATIONS_MONITOR_ENABLED=1\n'
    printf 'ISMS_JOB_WORKER_ENABLED=1\n'
    printf 'ISMS_NOTIFICATION_DELIVERY_ENABLED=0\n'
  } >"${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  echo "Geschuetzte Staging-Konfiguration angelegt: ${ENV_FILE}"
}

wait_for_health() {
  local attempt
  for attempt in $(seq 1 90); do
    if curl -fsS "${BASE_URL}/api/health" >/dev/null 2>&1; then
      echo "Staging ist erreichbar: ${BASE_URL}"
      return
    fi
    sleep 2
  done
  echo "Staging wurde nicht rechtzeitig gesund." >&2
  compose ps >&2
  exit 1
}

wait_for_dependencies() {
  load_env
  local attempt clamav_id clamav_health
  for attempt in $(seq 1 120); do
    clamav_id="$(docker ps -q \
      --filter "label=com.docker.compose.project=${PROJECT}" \
      --filter "label=com.docker.compose.service=clamav" | head -1)"
    clamav_health=""
    if [[ -n "${clamav_id}" ]]; then
      clamav_health="$(docker inspect "${clamav_id}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')"
    fi
    if [[ "${clamav_health}" == "healthy" ]] \
      && curl -fsS "http://127.0.0.1:${SFM_MINIO_PORT}/minio/health/live" >/dev/null 2>&1; then
      echo "PostgreSQL, MinIO und ClamAV sind bereit."
      return
    fi
    sleep 2
  done
  echo "Staging-Abhaengigkeiten wurden nicht rechtzeitig bereit." >&2
  compose ps >&2
  exit 1
}

load_env() {
  set -a
  # The generated file contains only shell-safe key/value pairs.
  source "${ENV_FILE}"
  set +a
}

smoke() {
  load_env
  SFM_SMOKE_BASE_URL="${BASE_URL}" python3 "${ROOT}/scripts/storage_smoke.py"
  SFM_SMOKE_BASE_URL="${BASE_URL}" python3 "${ROOT}/scripts/postgres_smoke.py"
}

command="${1:-status}"
ensure_docker
ensure_env
cd "${ROOT}"

case "${command}" in
  up)
    compose up -d --build
    wait_for_health
    wait_for_dependencies
    compose ps
    ;;
  status)
    compose ps
    curl -fsS "${BASE_URL}/api/health" || true
    printf '\n'
    ;;
  smoke)
    wait_for_health
    wait_for_dependencies
    smoke
    ;;
  down)
    compose down --remove-orphans
    ;;
  reset)
    compose down -v --remove-orphans
    rm -f "${ENV_FILE}"
    echo "Nur der isolierte Staging-Stack und seine Staging-Secrets wurden entfernt."
    ;;
  *)
    echo "Verwendung: $0 {up|status|smoke|down|reset}" >&2
    exit 2
    ;;
esac
