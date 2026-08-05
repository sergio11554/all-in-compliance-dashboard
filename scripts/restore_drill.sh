#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${SFM_STAGING_PROJECT:-sfm-staging}"
ENV_FILE="${SFM_STAGING_ENV:-${ROOT}/data/staging.env}"
SOURCE_URL="${SFM_STAGING_BASE_URL:-http://127.0.0.1:5190}"
RESTORE_PORT="${SFM_RESTORE_DRILL_PORT:-5290}"
RESTORE_URL="http://127.0.0.1:${RESTORE_PORT}"
SUFFIX="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)"
RESTORE_DB="sfm_restore_${SUFFIX//-/_}"
RESTORE_PREFIX="restore-drill-${SUFFIX}"
VERIFIER="sfm-restore-verifier-${SUFFIX}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Staging-Konfiguration fehlt. Zuerst ./scripts/staging_stack.sh up ausfuehren." >&2
  exit 1
fi

set -a
source "${ENV_FILE}"
set +a

APP_CONTAINER="$(docker ps -q \
  --filter "label=com.docker.compose.project=${PROJECT}" \
  --filter "label=com.docker.compose.service=sfm-compliance" | head -1)"
POSTGRES_CONTAINER="$(docker ps -q \
  --filter "label=com.docker.compose.project=${PROJECT}" \
  --filter "label=com.docker.compose.service=postgres" | head -1)"
NETWORK="${PROJECT}_default"
TARGET_DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${RESTORE_DB}"

if [[ -z "${APP_CONTAINER}" || -z "${POSTGRES_CONTAINER}" ]]; then
  echo "Der isolierte Staging-Stack laeuft nicht vollstaendig." >&2
  exit 1
fi

cleanup() {
  docker rm -f "${VERIFIER}" >/dev/null 2>&1 || true
  docker exec "${POSTGRES_CONTAINER}" dropdb --if-exists -U "${POSTGRES_USER}" "${RESTORE_DB}" >/dev/null 2>&1 || true
  docker exec -i -e ISMS_S3_PREFIX="${RESTORE_PREFIX}" "${APP_CONTAINER}" python - <<'PY' >/dev/null 2>&1 || true
from storage import storage_from_env
storage = storage_from_env('/tmp/unused')
for name in storage.list_names():
    storage.delete(name)
PY
}
trap cleanup EXIT

curl -fsS "${SOURCE_URL}/api/health" >/dev/null
SFM_BASE_URL="${SOURCE_URL}" SFM_ADMIN_PASSWORD="${ISMS_ADMIN_PASSWORD}" "${ROOT}/scripts/backup_now.sh" >/dev/null
BACKUP_NAME="$(docker exec "${APP_CONTAINER}" sh -c "find /data/backups -maxdepth 1 -type f -name '*.ismsbak' -printf '%f\\n' | sort | tail -1")"
if [[ -z "${BACKUP_NAME}" ]]; then
  echo "Kein System-Backup im Staging gefunden." >&2
  exit 1
fi

docker exec "${APP_CONTAINER}" python /app/scripts/restore_system_backup.py \
  "/data/backups/${BACKUP_NAME}" --verify-only >/dev/null
docker exec "${POSTGRES_CONTAINER}" createdb -U "${POSTGRES_USER}" -O "${POSTGRES_USER}" "${RESTORE_DB}"
docker exec \
  -e DATABASE_URL="${TARGET_DATABASE_URL}" \
  -e ISMS_S3_PREFIX="${RESTORE_PREFIX}" \
  "${APP_CONTAINER}" \
  python /app/scripts/restore_system_backup.py "/data/backups/${BACKUP_NAME}" \
    --database-url "${TARGET_DATABASE_URL}" \
    --replace-storage \
    --confirm RESTORE

docker run -d --name "${VERIFIER}" \
  --network "${NETWORK}" \
  --env-file "${ENV_FILE}" \
  -e ISMS_HOST=0.0.0.0 \
  -e ISMS_PORT=5173 \
  -e ISMS_PUBLIC_URL="${RESTORE_URL}" \
  -e DATABASE_URL="${TARGET_DATABASE_URL}" \
  -e ISMS_S3_PREFIX="${RESTORE_PREFIX}" \
  -e ISMS_S3_AUTO_CREATE_BUCKET=0 \
  -p "${RESTORE_PORT}:5173" \
  -v "${ROOT}/frontend-current:/app/frontend:ro" \
  "${PROJECT}-sfm-compliance" >/dev/null

for attempt in $(seq 1 60); do
  if curl -fsS "${RESTORE_URL}/api/health" >/dev/null 2>&1; then
    break
  fi
  if [[ "${attempt}" == "60" ]]; then
    docker logs "${VERIFIER}" >&2
    echo "Restore-Pruefinstanz wurde nicht bereit." >&2
    exit 1
  fi
  sleep 1
done

ISMS_ADMIN_PASSWORD="${ISMS_ADMIN_PASSWORD}" python3 "${ROOT}/scripts/restore_drill_verify.py" \
  --source-url "${SOURCE_URL}" \
  --restore-url "${RESTORE_URL}" \
  --backup-name "${BACKUP_NAME}"
echo "Restore-Drill erfolgreich; isolierte Pruefdaten werden jetzt entfernt."
