#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SFM_BASE_URL:-http://127.0.0.1:5173}"
USERNAME="${SFM_ADMIN_USERNAME:-admin}"
PASSWORD="${SFM_ADMIN_PASSWORD:?Set SFM_ADMIN_PASSWORD for the admin user.}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "${COOKIE_JAR}"' EXIT

LOGIN_RESPONSE="$(curl -fsS -c "${COOKIE_JAR}" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}" \
  "${BASE_URL}/api/auth/login")"

CSRF_TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["csrfToken"])' <<<"${LOGIN_RESPONSE}")"

curl -fsS -b "${COOKIE_JAR}" -H "X-CSRF-Token: ${CSRF_TOKEN}" -X POST "${BASE_URL}/api/backups"
echo
