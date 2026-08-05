#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${ROOT}/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

export ISMS_STATIC_BASE="${ISMS_STATIC_BASE:-${ROOT}/frontend-current}"
exec python3 "${ROOT}/backend_app.py"
