#!/usr/bin/env sh
set -eu

mkdir -p "${ISMS_DATA_DIR:-/data}/uploads" "${ISMS_DATA_DIR:-/data}/backups"

if [ ! -f "${ISMS_STATIC_BASE:-/app/frontend}/index.html" ]; then
  echo "ERROR: Frontend not found at ${ISMS_STATIC_BASE:-/app/frontend}. Mount or copy index.html, app.js and styles.css." >&2
  exit 1
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec python /app/backend_app.py
