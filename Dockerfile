FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV ISMS_HOST=0.0.0.0
ENV ISMS_PORT=5173
ENV ISMS_DATA_DIR=/data
ENV ISMS_STATIC_BASE=/app/frontend

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --system sfm && \
    adduser --system --ingroup sfm sfm && \
    mkdir -p /data /app/frontend && \
    chown -R sfm:sfm /data /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend_app.py /app/backend_app.py
COPY database.py /app/database.py
COPY intune_connector.py /app/intune_connector.py
COPY intune_sync.py /app/intune_sync.py
COPY storage.py /app/storage.py
COPY oidc_auth.py /app/oidc_auth.py
COPY malware_scan.py /app/malware_scan.py
COPY scripts/migrate_sqlite_to_postgres.py /app/scripts/migrate_sqlite_to_postgres.py
COPY scripts/migrate_file_storage.py /app/scripts/migrate_file_storage.py
COPY scripts/storage_smoke.py /app/scripts/storage_smoke.py
COPY scripts/restore_system_backup.py /app/scripts/restore_system_backup.py
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN chmod 0755 /app/docker-entrypoint.sh /app/scripts/migrate_sqlite_to_postgres.py /app/scripts/migrate_file_storage.py /app/scripts/storage_smoke.py /app/scripts/restore_system_backup.py

USER sfm

EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import json, os, urllib.request; port=os.environ.get('ISMS_PORT','5173'); data=json.load(urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=3)); raise SystemExit(0 if data.get('ok') else 1)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
