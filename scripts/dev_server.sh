#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${ROOT}/data"
PID_FILE="${DATA_DIR}/backend.pid"
LOG_FILE="${DATA_DIR}/backend.log"
ERR_FILE="${DATA_DIR}/backend-error.log"
URL="${SFM_DEV_URL:-http://127.0.0.1:5173}"
LAUNCH_LABEL="com.sfm-compliance.dev"
PLIST_FILE="${DATA_DIR}/${LAUNCH_LABEL}.plist"

mkdir -p "${DATA_DIR}"

is_running() {
  [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null
}

health() {
  curl -fsS "${URL}/api/health"
}

use_launchctl() {
  [[ "$(uname -s)" == "Darwin" ]] && command -v launchctl >/dev/null 2>&1
}

launch_domain() {
  echo "gui/$(id -u)"
}

write_launch_plist() {
  cat > "${PLIST_FILE}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCH_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-lc</string>
    <string>cd "${ROOT}" &amp;&amp; echo \$\$ &gt; "${PID_FILE}" &amp;&amp; exec ./run_backend.sh</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${ROOT}</string>
  <key>StandardOutPath</key>
  <string>${LOG_FILE}</string>
  <key>StandardErrorPath</key>
  <string>${ERR_FILE}</string>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF
}

start_detached() {
  rm -f "${PID_FILE}"
  if use_launchctl; then
    write_launch_plist
    launchctl bootout "$(launch_domain)" "${PLIST_FILE}" >/dev/null 2>&1 || true
    launchctl bootstrap "$(launch_domain)" "${PLIST_FILE}"
    return 0
  fi

  (
    cd "${ROOT}"
    nohup ./run_backend.sh > "${LOG_FILE}" 2> "${ERR_FILE}" < /dev/null &
    echo "$!" > "${PID_FILE}"
  )
}

start_server() {
  if is_running; then
    echo "SFM Compliance läuft bereits. PID $(cat "${PID_FILE}")"
    health || true
    echo
    return 0
  fi

  rm -f "${LOG_FILE}" "${ERR_FILE}"
  start_detached

  echo "Starte SFM Compliance Backend."
  for attempt in {1..20}; do
    if health >/dev/null 2>&1; then
      echo "Healthcheck OK: ${URL}/api/health"
      health
      echo
      echo "Webseite: ${URL}/"
      return 0
    fi
    if [[ "${attempt}" -gt 4 ]] && ! is_running; then
      echo "Backend ist beim Start beendet. Fehlerlog:" >&2
      tail -n 80 "${ERR_FILE}" >&2 || true
      return 1
    fi
    sleep 0.5
  done

  echo "Backend läuft, aber Healthcheck antwortet nicht rechtzeitig." >&2
  tail -n 80 "${ERR_FILE}" >&2 || true
  return 1
}

stop_server() {
  if ! is_running; then
    echo "SFM Compliance Backend läuft nicht."
    if use_launchctl; then
      launchctl bootout "$(launch_domain)" "${PLIST_FILE}" >/dev/null 2>&1 || true
    fi
    rm -f "${PID_FILE}"
    return 0
  fi

  local pid
  pid="$(cat "${PID_FILE}")"
  echo "Stoppe SFM Compliance Backend. PID ${pid}"
  if use_launchctl; then
    launchctl bootout "$(launch_domain)" "${PLIST_FILE}" >/dev/null 2>&1 || true
  fi
  kill "${pid}" 2>/dev/null || true
  for _ in {1..20}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      rm -f "${PID_FILE}"
      echo "Gestoppt."
      return 0
    fi
    sleep 0.25
  done
  echo "Prozess reagiert nicht, beende hart. PID ${pid}"
  kill -9 "${pid}" 2>/dev/null || true
  rm -f "${PID_FILE}"
}

status_server() {
  if is_running; then
    echo "SFM Compliance Backend läuft. PID $(cat "${PID_FILE}")"
    health || true
    echo
  else
    echo "SFM Compliance Backend läuft nicht."
    [[ -f "${PID_FILE}" ]] && echo "Veraltete PID-Datei: ${PID_FILE}"
  fi
  echo "Logs:"
  echo "- ${LOG_FILE}"
  echo "- ${ERR_FILE}"
}

case "${1:-status}" in
  start)
    start_server
    ;;
  stop)
    stop_server
    ;;
  restart)
    stop_server
    start_server
    ;;
  status)
    status_server
    ;;
  health)
    health
    echo
    ;;
  logs)
    tail -n "${2:-120}" "${LOG_FILE}" "${ERR_FILE}" 2>/dev/null || true
    ;;
  follow)
    tail -f "${LOG_FILE}" "${ERR_FILE}"
    ;;
  *)
    echo "Nutzung: $0 {start|stop|restart|status|health|logs|follow}" >&2
    exit 2
    ;;
esac
