#!/usr/bin/env bash
set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_FRONTEND_DIR="${BACKEND_DIR}/frontend-current"
FRONTEND_DIR="${1:-${SFM_FRONTEND_DIR:-$DEFAULT_FRONTEND_DIR}}"
RELEASE_ROOT="${SFM_RELEASE_ROOT:-${BACKEND_DIR}/release}"
STAMP="$(date +%Y%m%d-%H%M%S)"
TARGET="${RELEASE_ROOT}/sfm-compliance-${STAMP}"

if [ ! -f "${FRONTEND_DIR}/index.html" ] || [ ! -f "${FRONTEND_DIR}/core-utils.js" ] || [ ! -f "${FRONTEND_DIR}/api-client.js" ] || [ ! -f "${FRONTEND_DIR}/state-store.js" ] || [ ! -f "${FRONTEND_DIR}/router.js" ] || [ ! -f "${FRONTEND_DIR}/workspace-validator.js" ] || [ ! -f "${FRONTEND_DIR}/access-control.js" ] || [ ! -f "${FRONTEND_DIR}/language-service.js" ] || [ ! -f "${FRONTEND_DIR}/review-workflow.js" ] || [ ! -f "${FRONTEND_DIR}/risk-engine.js" ] || [ ! -f "${FRONTEND_DIR}/audit-package-gate.js" ] || [ ! -f "${FRONTEND_DIR}/versioning.js" ] || [ ! -f "${FRONTEND_DIR}/task-engine.js" ] || [ ! -f "${FRONTEND_DIR}/soa-engine.js" ] || [ ! -f "${FRONTEND_DIR}/project-plan-engine.js" ] || [ ! -f "${FRONTEND_DIR}/document-engine.js" ] || [ ! -f "${FRONTEND_DIR}/workspace-merge.js" ] || [ ! -f "${FRONTEND_DIR}/app.js" ] || [ ! -f "${FRONTEND_DIR}/styles.css" ]; then
  echo "Frontend directory is incomplete: ${FRONTEND_DIR}" >&2
  exit 1
fi

python3 - "$FRONTEND_DIR" <<'PY'
import sys
from html.parser import HTMLParser
from pathlib import Path

frontend = Path(sys.argv[1])
checks = {
    "index.html": [
        'id="mainNav"',
        'id="appView"',
        'id="toast"',
        'id="guideToggleBtn"',
        "</html>",
    ],
    "core-utils.js": [
        "global.SFMCore",
        "function escapeHtml",
        "function normalizeImportKey",
    ],
    "api-client.js": [
        "global.SFMApiClient",
        "class ApiError",
        "function createApiClient",
    ],
    "state-store.js": [
        "global.SFMStateStore",
        "function createStateStore",
        "function stringify",
    ],
    "router.js": [
        "global.SFMRouter",
        "function createHashRouter",
        "function invitationTokenFromHash",
    ],
    "workspace-validator.js": [
        "global.SFMWorkspaceValidator",
        "function createWorkspaceValidator",
        "function warningText",
    ],
    "access-control.js": [
        "global.SFMAccessControl",
        "function createAccessControl",
        "function canAccessView",
    ],
    "language-service.js": [
        "global.SFMLanguageService",
        "function createLanguageService",
        "function translate",
    ],
    "review-workflow.js": [
        "global.SFMReviewWorkflow",
        "function createReviewWorkflow",
        "function canonical",
    ],
    "risk-engine.js": [
        "global.SFMRiskEngine",
        "function createRiskEngine",
        "function score",
    ],
    "audit-package-gate.js": [
        "global.SFMAuditPackageGate",
        "function createAuditPackageGate",
        "formalGateClear",
    ],
    "versioning.js": [
        "global.SFMVersioning",
        "function fingerprint",
        "function nextDocumentVersion",
    ],
    "task-engine.js": [
        "global.SFMTaskEngine",
        "function createTaskEngine",
        "function isOverdue",
    ],
    "soa-engine.js": [
        "global.SFMSoaEngine",
        "function createSoaEngine",
        "function normalizeRegister",
    ],
    "project-plan-engine.js": [
        "global.SFMProjectPlanEngine",
        "function createProjectPlanEngine",
        "function ownerSummary",
    ],
    "document-engine.js": [
        "global.SFMDocumentEngine",
        "function createDocumentEngine",
        "function isReviewOverdue",
    ],
    "workspace-merge.js": [
        "global.SFMWorkspaceMerge",
        "function compare",
        "function merge",
    ],
    "app.js": [
        "function render()",
        "function renderDashboard()",
        "const appView = document.getElementById(\"appView\")",
    ],
    "styles.css": [
        ".view",
        ".command-center",
        ".dashboard-program-grid",
    ],
}

required_scripts = {
    "core-utils.js",
    "api-client.js",
    "state-store.js",
    "router.js",
    "workspace-validator.js",
    "access-control.js",
    "language-service.js",
    "review-workflow.js",
    "risk-engine.js",
    "audit-package-gate.js",
    "versioning.js",
    "task-engine.js",
    "soa-engine.js",
    "project-plan-engine.js",
    "document-engine.js",
    "workspace-merge.js",
    "app.js",
}


class ScriptSourceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = set()

    def handle_starttag(self, tag, attrs):
        if tag.casefold() != "script":
            return
        source = dict(attrs).get("src", "")
        normalized = source.split("?", 1)[0].split("#", 1)[0]
        if normalized:
            self.sources.add(Path(normalized).name)

minimum_sizes = {
    "index.html": 1000,
    "core-utils.js": 1000,
    "api-client.js": 1000,
    "state-store.js": 1000,
    "router.js": 1000,
    "workspace-validator.js": 2000,
    "access-control.js": 2000,
    "language-service.js": 1500,
    "review-workflow.js": 2000,
    "risk-engine.js": 2500,
    "audit-package-gate.js": 3000,
    "versioning.js": 1200,
    "task-engine.js": 2000,
    "soa-engine.js": 2500,
    "project-plan-engine.js": 3000,
    "document-engine.js": 2500,
    "workspace-merge.js": 1500,
    "app.js": 10000,
    "styles.css": 10000,
}

for name, markers in checks.items():
    path = frontend / name
    data = path.read_bytes()
    if b"\x00" in data:
        raise SystemExit(f"Frontend validation failed: {name} contains null bytes")
    if len(data) < minimum_sizes[name]:
        raise SystemExit(f"Frontend validation failed: {name} is unexpectedly small")
    text = data.decode("utf-8")
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"Frontend validation failed: {name} missing {', '.join(missing)}")

index_parser = ScriptSourceParser()
index_parser.feed((frontend / "index.html").read_text(encoding="utf-8"))
missing_scripts = sorted(required_scripts - index_parser.sources)
if missing_scripts:
    raise SystemExit(
        "Frontend validation failed: index.html missing script sources "
        + ", ".join(missing_scripts)
    )

css = (frontend / "styles.css").read_text(encoding="utf-8")
balance = 0
for char in css:
    if char == "{":
        balance += 1
    elif char == "}":
        balance -= 1
    if balance < 0:
        raise SystemExit("Frontend validation failed: styles.css has an extra closing brace")
if balance != 0:
    raise SystemExit(f"Frontend validation failed: styles.css has unbalanced braces ({balance})")

print("Frontend validation: ok")
PY

if command -v node >/dev/null 2>&1; then
  node --check "${FRONTEND_DIR}/core-utils.js" >/dev/null
  node --check "${FRONTEND_DIR}/api-client.js" >/dev/null
  node --check "${FRONTEND_DIR}/state-store.js" >/dev/null
  node --check "${FRONTEND_DIR}/router.js" >/dev/null
  node --check "${FRONTEND_DIR}/workspace-validator.js" >/dev/null
  node --check "${FRONTEND_DIR}/access-control.js" >/dev/null
  node --check "${FRONTEND_DIR}/language-service.js" >/dev/null
  node --check "${FRONTEND_DIR}/review-workflow.js" >/dev/null
  node --check "${FRONTEND_DIR}/risk-engine.js" >/dev/null
  node --check "${FRONTEND_DIR}/audit-package-gate.js" >/dev/null
  node --check "${FRONTEND_DIR}/versioning.js" >/dev/null
  node --check "${FRONTEND_DIR}/task-engine.js" >/dev/null
  node --check "${FRONTEND_DIR}/soa-engine.js" >/dev/null
  node --check "${FRONTEND_DIR}/project-plan-engine.js" >/dev/null
  node --check "${FRONTEND_DIR}/document-engine.js" >/dev/null
  node --check "${FRONTEND_DIR}/workspace-merge.js" >/dev/null
  node --check "${FRONTEND_DIR}/app.js" >/dev/null
fi

mkdir -p "${TARGET}/frontend-current" "${TARGET}/deployment" "${TARGET}/scripts"

cp "${BACKEND_DIR}/backend_app.py" "${TARGET}/backend_app.py"
cp "${BACKEND_DIR}/database.py" "${TARGET}/database.py"
cp "${BACKEND_DIR}/storage.py" "${TARGET}/storage.py"
cp "${BACKEND_DIR}/oidc_auth.py" "${TARGET}/oidc_auth.py"
cp "${BACKEND_DIR}/malware_scan.py" "${TARGET}/malware_scan.py"
cp "${BACKEND_DIR}/requirements.txt" "${TARGET}/requirements.txt"
cp "${BACKEND_DIR}/Dockerfile" "${TARGET}/Dockerfile"
cp "${BACKEND_DIR}/docker-compose.yml" "${TARGET}/docker-compose.yml"
cp "${BACKEND_DIR}/docker-entrypoint.sh" "${TARGET}/docker-entrypoint.sh"
cp "${BACKEND_DIR}/.env.example" "${TARGET}/.env.example"
cp "${BACKEND_DIR}/OPERATIONS.md" "${TARGET}/OPERATIONS.md"
cp -R "${BACKEND_DIR}/deployment/." "${TARGET}/deployment/"
cp -R "${BACKEND_DIR}/scripts/." "${TARGET}/scripts/"

cp "${FRONTEND_DIR}/index.html" "${TARGET}/frontend-current/index.html"
cp "${FRONTEND_DIR}/core-utils.js" "${TARGET}/frontend-current/core-utils.js"
cp "${FRONTEND_DIR}/api-client.js" "${TARGET}/frontend-current/api-client.js"
cp "${FRONTEND_DIR}/state-store.js" "${TARGET}/frontend-current/state-store.js"
cp "${FRONTEND_DIR}/router.js" "${TARGET}/frontend-current/router.js"
cp "${FRONTEND_DIR}/workspace-validator.js" "${TARGET}/frontend-current/workspace-validator.js"
cp "${FRONTEND_DIR}/access-control.js" "${TARGET}/frontend-current/access-control.js"
cp "${FRONTEND_DIR}/language-service.js" "${TARGET}/frontend-current/language-service.js"
cp "${FRONTEND_DIR}/review-workflow.js" "${TARGET}/frontend-current/review-workflow.js"
cp "${FRONTEND_DIR}/risk-engine.js" "${TARGET}/frontend-current/risk-engine.js"
cp "${FRONTEND_DIR}/audit-package-gate.js" "${TARGET}/frontend-current/audit-package-gate.js"
cp "${FRONTEND_DIR}/versioning.js" "${TARGET}/frontend-current/versioning.js"
cp "${FRONTEND_DIR}/task-engine.js" "${TARGET}/frontend-current/task-engine.js"
cp "${FRONTEND_DIR}/soa-engine.js" "${TARGET}/frontend-current/soa-engine.js"
cp "${FRONTEND_DIR}/project-plan-engine.js" "${TARGET}/frontend-current/project-plan-engine.js"
cp "${FRONTEND_DIR}/document-engine.js" "${TARGET}/frontend-current/document-engine.js"
cp "${FRONTEND_DIR}/workspace-merge.js" "${TARGET}/frontend-current/workspace-merge.js"
cp "${FRONTEND_DIR}/app.js" "${TARGET}/frontend-current/app.js"
cp "${FRONTEND_DIR}/styles.css" "${TARGET}/frontend-current/styles.css"
if [ -d "${FRONTEND_DIR}/docs" ]; then
  mkdir -p "${TARGET}/frontend-current/docs"
  docs_copied=0
  for attempt in 1 2 3; do
    if cp -R "${FRONTEND_DIR}/docs/." "${TARGET}/frontend-current/docs/"; then
      docs_copied=1
      break
    fi
    echo "Documentation copy attempt ${attempt} failed; retrying ..." >&2
    sleep 1
  done
  if [ "${docs_copied}" -ne 1 ]; then
    echo "Release failed: documentation could not be copied after 3 attempts" >&2
    exit 1
  fi
fi

chmod 0755 "${TARGET}/docker-entrypoint.sh" "${TARGET}/scripts/"*.sh

(
  cd "${RELEASE_ROOT}"
  tar -czf "sfm-compliance-${STAMP}.tar.gz" "sfm-compliance-${STAMP}"
)

echo "Release directory: ${TARGET}"
echo "Release archive: ${RELEASE_ROOT}/sfm-compliance-${STAMP}.tar.gz"
