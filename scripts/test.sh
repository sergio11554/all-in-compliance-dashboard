#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "[1/6] Backend integration tests"
python3 -m unittest discover -s tests -p 'test_*.py' -v

echo "[2/6] Frontend module unit tests"
node tests/core_utils.test.cjs
node tests/api_client.test.cjs
node tests/state_store.test.cjs
node tests/router.test.cjs
node tests/workspace_validator.test.cjs
node tests/access_control.test.cjs
node tests/language_service.test.cjs
node tests/review_workflow.test.cjs
node tests/risk_engine.test.cjs
node tests/audit_package_gate.test.cjs
node tests/versioning.test.cjs
node tests/task_engine.test.cjs
node tests/soa_engine.test.cjs
node tests/project_plan_engine.test.cjs
node tests/document_engine.test.cjs
node tests/workspace_merge.test.cjs

echo "[3/6] Browser end-to-end tests"
if [[ "${SFM_SKIP_E2E:-0}" == "1" ]]; then
  echo "Browser E2E checks explicitly skipped via SFM_SKIP_E2E=1."
else
  NODE_MODULES="${SFM_NODE_MODULES:-}"
  if [[ -z "${NODE_MODULES}" ]] && node -e "require('playwright')" >/dev/null 2>&1; then
    NODE_MODULES="$(npm root)"
  fi
  if [[ -z "${NODE_MODULES}" ]]; then
    NODE_MODULES="$(find "${HOME}/.cache/codex-runtimes" -type d -path '*/dependencies/node/node_modules' 2>/dev/null | sort -r | head -n 1 || true)"
  fi
  if [[ -z "${NODE_MODULES}" ]] || ! NODE_PATH="${NODE_MODULES}" node -e "require('playwright')" >/dev/null 2>&1; then
    echo "Playwright runtime not found. Set SFM_NODE_MODULES or use SFM_SKIP_E2E=1 explicitly." >&2
    exit 1
  fi
  NODE_PATH="${NODE_MODULES}" node tests/frontend_e2e.cjs
fi

echo "[4/6] Frontend JavaScript syntax"
node --check frontend-current/core-utils.js
node --check frontend-current/api-client.js
node --check frontend-current/state-store.js
node --check frontend-current/router.js
node --check frontend-current/workspace-validator.js
node --check frontend-current/access-control.js
node --check frontend-current/language-service.js
node --check frontend-current/review-workflow.js
node --check frontend-current/risk-engine.js
node --check frontend-current/audit-package-gate.js
node --check frontend-current/versioning.js
node --check frontend-current/task-engine.js
node --check frontend-current/soa-engine.js
node --check frontend-current/project-plan-engine.js
node --check frontend-current/document-engine.js
node --check frontend-current/workspace-merge.js
node --check frontend-current/app.js

echo "[5/6] CSS structure"
node <<'NODE'
const fs = require('fs');
const css = fs.readFileSync('frontend-current/styles.css', 'utf8');
let depth = 0;
let quote = '';
let comment = false;
for (let i = 0; i < css.length; i += 1) {
  const current = css[i];
  const next = css[i + 1];
  if (comment) {
    if (current === '*' && next === '/') {
      comment = false;
      i += 1;
    }
    continue;
  }
  if (!quote && current === '/' && next === '*') {
    comment = true;
    i += 1;
    continue;
  }
  if (quote) {
    if (current === '\\') {
      i += 1;
      continue;
    }
    if (current === quote) quote = '';
    continue;
  }
  if (current === '"' || current === "'") {
    quote = current;
    continue;
  }
  if (current === '{') depth += 1;
  if (current === '}') depth -= 1;
  if (depth < 0) throw new Error('styles.css has an extra closing brace');
}
if (depth !== 0) throw new Error(`styles.css brace balance: ${depth}`);
console.log('CSS structure OK');
NODE

echo "[6/6] Backend compilation"
python3 -m py_compile backend_app.py database.py storage.py oidc_auth.py malware_scan.py scripts/migrate_file_storage.py scripts/storage_smoke.py scripts/restore_system_backup.py scripts/restore_drill_verify.py scripts/production_preflight.py

echo "All checks passed."
