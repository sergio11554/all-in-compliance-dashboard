const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/audit-package-gate.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "audit-package-gate.js" });
const gate = sandbox.SFMAuditPackageGate.createAuditPackageGate();

const blocked = gate.evaluate({
  documents: [{ title: "Restore-Test", auditRelevant: true, approved: false }],
  risks: [{ title: "R-001", critical: true, treatment: false, approved: false }],
  soa: [{ title: "A.5.1", auditRelevant: true, approved: false }],
  policies: [{ title: "Security Policy", auditRelevant: true, approved: false }],
  drafts: [{ title: "Scope", open: true, approved: false }],
  reviewItems: [{ type: "Asset", title: "Kernsystem", auditBlocker: true, approved: false }],
  bundle: { ready: 3, total: 4 }
});
assert.equal(blocked.formalGateClear, false);
assert.equal(blocked.consultantApproved, false);
assert.equal(blocked.blockers.length, 6);
assert.equal(blocked.criteria[0].open, 6);
assert.equal(blocked.autoPreparedPercent, 75);

const clear = gate.evaluate({
  documents: [{ auditRelevant: true, approved: true }],
  risks: [{ critical: true, treatment: true, approved: true }],
  soa: [{ auditRelevant: true, approved: true }],
  policies: [{ auditRelevant: true, approved: true }],
  drafts: [{ open: false, approved: false }],
  reviewItems: [{ auditBlocker: true, approved: true }],
  bundle: { ready: 5, total: 5 }
});
assert.equal(clear.formalGateClear, true);
assert.equal(clear.blockers.length, 0);
assert.equal(clear.autoPreparedPercent, 100);
assert.ok(clear.criteria.every((criterion) => criterion.open === 0));

const duplicate = gate.evaluate({
  reviewItems: [
    { type: "Nachweis", title: "Doppelt", auditBlocker: true, approved: false },
    { type: "Nachweis", title: "Doppelt", auditBlocker: true, approved: false }
  ]
});
assert.equal(duplicate.blockers.length, 1);

console.log("Audit package gate unit tests passed.");
