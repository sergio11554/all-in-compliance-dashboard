const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/document-engine.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "document-engine.js" });
const engine = sandbox.SFMDocumentEngine.createDocumentEngine({ today: () => "2026-07-03" });

const documents = [
  { id: "source", status: "Quelle", approval: "Nicht erforderlich" },
  { id: "approved", status: "Freigegeben", approval: "Freigegeben", owner: "ISB", version: "1.0", review: "2027-01-01", linkedTo: "A.5.1" },
  { id: "review", status: "In Prüfung", approval: "Prüfung läuft", owner: "ISB", version: "0.9", review: "2026-07-10", evidenceFor: "A.8.13" },
  { id: "overdue", status: "Entwurf", approval: "Nicht gestartet", owner: "", version: "0.1", review: "2026-07-02", linkedTo: "Clause 7.5" },
  { id: "archived", status: "Archiviert", approval: "Nicht gestartet", review: "2020-01-01" }
];

assert.equal(engine.isWorking(documents[0]), false);
assert.equal(engine.hasMissingMetadata(documents[3]), true);
assert.equal(engine.isReviewOverdue(documents[3]), true);
assert.equal(engine.isReviewOverdue(documents[4]), false);
assert.equal(engine.isApprovalOpen(documents[1]), false);
assert.equal(engine.isApprovalOpen(documents[3]), true);
assert.equal(engine.needsReviewQueue(documents[2]), true);
assert.equal(engine.reviewPriority({ status: "In Prüfung", approval: "Prüfung läuft", review: "2026-07-01" }), 50);
assert.deepEqual(
  JSON.parse(JSON.stringify(engine.metrics(documents))),
  { working: 4, approved: 1, inReview: 1, overdue: 1, missing: 2 }
);

console.log("Document engine unit tests passed.");
