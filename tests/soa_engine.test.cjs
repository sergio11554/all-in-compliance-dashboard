const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/soa-engine.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "soa-engine.js" });
let id = 0;
const engine = sandbox.SFMSoaEngine.createSoaEngine({
  controls: [
    { id: "A.5.1", module: "Governance" },
    { id: "A.5.2", module: "Access" }
  ],
  applicabilityOptions: ["Zu prüfen", "Anwendbar", "Nicht anwendbar", "Teilweise anwendbar"],
  implementationOptions: ["Offen", "Geplant", "In Umsetzung", "Umgesetzt", "Nicht erforderlich"],
  defaultOwnerByModule: { Governance: "ISB", Access: "IAM" },
  idFactory: () => `id-${++id}`
});

const defaults = engine.normalizeRegister([]);
assert.equal(defaults.length, 2);
assert.equal(defaults[0].controlId, "A.5.1");
assert.equal(defaults[1].owner, "IAM");

const records = engine.normalizeRegister([
  { controlId: "A.5.1", applicability: "Anwendbar", implementation: "Umgesetzt", owner: "  Leitung  " },
  { controlId: "A.5.2", applicability: "Ungültig", implementation: "Falsch", evidence: "Ticket-1" }
]);
assert.equal(records[0].owner, "Leitung");
assert.equal(records[1].applicability, "Zu prüfen");
assert.equal(records[1].implementation, "Offen");

const missing = engine.metrics(records);
assert.deepEqual(JSON.parse(JSON.stringify(missing)), { total: 2, applicable: 1, implemented: 1, open: 1, missingEvidence: 1 });
const linked = engine.metrics(records, { hasLinkedEvidence: (record) => record.controlId === "A.5.1" });
assert.equal(linked.missingEvidence, 0);

console.log("SoA engine unit tests passed.");
