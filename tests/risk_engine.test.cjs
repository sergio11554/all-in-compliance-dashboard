const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/risk-engine.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "risk-engine.js" });
const engine = sandbox.SFMRiskEngine.createRiskEngine();

assert.equal(engine.score(4, 5), 20);
assert.equal(engine.score("3", "4"), 12);
assert.equal(engine.score("", 4), 0);
assert.equal(engine.level(20), "Sehr hoch");
assert.equal(engine.level(12), "Hoch");
assert.equal(engine.level(7), "Mittel");
assert.equal(engine.level(2), "Niedrig");
assert.equal(engine.level(0), "-");

const methodology = engine.normalizeMethodology({ owner: "  ISB  ", criticalFrom: "30" });
assert.equal(methodology.owner, "ISB");
assert.equal(methodology.treatmentFrom, "10");
assert.deepEqual(
  JSON.parse(JSON.stringify(engine.thresholds(methodology))),
  { treatmentFrom: 10, managementFrom: 10, criticalFrom: 25 }
);
assert.deepEqual(
  JSON.parse(JSON.stringify(engine.thresholds({ treatmentFrom: "0", managementFrom: "abc", criticalFrom: "1" }))),
  { treatmentFrom: 10, managementFrom: 10, criticalFrom: 1 }
);

const scale = engine.splitScale("1 selten; 2 möglich; 5 häufig");
assert.deepEqual(JSON.parse(JSON.stringify(scale)), [
  { value: "1", label: "selten" },
  { value: "2", label: "möglich" },
  { value: "5", label: "häufig" }
]);
assert.equal(engine.splitScale("").length, 5);

console.log("Risk engine unit tests passed.");
