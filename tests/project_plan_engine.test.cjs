const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/project-plan-engine.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "project-plan-engine.js" });
const defaults = [
  ["iso-1", "ISO 27001", "1", "ISO Start", "Clause 4", "Scope", "ISB", "Quelle", "Dokumentation"],
  ["nis-1", "NIS-2", "1", "NIS Start", "§28", "Einordnung", "Legal", "Quelle", "Rechtsregister"],
  ["shared-1", "Gemeinsam", "1", "Gemeinsamer Nachweis", "Mapping", "Nachweis", "ISB", "Quelle", "Dokumentation"]
];
const engine = sandbox.SFMProjectPlanEngine.createProjectPlanEngine({
  defaults,
  streams: ["ISO 27001", "NIS-2", "Gemeinsam"],
  today: () => "2026-07-03"
});

const initial = engine.createDefault();
assert.equal(initial.length, 3);
assert.equal(initial[0].status, "In Arbeit");
assert.equal(initial[2].status, "Offen");

const normalized = engine.normalize([
  { id: "iso-1", status: "Erledigt", owner: "Alice" },
  { id: "nis-1", status: "Blockiert", due: "2026-07-01" },
  { id: "unknown", status: "Erledigt" }
]);
assert.equal(normalized.length, 3);
assert.equal(normalized[0].owner, "Alice");
assert.equal(normalized.some((item) => item.id === "unknown"), false);

const progress = engine.progress(normalized);
assert.equal(progress.percent, 33);
assert.equal(progress.byStream["ISO 27001"], "100%");
assert.equal(progress.byStream["NIS-2"], "0%");
assert.equal(progress.byStream.Gemeinsam, "0%");

const metrics = engine.statusMetrics(normalized);
assert.equal(metrics.done, 1);
assert.equal(metrics.blocked, 1);
assert.equal(metrics.overdue, 1);
assert.equal(engine.dueState(normalized[1]).tone, "blocked");
assert.equal(engine.ownerSummary(normalized)[0].owner, "Legal");

console.log("Project plan engine unit tests passed.");
