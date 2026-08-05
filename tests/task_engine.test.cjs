const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/task-engine.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "task-engine.js" });
const engine = sandbox.SFMTaskEngine.createTaskEngine({ today: () => "2026-07-03" });

const tasks = [
  { id: "normal", title: "Normale Aufgabe", status: "Offen", due: "2026-07-10" },
  { id: "done", title: "Erledigt", status: "Erledigt", due: "2026-06-01" },
  { id: "overdue", title: "Überfällig", status: "Offen", due: "2026-07-02" },
  { id: "blocked", title: "Blockiert", status: "Blockiert", due: "2026-07-20" },
  { id: "rework", title: "Nacharbeit", status: "Offen", source: "Berater-Rückgabe" }
];

assert.equal(engine.isDone(tasks[1]), true);
assert.equal(engine.isOverdue(tasks[1]), false);
assert.equal(engine.isOverdue(tasks[2]), true);
assert.equal(engine.isRework(tasks[4]), true);
assert.deepEqual(Array.from(engine.sort(tasks), (task) => task.id), ["rework", "blocked", "overdue", "normal", "done"]);
assert.deepEqual(
  JSON.parse(JSON.stringify(engine.metrics(tasks))),
  { total: 5, done: 1, open: 4, blocked: 1, overdue: 1, rework: 1 }
);

console.log("Task engine unit tests passed.");
