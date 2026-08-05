const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/core-utils.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "core-utils.js" });
const core = sandbox.SFMCore;

assert.ok(core, "SFMCore must be exposed");
assert.equal(Object.isFrozen(core), true, "SFMCore must be immutable");
assert.equal(core.percentOf(3, 4), 75);
assert.equal(core.percentOf(0, 0), 0);
assert.equal(core.parsePercent("42%"), 42);
assert.equal(core.normalizeImportKey("Änderung & Prüfung"), "anderung prufung");
assert.equal(core.slugify("Änderung & Prüfung"), "aenderung-pruefung");
assert.equal(core.formatBytes(1536), "1.5 KB");
assert.equal(core.escapeHtml('<script a="1">&</script>'), "&lt;script a=&quot;1&quot;&gt;&amp;&lt;/script&gt;");
assert.equal(core.dateInputValue("2026-07-01", "fallback"), "2026-07-01");
assert.equal(core.dateInputValue("not-a-date", "fallback"), "fallback");
assert.match(core.today(), /^\d{4}-\d{2}-\d{2}$/);
assert.match(core.futureDate(7), /^\d{4}-\d{2}-\d{2}$/);
assert.equal(core.startOfToday().getHours(), 0);

console.log("Core utility unit tests passed.");
