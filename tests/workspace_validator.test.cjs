const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/workspace-validator.js"),
  "utf8"
);
const sandbox = { Blob, TextEncoder };
vm.runInNewContext(source, sandbox, { filename: "workspace-validator.js" });

const validator = sandbox.SFMWorkspaceValidator.createWorkspaceValidator({
  requiredArrays: ["documents", "assets", "risks"],
  legacyRequiredArrays: ["documents", "soa", "tasks"],
  optionalTopLevel: ["setup", "notifications"]
});

const valid = validator.validate({ documents: [], assets: [{}], risks: [], notifications: {} });
assert.equal(valid.valid, true);
assert.equal(valid.format, "sfm-compliance");
assert.equal(valid.counts.assets, 1);
assert.ok(valid.bytes > 0);
assert.equal(validator.summary(valid), "Format: sfm-compliance");

const legacy = validator.validate({ setup: {}, documents: [], soa: [], tasks: [] });
assert.equal(legacy.valid, true);
assert.equal(legacy.format, "legacy");
assert.equal(legacy.warnings.length, 1);

const invalid = validator.validate({ documents: {}, assets: [] });
assert.equal(invalid.valid, false);
assert.deepEqual(Array.from(invalid.requiredMissing), ["risks"]);
assert.deepEqual(Array.from(invalid.requiredInvalid), ["documents"]);
assert.match(validator.warningText(invalid), /Pflichtbereiche/);

const unknown = validator.validate({ documents: [], assets: [], risks: [], custom: true });
assert.deepEqual(Array.from(unknown.unknownTopLevelKeys), ["custom"]);
assert.match(validator.toast("Import", unknown), /unbekannte/);

assert.equal(validator.validate(null).valid, false);
console.log("Workspace validator unit tests passed.");
