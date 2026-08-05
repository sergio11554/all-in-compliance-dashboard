const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/versioning.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "versioning.js" });
const versioning = sandbox.SFMVersioning;

const first = versioning.fingerprint({ documents: [["a", "1.0"]], blockers: [] });
const same = versioning.fingerprint({ documents: [["a", "1.0"]], blockers: [] });
const changed = versioning.fingerprint({ documents: [["a", "1.1"]], blockers: [] });
assert.match(first, /^pkg-[a-z0-9]+$/);
assert.equal(first, same);
assert.notEqual(first, changed);

assert.equal(versioning.approvedVersion("0.1"), "1.0");
assert.equal(versioning.approvedVersion("0.9"), "1.0");
assert.equal(versioning.approvedVersion("1.2"), "1.2");
assert.equal(versioning.nextDraftVersion("0.1"), "0.2");
assert.equal(versioning.nextDraftVersion("1.9"), "1.10");
assert.equal(versioning.nextDraftVersion("Entwurf"), "0.2");
assert.equal(versioning.nextDocumentVersion("2.3"), "2.4");
assert.equal(versioning.nextDocumentVersion("2"), "2.1");
assert.equal(versioning.nextDocumentVersion("unbekannt"), "0.2");
assert.equal(versioning.nextSequence("Version 12"), "13");

console.log("Versioning unit tests passed.");
