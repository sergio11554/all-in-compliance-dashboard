const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/workspace-merge.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "workspace-merge.js" });
const mergeEngine = sandbox.SFMWorkspaceMerge;

const sections = [
  { key: "assets", label: "Assets" },
  { key: "risks", label: "Risiken" },
  { key: "onboarding", label: "Startprofil" }
];
const local = {
  assets: [{ id: "a", name: "Lokales Asset" }],
  risks: [{ id: "r", title: "Gleich" }],
  onboarding: { organization: "Lokal" }
};
const remote = {
  assets: [{ id: "a", name: "Server Asset" }],
  risks: [{ title: "Gleich", id: "r" }],
  onboarding: { organization: "Server" },
  serverOnly: true
};

assert.equal(mergeEngine.equal(local.risks, remote.risks), true);
const comparison = mergeEngine.compare(local, remote, sections);
assert.deepEqual(
  JSON.parse(JSON.stringify(comparison.map(({ key, changed }) => ({ key, changed })))),
  [
    { key: "assets", changed: true },
    { key: "risks", changed: false },
    { key: "onboarding", changed: true }
  ]
);
assert.equal(comparison[0].local.count, 1);

const merged = mergeEngine.merge(local, remote, { assets: "local", onboarding: "remote" }, sections);
assert.equal(merged.assets[0].name, "Lokales Asset");
assert.equal(merged.onboarding.organization, "Server");
assert.equal(merged.serverOnly, true);
merged.assets[0].name = "Geändert";
assert.equal(local.assets[0].name, "Lokales Asset");

console.log("Workspace merge unit tests passed.");
