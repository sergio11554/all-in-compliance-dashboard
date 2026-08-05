const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/state-store.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "state-store.js" });
const stateModule = sandbox.SFMStateStore;

function memoryStorage() {
  const values = new Map();
  return {
    getItem: (key) => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  };
}

assert.ok(stateModule, "SFMStateStore must be exposed");
const storage = memoryStorage();
const store = stateModule.createStateStore({ storage, key: "workspace" });

assert.deepEqual(
  JSON.parse(JSON.stringify(store.read())),
  { ok: true, found: false, value: null }
);
assert.equal(store.write({ documents: [], version: 1 }).ok, true);
assert.deepEqual(
  JSON.parse(JSON.stringify(store.read().value)),
  { documents: [], version: 1 }
);
storage.setItem("workspace", "{broken-json");
assert.equal(store.read().ok, false);
assert.equal(store.read().found, false);

const cyclic = {};
cyclic.self = cyclic;
assert.equal(stateModule.stringify(cyclic).ok, false);
assert.equal(stateModule.parse("not-json").ok, false);

const blockedStore = stateModule.createStateStore({
  key: "blocked",
  storage: {
    getItem: () => { throw new Error("blocked"); },
    setItem: () => { throw new Error("blocked"); },
    removeItem: () => { throw new Error("blocked"); },
  },
});
assert.equal(blockedStore.read().ok, false);
assert.equal(blockedStore.write({ value: 1 }).ok, false);
assert.equal(blockedStore.remove().ok, false);

console.log("State store unit tests passed.");
