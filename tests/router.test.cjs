const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/router.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "router.js" });

const calls = [];
const browserWindow = {
  location: { hash: "#dashboard" },
  history: {
    pushState(_state, _title, hash) {
      calls.push(["push", hash]);
      browserWindow.location.hash = hash;
    },
    replaceState(_state, _title, hash) {
      calls.push(["replace", hash]);
      browserWindow.location.hash = hash;
    }
  }
};

const router = sandbox.SFMRouter.createHashRouter({
  window: browserWindow,
  knownViews: ["dashboard", "review", "nis2"],
  fallback: "dashboard"
});

assert.equal(router.viewFromHash(), "dashboard");
assert.equal(router.viewFromHash("#/review"), "review");
assert.equal(router.viewFromHash("#unknown"), "dashboard");
assert.equal(router.viewFromHash("#%E0%A4%A"), "dashboard");
assert.equal(router.invitationTokenFromHash("#invite=abc%20123"), "abc 123");
assert.equal(router.invitationTokenFromHash("#review"), "");
assert.equal(router.push("unknown"), false);
assert.equal(router.push("dashboard"), false);
assert.equal(router.push("review"), true);
assert.deepEqual(calls.at(-1), ["push", "#review"]);
assert.equal(router.push("nis2", { replace: true }), true);
assert.deepEqual(calls.at(-1), ["replace", "#nis2"]);

console.log("Router unit tests passed.");
