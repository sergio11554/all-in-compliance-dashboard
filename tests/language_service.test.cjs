const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/language-service.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "language-service.js" });

const values = new Map([["lang", "en"]]);
const storage = {
  getItem(key) { return values.get(key) || null; },
  setItem(key, value) { values.set(key, value); }
};
const service = sandbox.SFMLanguageService.createLanguageService({
  translations: {
    de: { hello: "Hallo", fallback: "Deutsch" },
    en: { hello: "Hello" }
  },
  supported: ["de", "en"],
  fallbackLanguage: "de",
  storage,
  storageKey: "lang"
});

assert.equal(service.current(), "en");
assert.equal(service.translate("hello"), "Hello");
assert.equal(service.translate("fallback"), "Deutsch");
assert.equal(service.translate("missing", "Ersatz"), "Ersatz");
assert.equal(service.set("de").changed, true);
assert.equal(values.get("lang"), "de");
assert.equal(service.translate("hello"), "Hallo");
assert.equal(service.set("fr").language, "de");
assert.equal(service.isActive("de"), true);

const blocked = sandbox.SFMLanguageService.createLanguageService({
  translations: { de: {} },
  supported: ["de"],
  fallbackLanguage: "de",
  storage: {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); }
  }
});
assert.equal(blocked.current(), "de");
assert.equal(blocked.set("de").persisted, false);

console.log("Language service unit tests passed.");
