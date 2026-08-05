const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/api-client.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "api-client.js" });
const apiModule = sandbox.SFMApiClient;

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}

(async () => {
  assert.ok(apiModule, "SFMApiClient must be exposed");
  assert.equal(typeof apiModule.createApiClient, "function");

  const requests = [];
  let nextResponse = response({ ok: true });
  const client = apiModule.createApiClient({
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return nextResponse;
    },
    getCsrfToken: () => "csrf-test-token",
    validationSummary: (validation) => validation?.summary || "",
  });

  await client.request("/api/example");
  assert.equal(requests[0].url, "/api/example");
  assert.equal(requests[0].options.credentials, "same-origin");
  assert.equal(requests[0].options.headers["X-CSRF-Token"], undefined);

  await client.request("/api/example", { method: "POST", json: { value: 42 } });
  assert.equal(requests[1].options.headers["Content-Type"], "application/json");
  assert.equal(requests[1].options.headers["X-CSRF-Token"], "csrf-test-token");
  assert.equal(requests[1].options.body, JSON.stringify({ value: 42 }));
  assert.equal("json" in requests[1].options, false);

  nextResponse = response(
    { error: "workspace invalid", validation: { summary: "Pflichtfelder fehlen" } },
    400
  );
  await assert.rejects(
    () => client.request("/api/state", { method: "PUT", json: { state: {} } }),
    (error) => {
      assert.equal(error.name, "ApiError");
      assert.equal(error.status, 400);
      assert.equal(error.message, "workspace invalid · Pflichtfelder fehlen");
      return true;
    }
  );

  console.log("API client unit tests passed.");
})().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
