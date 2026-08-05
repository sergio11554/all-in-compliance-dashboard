const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/access-control.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "access-control.js" });

const access = sandbox.SFMAccessControl.createAccessControl({
  rolePermissions: {
    admin: ["readWorkspace", "saveWorkspace", "reviewDocument", "admin"],
    consultant: ["readWorkspace", "saveWorkspace", "reviewDocument"],
    contributor: ["readWorkspace", "submitWorkspace", "uploadFile", "downloadFile"],
    customer: ["readWorkspace", "submitWorkspace", "uploadFile", "downloadFile"],
    viewer: ["readWorkspace", "downloadFile"]
  },
  submitterRoles: ["customer", "contributor"]
});

const admin = { role: "admin" };
const consultant = { role: "consultant" };
const customer = { role: "customer" };
const contributor = { role: "contributor" };
const viewer = { role: "viewer" };
const platformAdmin = { role: "viewer", platformAdmin: true };

assert.equal(access.isAdmin(admin), true);
assert.equal(access.isAdmin(consultant), false);
assert.equal(access.hasPermission(platformAdmin, "anything", false), true);
assert.deepEqual(Array.from(access.permissionsFor({ role: "viewer", permissions: ["custom"] })), ["readWorkspace", "downloadFile", "custom"]);
assert.equal(access.canSubmitDocuments(customer), true);
assert.equal(access.canSubmitDocuments(viewer), false);
assert.equal(access.canSubmitWorkspace(customer), true);
assert.equal(access.canSubmitWorkspace(contributor), true);
assert.equal(access.canSubmitWorkspace(viewer), false);
assert.equal(access.canReviewDocuments(consultant), true);
assert.equal(access.canReviewDocuments(customer), false);
assert.equal(access.isCustomerWorkspaceUser(customer), true);
assert.equal(access.isCustomerWorkspaceUser(admin), false);
assert.equal(access.canUseConsultantArea(null, true), true);
assert.equal(access.canUseConsultantArea(customer, true), false);
assert.equal(access.canAccessView(customer, "review"), false);
assert.equal(access.canAccessView(consultant, "review"), true);
assert.equal(access.canAccessView(admin, "team"), true);
assert.equal(access.canAccessView(consultant, "team"), false);
assert.equal(access.canAccessView(admin, "quarantine"), true);
assert.equal(access.canAccessView(consultant, "quarantine"), false);
assert.equal(access.canAccessView(customer, "quarantine"), false);
assert.equal(access.canAccessView(viewer, "quarantine"), false);
assert.equal(access.canAccessView(admin, "operations"), false);
assert.equal(access.canAccessView(platformAdmin, "operations"), true);
assert.equal(access.canAccessView(admin, "jobs"), false);
assert.equal(access.canAccessView(platformAdmin, "jobs"), true);
assert.equal(access.canAccessView(null, "clients", { customerPresentationMode: true }), false);
assert.equal(access.canAccessView(null, "clients", { customerPresentationMode: false }), true);

console.log("Access control unit tests passed.");
