const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.resolve(__dirname, "../frontend-current/review-workflow.js"),
  "utf8"
);
const sandbox = {};
vm.runInNewContext(source, sandbox, { filename: "review-workflow.js" });

const statuses = [
  "offen", "entwurf", "vom_kunden_eingereicht", "in_beraterpruefung",
  "nacharbeit_noetig", "freigegeben", "abgelehnt", "review_ueberfaellig",
  "spaeter_pruefen", "auditrelevant", "archiviert"
];
const workflow = sandbox.SFMReviewWorkflow.createReviewWorkflow({
  statuses,
  labels: { offen: "Offen", freigegeben: "Freigegeben" },
  today: () => "2026-07-01"
});

assert.equal(workflow.normalize("freigegeben"), "freigegeben");
assert.equal(workflow.normalize("unbekannt"), "offen");
assert.equal(workflow.label("freigegeben"), "Freigegeben");
assert.equal(workflow.label("unbekannt"), "Offen");
assert.equal(workflow.inferDocument({ status: "In Prüfung" }), "vom_kunden_eingereicht");
assert.equal(workflow.inferDocument({ status: "Überarbeiten" }), "nacharbeit_noetig");
assert.equal(workflow.inferDocument({ approval: "Abgelehnt" }), "abgelehnt");
assert.equal(workflow.inferDocument({ approval: "Freigegeben" }), "freigegeben");
assert.equal(workflow.canonical({ reviewStatus: "in_beraterpruefung", status: "Freigegeben" }), "in_beraterpruefung");
assert.equal(workflow.canonical({ status: "Entwurf" }), "entwurf");
assert.equal(workflow.canonical({ review: "2026-06-30" }), "review_ueberfaellig");
assert.equal(workflow.canonical({ auditRelevant: true }), "auditrelevant");
assert.equal(workflow.canonical({ status: "Freigegeben" }), "freigegeben");
assert.equal(workflow.canonical({ status: "In Prüfung" }, "document"), "vom_kunden_eingereicht");
assert.equal(workflow.isAuditRelevant({ reviewStatus: "auditrelevant" }), true);
assert.equal(workflow.isAuditRelevantOpen({ auditRelevant: true, status: "Freigegeben" }), false);
assert.equal(workflow.isAuditRelevantOpen({ auditRelevant: true, status: "In Prüfung" }), true);

console.log("Review workflow unit tests passed.");
