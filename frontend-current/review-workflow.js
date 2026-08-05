(function attachReviewWorkflow(global) {
  "use strict";

  function createReviewWorkflow(options = {}) {
    const statuses = new Set(options.statuses || []);
    const labels = options.labels || {};
    const today = typeof options.today === "function"
      ? options.today
      : () => new Date().toISOString().slice(0, 10);

    function normalize(status) {
      return statuses.has(status) ? status : "offen";
    }

    function label(status) {
      return labels[normalize(status)] || "Offen";
    }

    function inferDocument(record = {}) {
      if (record.status === "Freigegeben" || record.approval === "Freigegeben") return "freigegeben";
      if (record.approval === "Abgelehnt" || record.status === "Abgelehnt") return "abgelehnt";
      if (record.status === "Überarbeiten") return "nacharbeit_noetig";
      if (record.status === "In Prüfung" || record.approval === "Prüfung läuft") return "vom_kunden_eingereicht";
      return "offen";
    }

    function canonical(record = {}, type = "") {
      const explicit = normalize(record.reviewStatus);
      if (record.reviewStatus) return explicit;
      if (type === "document") return inferDocument(record);
      if (record.status === "Archiviert") return "archiviert";
      if (record.review && record.review < today()) return "review_ueberfaellig";
      if (record.auditRelevant) return "auditrelevant";
      if (record.status === "Freigegeben" || record.approval === "Freigegeben") return "freigegeben";
      if (record.status === "Abgelehnt" || record.approval === "Abgelehnt") return "abgelehnt";
      if (record.status === "Überarbeiten") return "nacharbeit_noetig";
      if (record.status === "In Prüfung" || record.approval === "Prüfung läuft") return "vom_kunden_eingereicht";
      if (record.status === "Entwurf") return "entwurf";
      return "offen";
    }

    function isAuditRelevant(record = {}) {
      return Boolean(record.auditRelevant) || record.reviewStatus === "auditrelevant";
    }

    function isAuditRelevantOpen(record = {}) {
      return isAuditRelevant(record)
        && !(record.reviewStatus === "freigegeben" || record.status === "Freigegeben" || record.approval === "Freigegeben");
    }

    return Object.freeze({ normalize, label, inferDocument, canonical, isAuditRelevant, isAuditRelevantOpen });
  }

  global.SFMReviewWorkflow = Object.freeze({ createReviewWorkflow });
})(typeof window !== "undefined" ? window : globalThis);
