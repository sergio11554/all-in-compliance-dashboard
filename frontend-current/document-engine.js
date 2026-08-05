(function attachDocumentEngine(global) {
  "use strict";

  function createDocumentEngine(options = {}) {
    const today = typeof options.today === "function"
      ? options.today
      : () => new Date().toISOString().slice(0, 10);

    function isSource(document = {}) {
      return document.status === "Quelle";
    }

    function isArchived(document = {}) {
      return document.status === "Archiviert";
    }

    function isWorking(document = {}) {
      return !isSource(document);
    }

    function hasMissingMetadata(document = {}) {
      return !document.owner
        || !document.version
        || !document.review
        || !(document.evidenceFor || document.linkedTo);
    }

    function isReviewOverdue(document = {}, referenceDate = today()) {
      return Boolean(document.review
        && String(document.review) < String(referenceDate)
        && !isArchived(document)
        && !isSource(document));
    }

    function isApprovalOpen(document = {}) {
      return !["Freigegeben", "Nicht erforderlich"].includes(document.approval)
        && !["Freigegeben", "Archiviert", "Quelle"].includes(document.status);
    }

    function needsReviewQueue(document = {}, referenceDate = today()) {
      if (!document || isSource(document) || isArchived(document)) return false;
      return document.status === "In Prüfung"
        || document.approval === "Prüfung läuft"
        || document.status === "Überarbeiten"
        || document.approval === "Abgelehnt"
        || isReviewOverdue(document, referenceDate);
    }

    function reviewPriority(document = {}, referenceDate = today()) {
      let priority = 0;
      if (isReviewOverdue(document, referenceDate)) priority += 30;
      if (document.status === "In Prüfung" || document.approval === "Prüfung läuft") priority += 20;
      if (document.status === "Überarbeiten" || document.approval === "Abgelehnt") priority += 10;
      return priority;
    }

    function metrics(documents = [], referenceDate = today()) {
      const workingDocuments = (Array.isArray(documents) ? documents : []).filter(isWorking);
      return {
        working: workingDocuments.length,
        approved: workingDocuments.filter((document) => document.status === "Freigegeben" || document.approval === "Freigegeben").length,
        inReview: workingDocuments.filter((document) => document.status === "In Prüfung" || document.approval === "Prüfung läuft").length,
        overdue: workingDocuments.filter((document) => isReviewOverdue(document, referenceDate)).length,
        missing: workingDocuments.filter(hasMissingMetadata).length
      };
    }

    return Object.freeze({
      isSource,
      isArchived,
      isWorking,
      hasMissingMetadata,
      isReviewOverdue,
      isApprovalOpen,
      needsReviewQueue,
      reviewPriority,
      metrics
    });
  }

  global.SFMDocumentEngine = Object.freeze({ createDocumentEngine });
})(typeof window !== "undefined" ? window : globalThis);
