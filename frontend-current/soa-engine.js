(function attachSoaEngine(global) {
  "use strict";

  function createSoaEngine(options = {}) {
    const controls = Array.isArray(options.controls) ? options.controls : [];
    const applicabilityOptions = new Set(options.applicabilityOptions || []);
    const implementationOptions = new Set(options.implementationOptions || []);
    const defaultOwnerByModule = options.defaultOwnerByModule || {};
    const idFactory = typeof options.idFactory === "function"
      ? options.idFactory
      : () => `soa-${Math.random().toString(36).slice(2)}`;

    function defaultRecord(control = controls[0] || {}) {
      return {
        id: idFactory(),
        controlId: control.id || "",
        applicability: "Zu prüfen",
        implementation: "Offen",
        owner: defaultOwnerByModule[control.module] || "ISB",
        justification: "",
        evidence: "",
        risk: "",
        review: "",
        notes: ""
      };
    }

    function normalizeRecord(record = {}, control = controls[0] || {}) {
      const fallback = defaultRecord(control);
      const applicability = applicabilityOptions.has(record.applicability) ? record.applicability : fallback.applicability;
      const implementation = implementationOptions.has(record.implementation) ? record.implementation : fallback.implementation;
      return {
        ...fallback,
        ...record,
        id: record.id || fallback.id,
        controlId: control.id || "",
        applicability,
        implementation,
        owner: String(record.owner || fallback.owner || "").trim(),
        justification: String(record.justification || "").trim(),
        evidence: String(record.evidence || "").trim(),
        risk: String(record.risk || "").trim(),
        review: String(record.review || "").trim(),
        notes: String(record.notes || "").trim()
      };
    }

    function normalizeRegister(records = []) {
      const byControl = new Map((Array.isArray(records) ? records : [])
        .filter((record) => record?.controlId)
        .map((record) => [record.controlId, record]));
      return controls.map((control) => normalizeRecord(byControl.get(control.id), control));
    }

    function metrics(records = [], metricOptions = {}) {
      const normalized = normalizeRegister(records);
      const hasLinkedEvidence = typeof metricOptions.hasLinkedEvidence === "function"
        ? metricOptions.hasLinkedEvidence
        : () => false;
      const applicable = normalized.filter((record) => ["Anwendbar", "Teilweise anwendbar"].includes(record.applicability)).length;
      const implemented = normalized.filter((record) => record.implementation === "Umgesetzt").length;
      const open = normalized.filter((record) => record.applicability === "Zu prüfen" || ["Offen", "Geplant"].includes(record.implementation)).length;
      const missingEvidence = normalized.filter((record, index) => {
        return ["Anwendbar", "Teilweise anwendbar"].includes(record.applicability)
          && record.implementation === "Umgesetzt"
          && !record.evidence
          && !hasLinkedEvidence(record, controls[index]);
      }).length;
      return { total: controls.length, applicable, implemented, open, missingEvidence };
    }

    return Object.freeze({ defaultRecord, normalizeRecord, normalizeRegister, metrics });
  }

  global.SFMSoaEngine = Object.freeze({ createSoaEngine });
})(typeof window !== "undefined" ? window : globalThis);
