(function attachWorkspaceValidator(global) {
  "use strict";

  function serializedBytes(value) {
    const serialized = JSON.stringify(value);
    if (typeof global.Blob === "function") return new global.Blob([serialized]).size;
    if (typeof global.TextEncoder === "function") return new global.TextEncoder().encode(serialized).length;
    return serialized.length;
  }

  function createWorkspaceValidator(options = {}) {
    const requiredArrays = Array.from(options.requiredArrays || [], String);
    const legacyRequiredArrays = Array.from(options.legacyRequiredArrays || [], String);
    const optionalTopLevel = new Set(Array.from(options.optionalTopLevel || [], String));

    function validate(data) {
      const report = {
        valid: false,
        format: "unknown",
        errors: [],
        warnings: [],
        requiredMissing: [],
        requiredInvalid: [],
        unknownTopLevelKeys: [],
        counts: {},
        bytes: 0
      };
      if (!data || typeof data !== "object" || Array.isArray(data)) {
        report.errors.push("Die Datei enthält keinen gültigen Workspace.");
        return report;
      }

      try {
        report.bytes = serializedBytes(data);
      } catch {
        report.errors.push("Die Datei kann nicht als Workspace gelesen werden.");
        return report;
      }

      const sfmMissing = requiredArrays.filter((key) => !(key in data));
      const sfmInvalid = requiredArrays.filter((key) => key in data && !Array.isArray(data[key]));
      const legacyMissing = legacyRequiredArrays.filter((key) => !(key in data));
      const legacyInvalid = legacyRequiredArrays.filter((key) => key in data && !Array.isArray(data[key]));
      const legacySetupOk = data.setup && typeof data.setup === "object" && !Array.isArray(data.setup);
      let knownKeys = new Set(requiredArrays);

      if (!sfmMissing.length && !sfmInvalid.length) {
        report.valid = true;
        report.format = "sfm-compliance";
      } else if (legacySetupOk && !legacyMissing.length && !legacyInvalid.length) {
        report.valid = true;
        report.format = "legacy";
        knownKeys = new Set([...legacyRequiredArrays, "setup"]);
        report.warnings.push("Älterer Workspace erkannt. Fehlende SFM-Bereiche werden beim Import mit Standardbereichen ergänzt.");
      } else {
        report.requiredMissing = sfmMissing;
        report.requiredInvalid = sfmInvalid;
        if (sfmMissing.length) report.errors.push(`Pflichtbereiche fehlen: ${sfmMissing.slice(0, 8).join(", ")}`);
        if (sfmInvalid.length) report.errors.push(`Pflichtbereiche haben ein falsches Format: ${sfmInvalid.slice(0, 8).join(", ")}`);
      }

      Object.entries(data).forEach(([key, value]) => {
        if (Array.isArray(value)) report.counts[key] = value.length;
      });

      const allowedKeys = new Set([...knownKeys, ...optionalTopLevel]);
      const unknown = Object.keys(data).filter((key) => !allowedKeys.has(key)).sort();
      report.unknownTopLevelKeys = unknown.slice(0, 25);
      if (unknown.length) {
        report.warnings.push(`${unknown.length} unbekannte Top-Level-Felder werden übernommen, aber nicht fachlich bewertet.`);
      }
      return report;
    }

    function summary(validation) {
      if (!validation || typeof validation !== "object") return "";
      const errors = Array.isArray(validation.errors) ? validation.errors : [];
      const warnings = Array.isArray(validation.warnings) ? validation.warnings : [];
      const parts = [...errors, ...warnings].filter(Boolean);
      if (parts.length) return parts.slice(0, 3).join(" · ");
      if (validation.valid && validation.format) return `Format: ${validation.format}`;
      return "";
    }

    function warningText(validation) {
      const text = summary(validation);
      if (text) return text;
      const missing = Array.isArray(validation?.requiredMissing) ? validation.requiredMissing : [];
      if (missing.length) return `Pflichtbereiche fehlen: ${missing.slice(0, 8).join(", ")}`;
      return "Workspace-Struktur konnte nicht bestätigt werden.";
    }

    function toast(prefix, validation) {
      const text = summary(validation);
      return text ? `${prefix}: ${text}` : prefix;
    }

    return Object.freeze({ validate, summary, warningText, toast });
  }

  global.SFMWorkspaceValidator = Object.freeze({ createWorkspaceValidator, serializedBytes });
})(typeof window !== "undefined" ? window : globalThis);
