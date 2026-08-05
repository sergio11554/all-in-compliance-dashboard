(function attachRiskEngine(global) {
  "use strict";

  function createRiskEngine() {
    function defaultMethodology() {
      return {
        methodName: "5x5 Likelihood/Impact",
        likelihoodLabels: "1 sehr selten; 2 eher selten; 3 möglich; 4 wahrscheinlich; 5 sehr wahrscheinlich",
        impactLabels: "1 gering; 2 moderat; 3 deutlich; 4 schwer; 5 kritisch",
        treatmentFrom: "10",
        managementFrom: "10",
        criticalFrom: "16",
        acceptanceRule: "Restrisiken ab Score 10 oder alle bewusst akzeptierten Risiken werden durch Management/Risk Owner dokumentiert und durch Berater/Admin geprüft.",
        reviewCycle: "Mindestens jährlich sowie nach wesentlichen Änderungen, Vorfällen oder Maßnahmenabschluss.",
        owner: "ISB / Risk Owner",
        updated: ""
      };
    }

    function normalizeMethodology(methodology = {}) {
      const fallback = defaultMethodology();
      const source = methodology && typeof methodology === "object" ? methodology : {};
      return {
        ...fallback,
        ...source,
        methodName: String(source.methodName || fallback.methodName).trim(),
        likelihoodLabels: String(source.likelihoodLabels || fallback.likelihoodLabels).trim(),
        impactLabels: String(source.impactLabels || fallback.impactLabels).trim(),
        treatmentFrom: String(source.treatmentFrom || fallback.treatmentFrom).trim(),
        managementFrom: String(source.managementFrom || fallback.managementFrom).trim(),
        criticalFrom: String(source.criticalFrom || fallback.criticalFrom).trim(),
        acceptanceRule: String(source.acceptanceRule || fallback.acceptanceRule).trim(),
        reviewCycle: String(source.reviewCycle || fallback.reviewCycle).trim(),
        owner: String(source.owner || fallback.owner).trim(),
        updated: String(source.updated || "").trim()
      };
    }

    function thresholds(methodology = {}) {
      const source = normalizeMethodology(methodology);
      const clamp = (value, fallback) => Math.max(1, Math.min(25, Number(value) || fallback));
      return {
        treatmentFrom: clamp(source.treatmentFrom, 10),
        managementFrom: clamp(source.managementFrom, 10),
        criticalFrom: clamp(source.criticalFrom, 16)
      };
    }

    function score(likelihood, impact) {
      const likelihoodValue = Number(likelihood);
      const impactValue = Number(impact);
      if (!likelihoodValue || !impactValue) return 0;
      return likelihoodValue * impactValue;
    }

    function level(value) {
      const numericScore = Number(value) || 0;
      if (numericScore >= 16) return "Sehr hoch";
      if (numericScore >= 10) return "Hoch";
      if (numericScore >= 5) return "Mittel";
      if (numericScore > 0) return "Niedrig";
      return "-";
    }

    function splitScale(text = "") {
      const items = String(text || "")
        .split(";")
        .map((part) => part.trim())
        .filter(Boolean)
        .map((part, index) => {
          const match = part.match(/^(\d+)\s*(.*)$/);
          return {
            value: match ? match[1] : String(index + 1),
            label: match ? match[2].trim() : part
          };
        });
      return items.length ? items : [
        { value: "1", label: "gering" },
        { value: "2", label: "eher niedrig" },
        { value: "3", label: "mittel" },
        { value: "4", label: "hoch" },
        { value: "5", label: "kritisch" }
      ];
    }

    return Object.freeze({ defaultMethodology, normalizeMethodology, thresholds, score, level, splitScale });
  }

  global.SFMRiskEngine = Object.freeze({ createRiskEngine });
})(typeof window !== "undefined" ? window : globalThis);
