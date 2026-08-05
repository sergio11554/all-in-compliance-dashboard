(function attachAuditPackageGate(global) {
  "use strict";

  function createAuditPackageGate(options = {}) {
    const percentOf = typeof options.percentOf === "function"
      ? options.percentOf
      : (value, total) => total ? Math.round((Number(value) / Number(total)) * 100) : 0;

    function evaluate(input = {}) {
      const documentsOpen = (input.documents || []).filter((item) => item.auditRelevant && !item.approved);
      const criticalRisksOpen = (input.risks || []).filter((item) => item.critical && (!item.treatment || !item.approved));
      const soaOpen = (input.soa || []).filter((item) => item.auditRelevant && !item.approved);
      const policyOpen = (input.policies || []).filter((item) => item.auditRelevant && !item.approved);
      const draftsOpen = (input.drafts || []).filter((item) => item.open && !item.approved);
      const capaOpen = (input.capa || []).filter((item) => item.auditRelevant && !item.approved);
      const explicitBlockers = (input.reviewItems || []).filter((item) => item.auditBlocker && !item.approved);

      const blockers = Array.from(new Set([
        ...documentsOpen.map((item) => `Nachweis nicht freigegeben: ${item.title || "Nachweis"}`),
        ...criticalRisksOpen.map((item) => `Kritisches Risiko nicht geprüft: ${item.title || "Risiko"}`),
        ...soaOpen.map((item) => `SoA-Eintrag nicht geprüft: ${item.title || "SoA-Eintrag"}`),
        ...policyOpen.map((item) => `Policy mit Auditbezug nicht freigegeben: ${item.title || "Policy"}`),
        ...draftsOpen.map((item) => `Arbeitsvorlage nicht freigegeben: ${item.title || "Arbeitsvorlage"}`),
        ...capaOpen.map((item) => item.reason || `CAPA nicht beraterfreigegeben: ${item.title || "Korrekturmaßnahme"}`),
        ...explicitBlockers.map((item) => `${item.type || "Prüfpunkt"}: ${item.title || "Audit-Blocker"}`)
      ]));
      const formalGateClear = blockers.length === 0;
      const criteria = [
        {
          label: "Audit-Blocker",
          open: blockers.length,
          hint: blockers.length ? "Vor Beraterfreigabe klären" : "Keine offenen Blocker erkannt"
        },
        {
          label: "Auditrelevante Nachweise",
          open: documentsOpen.length,
          hint: documentsOpen.length ? "Freigabe durch Berater/Admin fehlt" : "Freigegeben oder nicht offen"
        },
        {
          label: "Kritische Risiken",
          open: criticalRisksOpen.length,
          hint: criticalRisksOpen.length ? "Behandlung und Prüfstatus offen" : "Geprüft oder nicht kritisch offen"
        },
        {
          label: "SoA-Einträge",
          open: soaOpen.length,
          hint: soaOpen.length ? "Auditrelevante SoA-Prüfung offen" : "Keine offene auditrelevante SoA-Prüfung"
        },
        {
          label: "Policies mit Auditbezug",
          open: policyOpen.length,
          hint: policyOpen.length ? "Freigabe fehlt" : "Freigegeben oder nicht offen"
        },
        {
          label: "Arbeitsvorlagen",
          open: draftsOpen.length,
          hint: draftsOpen.length ? "Nacharbeit, Prüfung oder Freigabe offen" : "Keine auditrelevanten offenen Arbeitsvorlagen"
        },
        {
          label: "CAPA / Korrekturmaßnahmen",
          open: capaOpen.length,
          hint: capaOpen.length ? "Umsetzung, Nachweis oder Wirksamkeitsprüfung offen" : "Keine offene auditrelevante CAPA"
        }
      ];

      return {
        formalGateClear,
        consultantApproved: formalGateClear,
        blockers,
        criteria,
        autoPreparedPercent: percentOf(input.bundle?.ready || 0, input.bundle?.total || 0)
      };
    }

    return Object.freeze({ evaluate });
  }

  global.SFMAuditPackageGate = Object.freeze({ createAuditPackageGate });
})(typeof window !== "undefined" ? window : globalThis);
