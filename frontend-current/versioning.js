(function attachVersioning(global) {
  "use strict";

  function fingerprint(payload = {}, prefix = "pkg") {
    const value = JSON.stringify(payload);
    let hash = 5381;
    for (let index = 0; index < value.length; index += 1) {
      hash = ((hash << 5) + hash) ^ value.charCodeAt(index);
    }
    return `${prefix}-${(hash >>> 0).toString(36)}`;
  }

  function approvedVersion(version) {
    const current = String(version || "").trim();
    if (!current || current === "0.1" || current.startsWith("0.")) return "1.0";
    return current;
  }

  function nextDraftVersion(version) {
    const match = String(version || "0.1").trim().match(/^(\d+)\.(\d+)$/);
    if (!match) return "0.2";
    return `${Number(match[1])}.${Number(match[2]) + 1}`;
  }

  function nextDocumentVersion(version) {
    const current = String(version || "0.1").trim();
    const match = current.match(/^(\d+)\.(\d+)$/);
    if (match) return `${Number(match[1])}.${Number(match[2]) + 1}`;
    const numeric = Number.parseInt(current, 10);
    if (Number.isFinite(numeric)) return `${numeric}.1`;
    return "0.2";
  }

  function nextSequence(version) {
    const current = Number(String(version || "0").replace(/\D/g, "")) || 0;
    return String(current + 1);
  }

  global.SFMVersioning = Object.freeze({
    fingerprint,
    approvedVersion,
    nextDraftVersion,
    nextDocumentVersion,
    nextSequence
  });
})(typeof window !== "undefined" ? window : globalThis);
