(function exposeSfmCore(global) {
  "use strict";

  function percentOf(done, total) {
    return Math.round((done / Math.max(total, 1)) * 100);
  }

  function parsePercent(value) {
    return Number.parseInt(String(value || "0").replace("%", ""), 10) || 0;
  }

  function normalizeImportKey(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/ä/g, "ae")
      .replace(/ö/g, "oe")
      .replace(/ü/g, "ue")
      .replace(/ß/g, "ss")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, " ")
      .trim();
  }

  function formatBytes(bytes) {
    if (!bytes) return "";
    const units = ["B", "KB", "MB", "GB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
  }

  function today() {
    return new Date().toISOString().slice(0, 10);
  }

  function dateFromUnix(value) {
    const date = new Date(Number(value) * 1000);
    if (Number.isNaN(date.getTime())) return today();
    return date.toISOString().slice(0, 10);
  }

  function futureDate(days) {
    const date = new Date();
    date.setDate(date.getDate() + days);
    return date.toISOString().slice(0, 10);
  }

  function dateInputValue(value, fallback = today()) {
    const text = String(value || "").trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(text) && !Number.isNaN(new Date(`${text}T00:00:00`).getTime())) return text;
    return fallback;
  }

  function startOfToday() {
    const date = new Date();
    date.setHours(0, 0, 0, 0);
    return date;
  }

  function slugify(value) {
    return String(value)
      .toLowerCase()
      .replaceAll("ä", "ae")
      .replaceAll("ö", "oe")
      .replaceAll("ü", "ue")
      .replaceAll("ß", "ss")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  global.SFMCore = Object.freeze({
    percentOf,
    parsePercent,
    normalizeImportKey,
    formatBytes,
    today,
    dateFromUnix,
    futureDate,
    dateInputValue,
    startOfToday,
    slugify,
    escapeHtml,
  });
})(typeof window !== "undefined" ? window : globalThis);
