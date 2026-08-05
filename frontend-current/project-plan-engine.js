(function attachProjectPlanEngine(global) {
  "use strict";

  function createProjectPlanEngine(options = {}) {
    const defaults = Array.isArray(options.defaults) ? options.defaults : [];
    const streams = Array.isArray(options.streams) ? options.streams : ["ISO 27001", "NIS-2", "Gemeinsam"];
    const percentOf = typeof options.percentOf === "function"
      ? options.percentOf
      : (value, total) => total ? Math.round((Number(value) / Number(total)) * 100) : 0;
    const today = typeof options.today === "function"
      ? options.today
      : () => new Date().toISOString().slice(0, 10);

    function createDefault() {
      return defaults.map(([id, stream, phase, title, mapping, deliverable, owner, source, module], index) => ({
        id,
        stream,
        phase,
        title,
        mapping,
        deliverable,
        owner,
        source,
        module,
        due: "",
        status: index < 2 ? "In Arbeit" : "Offen"
      }));
    }

    function normalize(rows = []) {
      const existing = new Map((Array.isArray(rows) ? rows : []).map((row) => [row.id, row]));
      return createDefault().map((fallback) => ({ ...fallback, ...(existing.get(fallback.id) || {}) }));
    }

    function progress(rows = []) {
      const plan = normalize(rows);
      const total = plan.length;
      const done = plan.filter((item) => item.status === "Erledigt").length;
      const byStream = {};
      streams.forEach((stream) => {
        const streamRows = plan.filter((item) => item.stream === stream);
        const streamDone = streamRows.filter((item) => item.status === "Erledigt").length;
        byStream[stream] = `${percentOf(streamDone, streamRows.length)}%`;
      });
      return { total, done, byStream, percent: percentOf(done, total) };
    }

    function statusMetrics(rows = []) {
      const plan = Array.isArray(rows) ? rows : [];
      const total = plan.length;
      const done = plan.filter((item) => item.status === "Erledigt").length;
      const blocked = plan.filter((item) => item.status === "Blockiert").length;
      const active = plan.filter((item) => item.status === "In Arbeit").length;
      const open = Math.max(0, total - done - blocked - active);
      const overdue = plan.filter((item) => item.due && item.due < today() && item.status !== "Erledigt").length;
      return { total, done, blocked, active, open, overdue, percent: percentOf(done, total) };
    }

    function dueState(item = {}) {
      if (!item.due) return { label: "ohne Frist", tone: "open", overdue: false };
      const overdue = item.due < today() && item.status !== "Erledigt";
      return {
        label: overdue ? `überfällig ${item.due}` : item.due,
        tone: overdue ? "blocked" : "active",
        overdue
      };
    }

    function ownerSummary(rows = []) {
      const owners = new Map();
      (Array.isArray(rows) ? rows : normalize(rows)).forEach((item) => {
        const owner = item.owner || "Offen";
        const current = owners.get(owner) || { owner, total: 0, open: 0, active: 0, blocked: 0, done: 0 };
        current.total += 1;
        if (item.status === "Erledigt") current.done += 1;
        else if (item.status === "Blockiert") current.blocked += 1;
        else if (item.status === "In Arbeit") current.active += 1;
        else current.open += 1;
        owners.set(owner, current);
      });
      return [...owners.values()].sort((left, right) => {
        return right.blocked - left.blocked
          || right.active - left.active
          || right.open - left.open
          || left.owner.localeCompare(right.owner);
      });
    }

    return Object.freeze({ createDefault, normalize, progress, statusMetrics, dueState, ownerSummary });
  }

  global.SFMProjectPlanEngine = Object.freeze({ createProjectPlanEngine });
})(typeof window !== "undefined" ? window : globalThis);
