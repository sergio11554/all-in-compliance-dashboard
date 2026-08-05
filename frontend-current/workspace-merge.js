(function attachWorkspaceMerge(global) {
  "use strict";

  function clone(value) {
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  }

  function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (!value || typeof value !== "object") return value;
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = canonical(value[key]);
      return result;
    }, {});
  }

  function equal(left, right) {
    return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
  }

  function describe(value) {
    if (Array.isArray(value)) return { kind: "list", count: value.length };
    if (value && typeof value === "object") return { kind: "object", count: Object.keys(value).length };
    if (value === null || value === undefined || value === "") return { kind: "empty", count: 0 };
    return { kind: "value", count: 1 };
  }

  function compare(localState = {}, remoteState = {}, sections = []) {
    return sections.map((section) => {
      const key = section.key;
      const localValue = localState?.[key];
      const remoteValue = remoteState?.[key];
      return {
        key,
        label: section.label || key,
        changed: !equal(localValue, remoteValue),
        local: describe(localValue),
        remote: describe(remoteValue)
      };
    });
  }

  function merge(localState = {}, remoteState = {}, choices = {}, sections = []) {
    const merged = clone(remoteState) || {};
    sections.forEach((section) => {
      if (choices[section.key] !== "local") return;
      if (Object.prototype.hasOwnProperty.call(localState, section.key)) {
        merged[section.key] = clone(localState[section.key]);
      }
    });
    return merged;
  }

  global.SFMWorkspaceMerge = Object.freeze({ clone, canonical, equal, describe, compare, merge });
})(typeof window !== "undefined" ? window : globalThis);
