(function exposeSfmStateStore(global) {
  "use strict";

  function parse(text) {
    try {
      return { ok: true, value: JSON.parse(String(text)) };
    } catch (error) {
      return { ok: false, value: null, error };
    }
  }

  function stringify(value, space = 0) {
    try {
      return { ok: true, value: JSON.stringify(value, null, space) };
    } catch (error) {
      return { ok: false, value: "", error };
    }
  }

  function createStateStore(options = {}) {
    const storage = options.storage || global.localStorage;
    const key = String(options.key || "sfm-compliance-workspace");

    function read() {
      try {
        const raw = storage.getItem(key);
        if (!raw) return { ok: true, found: false, value: null };
        const result = parse(raw);
        return { ...result, found: result.ok };
      } catch (error) {
        return { ok: false, found: false, value: null, error };
      }
    }

    function write(value) {
      const serialized = stringify(value);
      if (!serialized.ok) return serialized;
      try {
        storage.setItem(key, serialized.value);
        return { ok: true };
      } catch (error) {
        return { ok: false, error };
      }
    }

    function remove() {
      try {
        storage.removeItem(key);
        return { ok: true };
      } catch (error) {
        return { ok: false, error };
      }
    }

    return Object.freeze({ key, read, write, remove });
  }

  global.SFMStateStore = Object.freeze({ createStateStore, parse, stringify });
})(typeof window !== "undefined" ? window : globalThis);
