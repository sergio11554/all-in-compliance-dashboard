(function attachRouter(global) {
  "use strict";

  function decodedHash(hash = "") {
    const raw = String(hash || "").replace(/^#\/?/, "");
    try {
      return decodeURIComponent(raw).trim();
    } catch {
      return "";
    }
  }

  function createHashRouter(options = {}) {
    const browserWindow = options.window || global;
    const fallback = String(options.fallback || "dashboard");
    const knownViews = new Set((options.knownViews || []).map((view) => String(view)));

    function isKnownView(view) {
      return knownViews.has(String(view || ""));
    }

    function viewFromHash(hash = browserWindow.location?.hash || "") {
      const route = decodedHash(hash);
      return isKnownView(route) ? route : fallback;
    }

    function invitationTokenFromHash(hash = browserWindow.location?.hash || "") {
      const route = decodedHash(hash);
      return route.startsWith("invite=") ? route.slice("invite=".length).trim() : "";
    }

    function recoveryTokenFromHash(hash = browserWindow.location?.hash || "") {
      const route = decodedHash(hash);
      return route.startsWith("recover=") ? route.slice("recover=".length).trim() : "";
    }

    function push(view, options = {}) {
      const route = String(view || "");
      if (!isKnownView(route)) return false;
      const nextHash = `#${encodeURIComponent(route)}`;
      if (browserWindow.location?.hash === nextHash) return false;
      const method = options.replace ? "replaceState" : "pushState";
      browserWindow.history?.[method]?.(null, "", nextHash);
      return true;
    }

    return Object.freeze({
      isKnownView,
      viewFromHash,
      invitationTokenFromHash,
      recoveryTokenFromHash,
      push
    });
  }

  global.SFMRouter = Object.freeze({ createHashRouter, decodedHash });
})(typeof window !== "undefined" ? window : globalThis);
