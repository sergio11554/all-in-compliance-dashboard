(function exposeSfmApiClient(global) {
  "use strict";

  class ApiError extends Error {
    constructor(message, status = 0, payload = {}) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.payload = payload;
    }
  }

  function createApiClient(options = {}) {
    const fetchImpl = options.fetchImpl || global.fetch?.bind(global);
    const getCsrfToken = options.getCsrfToken || (() => "");
    const validationSummary = options.validationSummary || (() => "");
    if (typeof fetchImpl !== "function") {
      throw new Error("A fetch implementation is required for SFMApiClient");
    }

    async function request(path, requestOptions = {}) {
      const headers = { ...(requestOptions.headers || {}) };
      const requestConfig = {
        ...requestOptions,
        credentials: requestOptions.credentials || "same-origin",
        headers,
      };

      if (requestOptions.json !== undefined) {
        headers["Content-Type"] = "application/json";
        requestConfig.body = JSON.stringify(requestOptions.json);
        delete requestConfig.json;
      }

      const method = String(requestConfig.method || "GET").toUpperCase();
      const csrfToken = getCsrfToken();
      if (!new Set(["GET", "HEAD", "OPTIONS"]).has(method) && csrfToken && !headers["X-CSRF-Token"]) {
        headers["X-CSRF-Token"] = csrfToken;
      }

      const response = await fetchImpl(path, requestConfig);
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = validationSummary(payload.validation);
        const message = [payload.error || payload.message || `HTTP ${response.status}`, detail]
          .filter(Boolean)
          .join(" · ");
        throw new ApiError(message, response.status, payload);
      }
      return payload;
    }

    return Object.freeze({
      request,
      health: () => request("/api/health", { cache: "no-store" }),
      session: () => request("/api/session", { cache: "no-store" }),
      ssoProviders: () => request("/api/auth/sso/providers", { cache: "no-store" }),
      login: (credentials) => request("/api/auth/login", { method: "POST", json: credentials }),
      logout: () => request("/api/auth/logout", { method: "POST" }),
    });
  }

  global.SFMApiClient = Object.freeze({ ApiError, createApiClient });
})(typeof window !== "undefined" ? window : globalThis);
