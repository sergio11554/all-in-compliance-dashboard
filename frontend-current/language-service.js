(function attachLanguageService(global) {
  "use strict";

  function createLanguageService(options = {}) {
    const translations = options.translations || {};
    const supported = new Set(options.supported || Object.keys(translations));
    const fallbackLanguage = supported.has(options.fallbackLanguage) ? options.fallbackLanguage : "de";
    const storage = options.storage;
    const storageKey = String(options.storageKey || "language");
    let language = fallbackLanguage;

    function normalize(value) {
      return supported.has(value) ? value : fallbackLanguage;
    }

    function load() {
      try {
        language = normalize(storage?.getItem(storageKey));
      } catch {
        language = fallbackLanguage;
      }
      return language;
    }

    function current() {
      return language;
    }

    function set(nextLanguage) {
      const next = normalize(nextLanguage);
      const changed = next !== language;
      language = next;
      try {
        storage?.setItem(storageKey, language);
        return { language, changed, persisted: true };
      } catch (error) {
        return { language, changed, persisted: false, error };
      }
    }

    function translate(key, fallback = "") {
      return translations[language]?.[key]
        || translations[fallbackLanguage]?.[key]
        || fallback
        || key;
    }

    function isActive(candidate) {
      return language === normalize(candidate);
    }

    load();
    return Object.freeze({ current, set, translate, isActive, normalize, load });
  }

  global.SFMLanguageService = Object.freeze({ createLanguageService });
})(typeof window !== "undefined" ? window : globalThis);
