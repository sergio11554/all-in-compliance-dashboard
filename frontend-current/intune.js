(function () {
  "use strict";
  let scope = "";
  let model = {};
  let timer;
  let paint = () => {};
  let refreshActive = () => {};
  window.addEventListener("online", () => refreshActive());
  const actionLabels = { new: "Neu", updated: "Aktualisieren", unchanged: "Unverändert", missing: "Nicht mehr gemeldet" };
  const demoDevices = [
    { id: "demo-01", deviceName: "DEMO-LAP-001", operatingSystem: "Windows", osVersion: "11", serialNumber: "DEMO-SN-001", manufacturer: "Microsoft", model: "Surface Laptop", isEncrypted: true, complianceState: "compliant", lastSyncDateTime: "" },
    { id: "demo-02", deviceName: "DEMO-LAP-002", operatingSystem: "Windows", osVersion: "11", serialNumber: "DEMO-SN-002", manufacturer: "Lenovo", model: "ThinkPad", isEncrypted: false, complianceState: "noncompliant", lastSyncDateTime: "" },
    { id: "demo-03", deviceName: "DEMO-MAC-003", operatingSystem: "macOS", osVersion: "", serialNumber: "DEMO-SN-003", manufacturer: "Apple", model: "MacBook", isEncrypted: null, complianceState: "unknown", lastSyncDateTime: "" }
  ];

  function date(value) {
    if (!value) return "Noch nicht erfolgt";
    const parsed = new Date(typeof value === "number" ? value * 1000 : value);
    return Number.isNaN(parsed.getTime()) ? "Unbekannt" : parsed.toLocaleString("de-DE", { timeZone: "Europe/Berlin", dateStyle: "short", timeStyle: "short" });
  }

  function deviceState(device) {
    return ({ compliant: "Intune: konform", noncompliant: "Intune: auffällig", inGracePeriod: "Intune: Nachfrist", conflict: "Intune: Konflikt" })[device.complianceState] || "Intune: ungeklärt";
  }

  function table(rows, escape, simulated = false) {
    return `<div class="intune-table-scroll" tabindex="0" role="region" aria-label="Intune-Geräte"><table class="intune-table"><thead><tr><th>Änderung</th><th>Gerät</th><th>Betriebssystem</th><th>Seriennummer</th><th>Verschlüsselung</th><th>Technischer Status</th></tr></thead><tbody>${rows.length ? rows.map(row => {
      const device = row.device;
      return `<tr><td>${escape(simulated ? "Test-Asset" : actionLabels[row.action] || "Prüfen")}</td><td><strong>${escape(device.deviceName || "Unbenannt")}</strong><small>${escape([device.manufacturer, device.model].filter(Boolean).join(" · "))}</small></td><td>${escape([device.operatingSystem, device.osVersion].filter(Boolean).join(" ") || "Unbekannt")}</td><td>${escape(device.serialNumber || "Unbekannt")}</td><td>${device.isEncrypted === true ? "Aktiv" : device.isEncrypted === false ? "Nicht aktiv" : "Unbekannt"}</td><td>${escape(deviceState(device))}</td></tr>`;
    }).join("") : '<tr><td colspan="6">Keine Geräte in dieser Vorschau.</td></tr>'}</tbody></table></div>`;
  }

  function setup(ctx, status, busy) {
    if (!model.setup) return "";
    const e = ctx.escape;
    const external = status.configurationSource === "server";
    const allowed = ctx.authenticated && status.canManage && status.setupTransportAllowed && !external;
    return `<section class="intune-setup" aria-label="Intune einrichten">
      <div class="intune-preview-heading"><h4>Intune einrichten</h4><button class="quiet-button" type="button" data-intune="setup-close" ${model.busy ? "disabled" : ""}>Schließen</button></div>
      <div class="intune-setup-links"><a href="https://entra.microsoft.com/" target="_blank" rel="noopener noreferrer">Microsoft Entra öffnen ↗</a><a href="https://intune.microsoft.com/" target="_blank" rel="noopener noreferrer">Intune-Verwaltung öffnen ↗</a></div>
      <dl class="intune-setup-requirements"><div><dt>Microsoft-App</dt><dd>App-Registrierung im Kundenmandanten · aktive Intune-Lizenz</dd></div><div><dt>API-Berechtigung</dt><dd>Microsoft Graph · Application · <code>DeviceManagementManagedDevices.Read.All</code> · Administratorfreigabe</dd></div></dl>
      <a class="intune-doc-link" href="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app" target="_blank" rel="noopener noreferrer">Microsoft-Anleitung zur App-Registrierung ↗</a>
      ${!ctx.authenticated ? '<p class="intune-notice">Einrichtung nur für angemeldete Plattform-Administratoren.</p><a class="intune-login-link" href="#account">An der Plattform anmelden →</a>' : !status.canManage ? '<p class="intune-notice">Für die Einrichtung ist die Administratorrolle in diesem Kundenraum erforderlich.</p>' : ""}
      ${ctx.authenticated && status.setupTransportAllowed === false ? '<p role="alert" class="intune-error">Für App-Zugangsdaten ist HTTPS erforderlich. Lokal ist localhost erlaubt.</p>' : ""}
      ${external ? '<p class="intune-notice">Dieser Zugang wird durch den Serverbetreiber verwaltet. Änderungen erfolgen in der Serverkonfiguration.</p>' : ""}
      <form data-intune-configure autocomplete="off">
        <input type="hidden" name="expectedVersion" value="${e(status.configurationVersion || "")}">
        <fieldset ${!allowed || busy ? "disabled" : ""}><legend>Zugang für ${e(ctx.tenantName)}</legend>
          <div class="intune-config-fields">
            <label>Microsoft-Mandanten-ID (Tenant-ID)<input name="tenantId" value="${e(status.microsoftTenantId || "")}" required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" spellcheck="false" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></label>
            <label>Anwendungs-ID (Client-ID)<input name="clientId" value="${e(status.clientId || "")}" required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" spellcheck="false" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></label>
            <label>Client-Secret · Wert, nicht ID<input name="clientSecret" type="password" required maxlength="4096" autocomplete="new-password" spellcheck="false" aria-describedby="intune-secret-note"></label>
          </div>
          <p id="intune-secret-note" class="intune-notice">Kein Microsoft-Passwort. Der App-Schlüssel wird serverseitig verschlüsselt gespeichert und nicht erneut angezeigt.</p>
          ${status.configured ? '<p class="intune-notice">Ein neuer Zugang ersetzt die bisherige Konfiguration. Die Automatik wird pausiert; vorhandene Assets bleiben erhalten.</p>' : ""}
          <button class="primary-button" type="submit">${ctx.icon("shield")} ${status.workerEnabled ? "Speichern und Verbindung testen" : "Zugang speichern"}</button>
        </fieldset>
      </form>
      ${allowed && status.configured ? `<div class="intune-disconnect">${model.confirmDisconnect ? '<p>Zugang entfernen und Automatik pausieren? Bereits importierte Assets bleiben erhalten. Die Microsoft-App wird nicht gelöscht.</p><button class="quiet-button" type="button" data-intune="disconnect">Zugang jetzt entfernen</button><button class="quiet-button" type="button" data-intune="disconnect-cancel">Abbrechen</button>' : `<button class="quiet-button" type="button" data-intune="disconnect-confirm" ${busy ? "disabled" : ""}>Zugang entfernen</button>`}</div>` : ""}
    </section>`;
  }

  function content(ctx) {
    const e = ctx.escape;
    const status = model.status || {};
    const pending = ["queued", "running", "retry"].includes(status.job?.status);
    const busy = model.busy || pending;
    const preview = model.demo ? { devices: demoDevices.map(device => ({ action: "new", device })), counts: { new: 3, updated: 0, unchanged: 0, missing: 0 }, total: 3 } : status.preview;
    const conflict = !model.demo && preview && preview.revision !== preview.currentRevision;
    const canImport = navigator.onLine && ctx.authenticated && status.canManage && status.configured && status.workerEnabled;
    const label = model.demo ? "Testvorschau" : status.lastError || status.configurationError || model.error ? "Prüfung nötig" : status.lastSuccessAt ? status.enabled ? "Automatisch · stündlich" : "Verbunden · manuell" : status.verifiedAt || status.preview ? "Microsoft-Zugriff geprüft · noch nicht importiert" : status.configured ? "Zugang gespeichert · noch nicht geprüft" : "Nicht verbunden";
    return `<header class="intune-heading"><div class="intune-title"><span aria-hidden="true">${ctx.icon("database")}</span><div><h3>Microsoft Intune</h3><span class="intune-state">${e(label)}</span></div></div><div class="intune-actions"><button type="button" class="quiet-button" data-intune="toggle" aria-expanded="${!!model.open}">${model.open ? "Schließen" : "Verbindung öffnen"}</button><button type="button" class="quiet-button" data-intune="demo" ${model.busy ? "disabled" : ""}>Testvorschau</button></div></header>
    ${model.open ? `<div class="intune-body">
      <dl class="intune-status-grid"><div><dt>Kundenraum</dt><dd>${e(ctx.tenantName)}</dd></div><div><dt>Letzte Übernahme · Berlin</dt><dd>${e(date(status.lastSuccessAt))}</dd></div><div><dt>Nächster Abruf · Berlin</dt><dd>${status.enabled ? e(date(status.nextRunAt)) : "Automatik pausiert"}</dd></div></dl>
      ${!ctx.authenticated ? '<p class="intune-notice">Nicht am Server angemeldet. <a href="#account">An der Plattform anmelden →</a></p>' : ""}
      ${status.configurationError ? `<p role="alert" class="intune-error">${e(status.configurationError)}</p>` : ""}
      ${!status.configured ? '<p class="intune-notice">Microsoft-Freigabe ausstehend: Intune-Lizenz, Tenant-ID, App-ID und serverseitiger App-Zugang.</p>' : `<p class="intune-notice">Microsoft-Mandant: ${e(status.microsoftTenantId)} · Leseberechtigung</p>`}
      ${model.error || status.lastError || status.job?.last_error ? `<p role="alert" class="intune-error">${e(model.error || status.lastError || status.job.last_error)}</p>` : ""}
      ${pending ? '<p role="status">Geräteabruf läuft im Hintergrund …</p>' : ""}
      <div class="intune-actions"><button type="button" class="quiet-button" data-intune="setup" ${busy ? "disabled" : ""}>${ctx.icon("settings")} ${status.configured ? "App-Konfiguration" : "Microsoft-Zugang einrichten"}</button>${canImport ? `<button type="button" class="quiet-button" data-intune="preview" ${busy ? "disabled" : ""}>Verbindung testen</button>` : ""}</div>
      ${setup(ctx, status, busy)}
      <div class="intune-actions"><button type="button" class="primary-button" data-intune="preview" ${!canImport || busy ? "disabled" : ""}>${ctx.icon("refresh")} Geräte abrufen</button><button type="button" class="quiet-button" data-intune="refresh" ${!ctx.authenticated || model.busy ? "disabled" : ""}>Status aktualisieren</button><label class="intune-schedule"><input type="checkbox" data-intune-schedule ${status.enabled ? "checked" : ""} ${!status.canManage || !status.lastSuccessAt || !status.workerEnabled || model.busy ? "disabled" : ""}> Stündlich synchronisieren</label></div>
      ${preview ? `<section class="intune-preview" aria-label="Importvorschau"><div class="intune-preview-heading"><h4>${model.demo ? model.simulated ? "Test-Asset-Register" : "Testvorschau · keine Microsoft-Verbindung" : "Importvorschau"}</h4><span>${preview.total} Einträge${preview.total > 100 ? " · erste 100 angezeigt" : ""}</span></div>
        <div class="intune-counts">${Object.entries(preview.counts).map(([key, count]) => `<span><strong>${count}</strong> ${e(actionLabels[key])}</span>`).join("")}</div>
        ${table(preview.devices, e, model.simulated)}
        <p class="intune-notice">${model.demo ? "Fiktive Geräte. Keine Speicherung im Kundenregister und keine automatische Synchronisierung." : "Übernahme technischer Gerätedaten. Owner, Kritikalität und fachliche Freigabe bleiben unverändert."}</p>
        ${conflict ? '<p role="alert" class="intune-error">Workspace zwischenzeitlich geändert. Neue Vorschau erforderlich.</p>' : ""}
        <div class="intune-actions"><button type="button" class="primary-button" data-intune="apply" ${model.simulated || busy || conflict || (!model.demo && !canImport) ? "disabled" : ""}>${model.demo ? "Übernahme simulieren" : "Ins Asset-Register übernehmen"}</button><button type="button" class="quiet-button" data-intune="discard" ${model.busy ? "disabled" : ""}>Vorschau schließen</button></div>
      </section>` : ""}
      ${model.success ? `<p role="status" class="intune-success">${e(model.success)}</p>` : ""}
    </div>` : ""}`;
  }

  function render(ctx) {
    if (scope !== ctx.scope) {
      clearTimeout(timer);
      scope = ctx.scope;
      model = { open: ctx.expanded, busy: false, status: null, demo: false };
    }
    return `<section class="intune-widget" aria-label="Microsoft Intune">${content(ctx)}</section>`;
  }

  function mount(root, ctx) {
    if (!root) return;
    clearTimeout(timer);
    const captured = scope;
    const sameScope = () => captured === scope && ctx.isCurrent();
    const valid = () => sameScope() && root.isConnected;
    const update = () => {
      if (!valid()) return;
      // Preserve an edited form during status refreshes, never serialize its secret into state.
      const form = root.querySelector("[data-intune-configure]");
      const preserve = model.setup && !model.busy && form?.dataset.dirty;
      root.innerHTML = content(ctx);
      if (preserve) root.querySelector("[data-intune-configure]")?.replaceWith(form);
    };
    paint = update;
    async function refresh() {
      if (!ctx.authenticated || !valid()) return;
      if (!navigator.onLine) {
        model.error = "Offline. Letzter Datenstand bleibt erhalten.";
        update();
        return;
      }
      try {
        const status = await ctx.request("/api/integrations/intune", { cache: "no-store" });
        if (!valid()) return;
        model.status = status;
        model.error = "";
        if (status.lastError || status.job?.last_error) model.success = "";
        else if (status.preview && !model.demo) model.success = "Microsoft-Zugriff geprüft. Die Vorschau wurde noch nicht ins Asset-Register übernommen.";
      } catch (error) {
        if (!valid()) return;
        model.error = error.status === 404 ? "Server benötigt ein Update für die Intune-Anbindung." : error.message;
      }
      update();
      if (valid() && ["queued", "retry", "running"].includes(model.status?.job?.status)) timer = setTimeout(refresh, 3000);
    }
    async function perform(action, value) {
      if (model.busy || !valid()) return;
      model.busy = true;
      model.error = "";
      model.success = "";
      update();
      try {
        if (action === "apply" && model.demo) {
          model.simulated = true;
          model.success = "3 Test-Assets in der Vorschau. Kundenregister unverändert.";
          return;
        }
        if (action === "apply" && !ctx.canReload()) throw new Error("Lokale Änderungen zuerst speichern oder abgleichen. Es wurde nichts importiert.");
        const payload = action === "configure" ? value : action === "disconnect" ? { expectedVersion: model.disconnectVersion } : action === "apply" ? { previewId: model.status.preview.id } : action === "schedule" ? { enabled: value } : {};
        await ctx.request(`/api/integrations/intune/${action}`, { method: "POST", json: payload });
        if (!sameScope()) return;
        model.demo = false;
        if (action === "configure" || action === "disconnect") {
          model.setup = false;
          model.confirmDisconnect = false;
          model.success = action === "configure" ? "Zugang gespeichert. Microsoft-Zugriff noch nicht bestätigt." : "Zugang entfernt. Vorhandene Assets bleiben erhalten.";
          await refresh();
          if (!sameScope()) return;
          if (action === "configure" && model.status.workerEnabled) {
            await ctx.request("/api/integrations/intune/preview", { method: "POST", json: {} });
            if (!sameScope()) return;
            model.success = "Zugang gespeichert. Verbindungstest läuft; noch keine Assets übernommen.";
          }
        }
        if (action === "apply") {
          model.success = "Intune-Geräte wurden ins Asset-Register übernommen.";
          model.busy = false;
          await ctx.reload();
          return;
        }
        await refresh();
      } catch (error) {
        if (valid()) model.error = error.message || "Intune-Anfrage fehlgeschlagen.";
      } finally {
        if (sameScope()) { model.busy = false; paint(); }
      }
    }
    root.onclick = event => {
      const button = event.target.closest("[data-intune]");
      if (!button || button.disabled) return;
      const action = button.dataset.intune;
      if (action === "toggle") { model.open = !model.open; update(); }
      else if (action === "demo") { model.open = true; model.demo = true; model.simulated = false; model.success = ""; update(); }
      else if (action === "discard") { model.demo = false; model.simulated = false; if (model.status) model.status.preview = null; model.success = ""; update(); }
      else if (action === "setup") { model.setup = true; model.demo = false; model.confirmDisconnect = false; update(); }
      else if (action === "setup-close") { model.setup = false; model.confirmDisconnect = false; update(); }
      else if (action === "disconnect-confirm") { model.confirmDisconnect = true; model.disconnectVersion = model.status.configurationVersion; update(); }
      else if (action === "disconnect-cancel") { model.confirmDisconnect = false; update(); }
      else if (action === "refresh") refresh();
      else perform(action);
    };
    root.oninput = event => {
      const form = event.target.closest("[data-intune-configure]");
      if (form) form.dataset.dirty = "true";
    };
    root.onsubmit = event => {
      const form = event.target.closest("[data-intune-configure]");
      if (!form) return;
      event.preventDefault();
      if (model.busy || !form.reportValidity()) return;
      const payload = Object.fromEntries(new FormData(form));
      form.elements.clientSecret.value = "";
      delete form.dataset.dirty;
      perform("configure", payload);
    };
    root.onchange = event => {
      if (event.target.matches("[data-intune-schedule]")) perform("schedule", event.target.checked);
    };
    refreshActive = refresh;
    refresh();
  }

  function sourceDetails(asset, escape) {
    if (!asset.intune?.device) return "";
    const source = asset.intune;
    return `<section class="register-detail-section intune-source"><h4>Microsoft Intune · technische Quelle</h4><dl class="intune-status-grid"><div><dt>Letzte Übernahme · Berlin</dt><dd>${escape(date(source.syncedAt))}</dd></div><div><dt>Letzter Gerätekontakt · Berlin</dt><dd>${escape(date(source.device.lastSyncDateTime))}</dd></div><div><dt>Quellenstatus</dt><dd>${source.missingSince ? "Nicht mehr in Intune gemeldet" : "Im letzten Abruf enthalten"}</dd></div></dl>${table([{ device: source.device, action: "unchanged" }], escape)}<p class="intune-notice">Intune-Gerätestatus ist keine fachliche Compliance-Freigabe.</p></section>`;
  }
  window.SFMIntune = { render, mount, sourceDetails };
})();
