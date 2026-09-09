const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { chromium } = require("playwright");
const { assertResponsiveLayout, assertExecutiveData, assertWorkspaceInteractions } = require("./ui_quality.cjs");
const { assertIntuneUi } = require("./intune_ui.cjs");

const ROOT = path.resolve(__dirname, "..");
const BACKEND = path.join(ROOT, "backend_app.py");
const FRONTEND = path.join(ROOT, "frontend-current");
const CONFIGURED_CHROME = process.env.SFM_CHROME_PATH || "";
const SCREENSHOT_DIR = process.env.SFM_E2E_SCREENSHOT_DIR || "";
const MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const ADMIN_PASSWORD = "E2E-Admin-Password-2026!";

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitForHealth(baseUrl, serverProcess) {
  const deadline = Date.now() + 15_000;
  let lastError = null;
  while (Date.now() < deadline) {
    if (serverProcess.exitCode !== null) {
      throw new Error(`Isolated backend stopped with code ${serverProcess.exitCode}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      const payload = await response.json();
      if (response.ok && payload.ok) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Isolated backend did not become ready: ${lastError || "timeout"}`);
}

async function stopProcess(processHandle) {
  if (!processHandle || processHandle.exitCode !== null || processHandle.signalCode !== null) return;
  await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(forceKillTimer);
      clearTimeout(giveUpTimer);
      resolve();
    };
    processHandle.once("exit", finish);
    const forceKillTimer = setTimeout(() => {
      if (processHandle.exitCode === null && processHandle.signalCode === null) {
        processHandle.kill("SIGKILL");
      }
    }, 3000);
    const giveUpTimer = setTimeout(finish, 5000);
    processHandle.kill("SIGTERM");
    if (processHandle.exitCode !== null || processHandle.signalCode !== null) finish();
  });
}

async function assertNoHorizontalOverflow(page, label) {
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
    app: document.querySelector(".app-shell")?.scrollWidth || 0,
  }));
  const widest = Math.max(dimensions.document, dimensions.body, dimensions.app);
  assert.ok(
    widest <= dimensions.viewport + 2,
    `${label} overflows horizontally: viewport=${dimensions.viewport}, widest=${widest}`
  );
}

async function assertPageIntegrity(page, label) {
  const audit = await page.evaluate(() => {
    const visible = (node) => {
      const rect = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden"
        && node.checkVisibility({ checkVisibilityCSS: true });
    };
    const ids = [...document.querySelectorAll("[id]")].map((node) => node.id).filter(Boolean);
    const duplicateIds = [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))];
    const buttonLabel = (button) => (
      String(button.textContent || "").trim()
      || String(button.getAttribute("aria-label") || "").trim()
      || String(button.getAttribute("title") || "").trim()
    );
    const unnamedButtons = [...document.querySelectorAll("button")]
      .filter(visible)
      .filter((button) => !buttonLabel(button))
      .map((button) => button.outerHTML.slice(0, 180));
    const unboundButtons = [...document.querySelectorAll("button")]
      .filter(visible)
      .filter((button) => (
        !button.disabled
        && !button.id
        && !button.closest("form")
        && button.type !== "submit"
        && !button.getAttribute("onclick")
        && ![...button.attributes].some((attribute) => attribute.name.startsWith("data-"))
      ))
      .map((button) => buttonLabel(button) || button.outerHTML.slice(0, 180));
    const brokenImages = [...document.images]
      .filter(visible)
      .filter((image) => !image.complete || image.naturalWidth === 0)
      .map((image) => image.src);
    return { duplicateIds, unnamedButtons, unboundButtons, brokenImages };
  });
  assert.deepEqual(audit.duplicateIds, [], `${label} contains duplicate IDs: ${audit.duplicateIds.join(", ")}`);
  assert.deepEqual(audit.unnamedButtons, [], `${label} contains unnamed buttons: ${audit.unnamedButtons.join("\n")}`);
  assert.deepEqual(audit.unboundButtons, [], `${label} contains visually interactive buttons without an action marker: ${audit.unboundButtons.join("\n")}`);
  assert.deepEqual(audit.brokenImages, [], `${label} contains broken images: ${audit.brokenImages.join(", ")}`);
  await assertNoHorizontalOverflow(page, label);
  await assertResponsiveLayout(page, label);
  if (SCREENSHOT_DIR) {
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      document.querySelector(".main")?.scrollTo(0, 0);
    });
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, `${label.replace(/[^a-z0-9-]/gi, "-")}.png`) });
  }
}

async function run() {
  const executablePath = CONFIGURED_CHROME
    ? CONFIGURED_CHROME
    : fs.existsSync(MAC_CHROME)
      ? MAC_CHROME
      : "";
  if (CONFIGURED_CHROME) {
    assert.ok(fs.existsSync(CONFIGURED_CHROME), `Chrome executable not found: ${CONFIGURED_CHROME}`);
  }
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sfm-compliance-e2e-"));
  const port = await reservePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const serverProcess = spawn(process.env.SFM_PYTHON || "python3", [BACKEND], {
    cwd: ROOT,
    env: {
      ...process.env,
      ISMS_HOST: "127.0.0.1",
      ISMS_PORT: String(port),
      ISMS_PUBLIC_URL: baseUrl,
      ISMS_STATIC_BASE: FRONTEND,
      ISMS_DATA_DIR: tempDir,
      ISMS_ADMIN_PASSWORD: ADMIN_PASSWORD,
      ISMS_FILE_KEY: "e2e-file-key-do-not-use-in-production",
      ISMS_COOKIE_SECURE: "0",
      ISMS_HSTS: "0",
      ISMS_OPERATIONS_MONITOR_ENABLED: "0",
      ISMS_NOTIFICATION_DELIVERY_ENABLED: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let browser;
  try {
    await waitForHealth(baseUrl, serverProcess);
    browser = await chromium.launch({
      headless: true,
      ...(executablePath ? { executablePath } : {}),
    });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, timezoneId: "Europe/Berlin" });
    await context.addInitScript(() => {
      localStorage.setItem("isms-catalyst-dashboard-v1", "{corrupted-test-state");
    });
    const page = await context.newPage();
    let liveContext = null;
    const browserErrors = [];
    let expectUnauthorizedConsole = false;
    let expectConflictConsole = false;
    page.on("pageerror", (error) => browserErrors.push(`pageerror: ${error.message}`));
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      if (expectUnauthorizedConsole && message.text().includes("401")) return;
      if (expectConflictConsole && message.text().includes("409")) return;
      browserErrors.push(`console: ${message.text()}`);
    });

    await page.goto(`${baseUrl}/#dashboard`, { waitUntil: "domcontentloaded" });
    await page.locator("[data-backend-login]").waitFor();
    await page.locator('[data-backend-login] input[name="username"]').fill("admin");
    await page.locator('[data-backend-login] input[name="password"]').fill(ADMIN_PASSWORD);
    await page.locator('[data-backend-login] button[type="submit"]').click();
    await page.locator(".backend-panel", { hasText: "Arbeitsbereich verbunden" }).waitFor();
    await page.locator(".top-status-chip.live", { hasText: "Live verbunden" }).waitFor();
    await page.locator("#viewTitle").filter({ hasText: "Dashboard" }).waitFor();
    await assertNoHorizontalOverflow(page, "Dashboard desktop");
    await assertExecutiveData(page, baseUrl);
    await assertWorkspaceInteractions(page, baseUrl);
    await assertIntuneUi(page, baseUrl);

    const platformViews = [
      "dashboard", "executive", "clients", "notifications", "guided", "project", "iso", "nis2",
      "documents", "review", "auditpackage", "audit", "capa", "soa", "templates", "assets", "risks", "legal",
      "suppliers", "policies", "incidents", "contracts", "integrations", "team", "account", "production",
      "operations", "jobs", "backup", "lifecycle", "audittrail", "quarantine", "tasks", "managementreview", "consultant",
    ];
    for (const view of platformViews) {
      await page.goto(`${baseUrl}/#${view}`, { waitUntil: "domcontentloaded" });
      await page.locator(`#appView[data-view="${view}"]`).waitFor();
      await assertPageIntegrity(page, `${view} desktop`);
    }

    const invitationEmail = `e2e-team-${Date.now()}@example.test`;
    await page.goto(`${baseUrl}/#team`, { waitUntil: "domcontentloaded" });
    const invitationForm = page.locator("[data-admin-create-invitation]");
    await invitationForm.waitFor();
    await invitationForm.locator('input[name="displayName"]').fill("E2E Teammitglied");
    await invitationForm.locator('input[name="email"]').fill(invitationEmail);
    await invitationForm.locator('select[name="role"]').selectOption("customer");
    await invitationForm.locator('button[type="submit"]').click();
    const invitationRow = page.locator(".team-invitation-row", { hasText: invitationEmail });
    await invitationRow.waitFor();
    await invitationRow.getByText("Link manuell teilen", { exact: true }).waitFor();
    const firstInvitationText = await page.locator("[data-invitation-text]").inputValue();
    assert.match(firstInvitationText, /Einladungslink: http:\/\/127\.0\.0\.1:/);

    await invitationRow.getByRole("button", { name: "Neuen Link erzeugen" }).click();
    await page.locator("[data-invitation-text]").waitFor();
    await page.waitForFunction((previous) => {
      const value = document.querySelector("[data-invitation-text]")?.value || "";
      return Boolean(value) && value !== previous;
    }, firstInvitationText);
    const secondInvitationText = await page.locator("[data-invitation-text]").inputValue();
    assert.notEqual(secondInvitationText, firstInvitationText, "Resend must rotate the invitation link");

    const refreshedInvitationRow = page.locator(".team-invitation-row", { hasText: invitationEmail });
    await refreshedInvitationRow.getByRole("button", { name: "Widerrufen" }).click();
    await page.locator(".team-invitation-row", { hasText: invitationEmail }).getByText("widerrufen", { exact: true }).waitFor();
    await assertPageIntegrity(page, "Team invitation workflow desktop");

    await page.goto(`${baseUrl}/#dashboard`, { waitUntil: "domcontentloaded" });

    const saveQueueResult = await page.evaluate(async () => {
      const results = await Promise.all([
        window.saveWorkspaceToBackend(),
        window.saveWorkspaceToBackend(),
        window.saveWorkspaceToBackend(),
      ]);
      return {
        results,
        conflictVisible: Boolean(document.querySelector(".workspace-conflict-banner")),
        status: document.querySelector("[data-backend-sync-status]")?.textContent || "",
      };
    });
    assert.deepEqual(saveQueueResult.results, [true, true, true]);
    assert.equal(saveQueueResult.conflictVisible, false);
    assert.match(saveQueueResult.status, /Gespeichert|Verbunden/);

    await context.setOffline(true);
    await page.waitForFunction(() => navigator.onLine === false);
    await page.locator(".workspace-connectivity-banner").waitFor();
    const offlineSaveResult = await page.evaluate(() => window.saveWorkspaceToBackend());
    assert.equal(offlineSaveResult, false);
    await page.locator("[data-backend-sync-status]").filter({ hasText: "Offline - lokal gesichert" }).first().waitFor();
    await assertNoHorizontalOverflow(page, "Offline banner desktop");

    await context.setOffline(false);
    await page.waitForFunction(() => navigator.onLine === true);
    await page.locator(".workspace-connectivity-banner").waitFor({ state: "detached" });
    await page.locator("[data-backend-sync-status]").filter({ hasText: /Gespeichert|Verbunden/ }).first().waitFor();

    const logoutStatus = await page.evaluate(async () => {
      const session = await fetch("/api/session", { cache: "no-store" }).then((response) => response.json());
      const response = await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "X-CSRF-Token": session.csrfToken || "" },
      });
      return response.status;
    });
    assert.equal(logoutStatus, 200);
    expectUnauthorizedConsole = true;
    const expiredSaveResult = await page.evaluate(() => window.saveWorkspaceToBackend());
    assert.equal(expiredSaveResult, false);
    await page.locator(".session-expired-banner").waitFor();
    await page.locator("[data-backend-sync-status]").filter({ hasText: "Sitzung abgelaufen" }).first().waitFor();
    await assertNoHorizontalOverflow(page, "Expired session banner desktop");

    await page.locator('[data-session-reauth] input[name="password"]').fill(ADMIN_PASSWORD);
    await page.locator('[data-session-reauth] button[type="submit"]').click();
    await page.locator(".session-expired-banner").waitFor({ state: "detached" });
    await page.locator("[data-backend-sync-status]").filter({ hasText: /Gespeichert|Verbunden/ }).first().waitFor();
    expectUnauthorizedConsole = false;

    const pendingBeforeReload = await page.evaluate(() => {
      window.saveState();
      return Object.keys(localStorage).filter((key) => key.startsWith("sfm-compliance-pending-workspace-v1:")).length;
    });
    assert.equal(pendingBeforeReload, 1);
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.locator("#viewTitle").filter({ hasText: "Dashboard" }).waitFor();
    await page.locator("[data-backend-sync-status]").filter({ hasText: /Gespeichert|Verbunden/ }).first().waitFor();
    await page.waitForFunction(() => !Object.keys(localStorage).some((key) => key.startsWith("sfm-compliance-pending-workspace-v1:")));

    liveContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    const livePage = await liveContext.newPage();
    await livePage.goto(`${baseUrl}/#dashboard`, { waitUntil: "domcontentloaded" });
    await livePage.locator("[data-backend-login]").waitFor();
    await livePage.locator('[data-backend-login] input[name="username"]').fill("admin");
    await livePage.locator('[data-backend-login] input[name="password"]').fill(ADMIN_PASSWORD);
    await livePage.locator('[data-backend-login] button[type="submit"]').click();
    await livePage.locator(".top-status-chip.live", { hasText: "Live verbunden" }).waitFor();

    await page.goto(`${baseUrl}/#tasks`, { waitUntil: "domcontentloaded" });
    const liveRevision = await livePage.evaluate(async () => {
      const session = await fetch("/api/session", { cache: "no-store" }).then((response) => response.json());
      const workspace = await fetch("/api/state", { cache: "no-store" }).then((response) => response.json());
      workspace.state.tasks.push({
        id: "e2e-live-sync-task",
        title: "E2E Live Sync Aufgabe",
        module: "Task Management",
        owner: "E2E",
        status: "Offen",
      });
      const response = await fetch("/api/state", {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrfToken || "" },
        body: JSON.stringify({ state: workspace.state, expectedRevision: workspace.revision }),
      });
      const payload = await response.json();
      return { status: response.status, revision: payload.revision };
    });
    assert.equal(liveRevision.status, 200);
    await page.getByText("E2E Live Sync Aufgabe", { exact: true }).first().waitFor({ timeout: 8_000 });
    const synchronizedRevision = await page.evaluate(() => backendSync.revision);
    assert.equal(synchronizedRevision, liveRevision.revision);
    await assertNoHorizontalOverflow(page, "Live synchronized task view");

    await page.locator('[data-view="assets"]').click();
    await page.waitForURL(/#assets$/);

    await context.setOffline(true);
    await page.waitForFunction(() => navigator.onLine === false);
    await page.locator('[data-form="asset"] input[name="name"]').fill("Lokales Merge Asset");
    await page.locator('[data-form="asset"] button[type="submit"]').click();
    await page.getByText("Lokales Merge Asset", { exact: true }).first().waitFor();
    const conflictingRemoteRevision = await livePage.evaluate(async () => {
      const session = await fetch("/api/session", { cache: "no-store" }).then((response) => response.json());
      const workspace = await fetch("/api/state", { cache: "no-store" }).then((response) => response.json());
      workspace.state.tasks.push({
        id: "e2e-conflict-task",
        title: "E2E parallele Änderung",
        module: "Task Management",
        owner: "E2E",
        status: "Offen",
      });
      const response = await fetch("/api/state", {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": session.csrfToken || "" },
        body: JSON.stringify({ state: workspace.state, expectedRevision: workspace.revision }),
      });
      const payload = await response.json();
      return { status: response.status, revision: payload.revision };
    });
    assert.equal(conflictingRemoteRevision.status, 200);
    expectConflictConsole = true;
    await context.setOffline(false);
    await page.waitForFunction(() => navigator.onLine === true);
    await page.locator(".workspace-conflict-banner").waitFor();
    await page.locator("[data-conflict-compare]").click();
    await page.locator(".workspace-conflict-comparison").waitFor();
    await page.locator('[data-conflict-merge-form] select[name="assets"]').selectOption("local");
    await page.locator('[data-conflict-merge-form] button[type="submit"]').click();
    await page.locator(".workspace-conflict-banner").waitFor({ state: "detached" });
    await page.locator(".workspace-conflict-comparison").waitFor({ state: "detached" });
    const mergedAssetStored = await page.evaluate(async () => {
      const workspace = await fetch("/api/state", { cache: "no-store" }).then((response) => response.json());
      return workspace.state.assets.some((asset) => asset.name === "Lokales Merge Asset");
    });
    expectConflictConsole = false;
    assert.equal(mergedAssetStored, true);
    await assertNoHorizontalOverflow(page, "Conflict merge desktop");

    await page.locator('[data-view="dashboard"]').click();
    await page.waitForURL(/#dashboard$/);

    await page.locator("#languageTrigger").click();
    await page.locator('[data-language-option="en"]').click();
    await page.locator("#languageCurrent").filter({ hasText: "English" }).waitFor();
    await page.locator("#viewSubtitle").filter({ hasText: "Tool hub" }).waitFor();
    assert.equal(await page.evaluate(() => localStorage.getItem("sfm-compliance-language")), "en");
    await page.locator("#languageTrigger").click();
    await page.locator('[data-language-option="de"]').click();
    await page.locator("#languageCurrent").filter({ hasText: "Deutsch" }).waitFor();
    await page.locator("#viewSubtitle").filter({ hasText: "Tool-Zentrale" }).waitFor();

    await page.locator('[data-view="review"]').click();
    await page.waitForURL(/#review$/);
    await page.getByRole("heading", { name: "Review Center", exact: true }).waitFor();
    await page.getByText("Review-Auslastung", { exact: true }).waitFor();
    await page.getByText("Sichtbare Warteschlange terminieren", { exact: true }).waitFor();
    await page.getByRole("button", { name: /mir zuweisen/ }).waitFor();
    await assertNoHorizontalOverflow(page, "Review Center desktop");

    await page.locator('[data-view="auditpackage"]').click();
    await page.waitForURL(/#auditpackage$/);
    await page.getByRole("heading", { name: "Auditpaket-Bericht vorbereiten", exact: true }).waitFor();
    await page.getByText(/die fachliche Freigabe bleibt beim Berater\/Admin/i).waitFor();
    await page.getByText("Explizite Beraterfreigabe", { exact: true }).waitFor();
    await assertNoHorizontalOverflow(page, "Audit package desktop");

    await page.locator('[data-view="soa"]').click();
    await page.waitForURL(/#soa$/);
    await page.getByRole("heading", { name: "Annex-A-Controls wie ein Register pflegen", exact: true }).waitFor();
    await page.getByText("SoA-Tabelle", { exact: true }).waitFor();
    await page.getByRole("heading", { name: "93 Controls angezeigt", exact: true }).waitFor();
    const soaControlRow = page.locator('[data-soa-row="A.8.34"]');
    const soaOwner = soaControlRow.locator('[data-soa-field="owner"]');
    await soaOwner.fill("E2E ISB / Audit");
    await soaOwner.blur();
    await page.waitForFunction(async () => {
      const response = await fetch("/api/soa", { cache: "no-store" });
      if (!response.ok) return false;
      const payload = await response.json();
      return payload.soa?.some((record) => record.controlId === "A.8.34" && record.owner === "E2E ISB / Audit");
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForURL(/#soa$/);
    await page.getByRole("heading", { name: "93 Controls angezeigt", exact: true }).waitFor();
    await page.waitForFunction(() => document.querySelector('[data-soa-row="A.8.34"] [data-soa-field="owner"]')?.value === "E2E ISB / Audit");
    await assertNoHorizontalOverflow(page, "SoA desktop");

    await page.goto(`${baseUrl}/#audit`, { waitUntil: "domcontentloaded" });
    const auditPlanForm = page.locator("form[data-internal-audit-plan-form]");
    await auditPlanForm.waitFor();
    await auditPlanForm.locator('input[name="title"]').fill("E2E Interne Auditplanung 2026");
    await auditPlanForm.locator('input[name="auditPeriod"]').fill("Q3 2026");
    await auditPlanForm.locator('input[name="plannedDate"]').fill("2026-09-15");
    await auditPlanForm.locator('input[name="leadAuditor"]').fill("E2E Interne Revision");
    await auditPlanForm.locator('textarea[name="scope"]').fill("E2E Hauptstandort, Kernprozesse und Cloud-Dienste");
    await auditPlanForm.locator('textarea[name="objectives"]').fill("E2E Umsetzungsstand und Wirksamkeit prüfen");
    await auditPlanForm.locator('textarea[name="criteria"]').fill("E2E Freigegebene interne Vorgaben und Verfahren");
    await auditPlanForm.locator('select[name="reviewStatus"]').selectOption("in_beraterpruefung");
    await auditPlanForm.locator('input[name="auditRelevant"]').check();
    const auditPlanSave = page.waitForResponse((response) => (
      response.url().endsWith("/api/internal-audit-plan")
      && response.request().method() === "PATCH"
    ));
    await auditPlanForm.locator('button[type="submit"]').click();
    assert.equal((await auditPlanSave).status(), 200, "Internal audit plan API save must succeed");
    const storedAuditPlanTitle = await page.evaluate(async () => {
      const response = await fetch("/api/state", { cache: "no-store" });
      const payload = await response.json();
      return payload.state?.internalAuditPlan?.title || "";
    });
    assert.equal(storedAuditPlanTitle, "E2E Interne Auditplanung 2026", "Backend must persist internal audit plan");
    const pendingAuditPlanSaves = await page.evaluate(() => (
      Object.keys(localStorage).filter((key) => key.startsWith("sfm-compliance-pending-workspace-v1:")).length
    ));
    assert.equal(pendingAuditPlanSaves, 0, "Internal audit plan save must not leave a stale pending workspace");
    const auditPlanReloadState = page.waitForResponse((response) => (
      response.url().endsWith("/api/state") && response.request().method() === "GET"
    ));
    await page.reload({ waitUntil: "domcontentloaded" });
    const reloadedAuditPlanState = await (await auditPlanReloadState).json();
    assert.equal(
      reloadedAuditPlanState.state?.internalAuditPlan?.title,
      "E2E Interne Auditplanung 2026",
      "Reloaded workspace state must contain internal audit plan"
    );
    const normalizedAuditPlanTitle = await page.evaluate((workspace) => (
      normalizeState(workspace).internalAuditPlan?.title || ""
    ), reloadedAuditPlanState.state);
    assert.equal(normalizedAuditPlanTitle, "E2E Interne Auditplanung 2026", "Frontend normalization must retain internal audit plan");
    await page.waitForURL(/#audit$/);
    await page.waitForFunction(() => backendSync.loaded === true && backendSync.mode === "backend");
    const activeAuditPlanTitle = await page.evaluate(() => state.internalAuditPlan?.title || "");
    assert.equal(activeAuditPlanTitle, "E2E Interne Auditplanung 2026", "Active frontend state must load internal audit plan");
    await page.waitForFunction(() => (
      document.querySelector('form[data-internal-audit-plan-form] input[name="title"]')?.value
        === state.internalAuditPlan?.title
    ));
    assert.equal(
      await page.locator('form[data-internal-audit-plan-form] input[name="title"]').inputValue(),
      "E2E Interne Auditplanung 2026",
      "Internal audit plan must persist after reload"
    );
    const auditPlanLayout = await page.evaluate(() => {
      const section = document.querySelector("[data-internal-audit-plan]");
      const head = section?.querySelector(".internal-audit-plan-head");
      const form = document.querySelector("[data-internal-audit-plan-form]");
      const sectionRect = section?.getBoundingClientRect();
      const headRect = head?.getBoundingClientRect();
      const formRect = form?.getBoundingClientRect();
      return {
        section: sectionRect ? { top: sectionRect.top, bottom: sectionRect.bottom, width: sectionRect.width } : null,
        head: headRect ? { top: headRect.top, bottom: headRect.bottom, width: headRect.width } : null,
        form: formRect ? { top: formRect.top, bottom: formRect.bottom, width: formRect.width } : null,
        nested: Boolean(section && form && section.contains(form))
      };
    });
    assert.equal(auditPlanLayout.nested, true, "Internal audit plan form must remain inside its panel");
    assert.ok(auditPlanLayout.section.top <= auditPlanLayout.form.top, "Internal audit plan form must start inside its panel");
    assert.ok(auditPlanLayout.section.bottom >= auditPlanLayout.form.bottom, "Internal audit plan panel must contain the complete form");
    assert.ok(auditPlanLayout.form.width >= 600, "Internal audit plan form must retain a readable desktop width");
    assert.ok(
      auditPlanLayout.head.top - auditPlanLayout.section.top <= 40,
      `Internal audit plan must not contain unexplained top whitespace: ${JSON.stringify(auditPlanLayout)}`
    );
    assert.ok(
      auditPlanLayout.form.top - auditPlanLayout.head.bottom <= 220,
      `Internal audit plan sections must remain compact: ${JSON.stringify(auditPlanLayout)}`
    );
    await assertNoHorizontalOverflow(page, "Internal audit plan desktop");
    if (SCREENSHOT_DIR) {
      fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
      await page.locator("[data-internal-audit-plan]").screenshot({
        path: path.join(SCREENSHOT_DIR, "internal-audit-plan-desktop.png"),
        style: ".topbar { visibility: hidden !important; }"
      });
    }
    const findingCreateButton = page.locator("[data-audit-finding-create]").first();
    await findingCreateButton.waitFor();
    await findingCreateButton.click();
    const persistedFinding = page.locator(".audit-finding-record").first();
    await persistedFinding.waitFor();
    await persistedFinding.locator('[data-audit-finding-field="owner"]').fill("E2E Audit Owner");
    await persistedFinding.locator('[data-audit-finding-field="owner"]').blur();
    await page.waitForFunction(async () => {
      const response = await fetch("/api/audit-findings", { cache: "no-store" });
      if (!response.ok) return false;
      const payload = await response.json();
      return payload.auditFindings?.some((finding) => finding.owner === "E2E Audit Owner");
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForURL(/#audit$/);
    await page.waitForFunction(() => [...document.querySelectorAll('[data-audit-finding-field="owner"]')]
      .some((field) => field.value === "E2E Audit Owner"));
    await assertNoHorizontalOverflow(page, "Persisted audit findings desktop");

    await page.goto(`${baseUrl}/#capa`, { waitUntil: "domcontentloaded" });
    const capaCreateForm = page.locator("form[data-capa-create-form]");
    await capaCreateForm.waitFor();
    await capaCreateForm.locator('input[name="title"]').fill("E2E Korrekturmaßnahme MFA");
    await capaCreateForm.locator('input[name="owner"]').fill("E2E IT Security");
    await capaCreateForm.locator('input[name="due"]').fill("2026-12-20");
    await capaCreateForm.locator('textarea[name="nonconformity"]').fill("E2E MFA-Stichprobe war formal unvollständig.");
    const capaCreateResponse = page.waitForResponse((response) => (
      response.url().endsWith("/api/audit-findings") && response.request().method() === "POST"
    ));
    await capaCreateForm.locator('button[type="submit"]').click();
    assert.equal((await capaCreateResponse).status(), 201, "CAPA create API must succeed");
    const capaDetailForm = page.locator("form[data-capa-detail-form]");
    await capaDetailForm.waitFor();
    await capaDetailForm.locator('textarea[name="rootCause"]').fill("E2E Kontrollliste war nicht mit dem IAM-Bestand abgeglichen.");
    await capaDetailForm.locator('textarea[name="correctiveAction"]').fill("E2E Monatlichen automatisierten Bestandsabgleich einführen.");
    await capaDetailForm.locator('textarea[name="effectivenessCriteria"]').fill("E2E Drei fehlerfreie Monatsprüfungen.");
    await capaDetailForm.locator('textarea[name="effectivenessEvidence"]').fill("E2E Monatsreports und Stichprobenliste.");
    await capaDetailForm.locator('textarea[name="effectivenessAssessment"]').fill("E2E Wirksamkeitsbewertung ist zur Prüfung vorbereitet.");
    await capaDetailForm.locator('select[name="reviewStatus"]').selectOption("in_beraterpruefung");
    const capaUpdateResponse = page.waitForResponse((response) => (
      response.url().includes("/api/audit-findings/") && response.request().method() === "PATCH"
    ));
    await capaDetailForm.locator('button[type="submit"]').click();
    assert.equal((await capaUpdateResponse).status(), 200, "CAPA update API must succeed");
    await page.waitForFunction(async () => {
      const response = await fetch("/api/audit-findings", { cache: "no-store" });
      if (!response.ok) return false;
      const payload = await response.json();
      return payload.auditFindings?.some((finding) => (
        finding.type === "CAPA"
        && finding.title === "E2E Korrekturmaßnahme MFA"
        && finding.rootCause?.startsWith("E2E Kontrollliste")
        && finding.reviewStatus === "in_beraterpruefung"
      ));
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForURL(/#capa$/);
    await page.getByText("E2E Korrekturmaßnahme MFA", { exact: true }).first().waitFor();
    const capaTaskResponse = page.waitForResponse((response) => (
      response.url().endsWith("/api/tasks") && response.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Umsetzungsaufgabe anlegen", exact: true }).click();
    assert.equal((await capaTaskResponse).status(), 201, "CAPA execution task API must succeed");
    await page.waitForURL(/#tasks$/);
    await page.locator('form[data-task-update]').waitFor();
    await page.getByText("CAPA umsetzen: E2E Korrekturmaßnahme MFA", { exact: true }).first().waitFor();
    await page.waitForFunction(async () => {
      const response = await fetch("/api/tasks", { cache: "no-store" });
      if (!response.ok) return false;
      const payload = await response.json();
      return payload.tasks?.some((task) => (
        task.workflowType === "capa-action"
        && task.title === "CAPA umsetzen: E2E Korrekturmaßnahme MFA"
        && String(task.reviewItemKey || "").startsWith("auditFinding:")
      ));
    });

    await page.goto(`${baseUrl}/#capa`, { waitUntil: "domcontentloaded" });
    await page.getByText("E2E Korrekturmaßnahme MFA", { exact: true }).first().waitFor();
    await page.getByRole("button", { name: "Nachweis hochladen", exact: true }).click();
    await page.waitForURL(/#documents$/);
    await page.waitForFunction(() => document.querySelector('[data-document-upload-context] input[name="linkedTo"]')?.value.includes("CAPA:"));
    const capaUploadReference = await page.locator('[data-document-upload-context] input[name="linkedTo"]').first().inputValue();
    assert.match(capaUploadReference, /E2E Korrekturmaßnahme MFA/, "CAPA upload context must retain the CAPA title");

    await page.goto(`${baseUrl}/#capa`, { waitUntil: "domcontentloaded" });
    await page.getByText("E2E Korrekturmaßnahme MFA", { exact: true }).first().waitFor();
    await page.getByRole("button", { name: "Offene Aufgabe anzeigen", exact: true }).waitFor();
    await assertNoHorizontalOverflow(page, "CAPA workspace desktop");
    if (SCREENSHOT_DIR) {
      fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "capa-desktop.png"), fullPage: true });
    }

    await page.locator('[data-view="project"]').click();
    await page.waitForURL(/#project$/);
    await page.getByRole("heading", { name: "Projektstrukturplan nach Phasen", exact: true }).waitFor();
    await page.getByText("ISO 27001", { exact: true }).first().waitFor();
    await page.getByText("NIS-2", { exact: true }).first().waitFor();
    await assertNoHorizontalOverflow(page, "Project plan desktop");

    await page.locator('[data-view="documents"]').click();
    await page.waitForURL(/#documents$/);
    await page.getByRole("heading", { name: "Was fehlt, was wartet, was ist freigegeben?", exact: true }).waitFor();
    await page.getByText("Fachansicht und Nachweismatrix anzeigen", { exact: true }).click();
    await page.getByRole("heading", { name: "Dokumente nach Status steuern", exact: true }).waitFor();
    await page.getByRole("heading", { name: "Vom Upload bis zur Beraterfreigabe", exact: true }).waitFor();
    await assertNoHorizontalOverflow(page, "Document center desktop");

    await page.locator('[data-view="notifications"]').click();
    await page.waitForURL(/#notifications$/);
    await page.getByRole("heading", { name: "Benachrichtigungen", exact: true }).waitFor();
    await page.getByText("Was braucht deine Aufmerksamkeit?", { exact: true }).waitFor();
    await assertNoHorizontalOverflow(page, "Notifications desktop");

    await page.locator('[data-view="tasks"]').click();
    await page.waitForURL(/#tasks$/);
    await page.getByRole("heading", { name: "Aufgaben und Audit-Readiness", exact: true }).waitFor();
    await page.getByText("Welche Aufgaben sind jetzt wirklich dran?", { exact: true }).waitFor();
    await assertNoHorizontalOverflow(page, "Task management desktop");

    await page.goto(`${baseUrl}/#suppliers`, { waitUntil: "domcontentloaded" });
    await page.locator("#supplierQuickForm").waitFor();
    await page.getByRole("button", { name: "Lieferant anlegen", exact: true }).waitFor();
    await page.locator("#suppliersReferenceRegister").waitFor();
    await assertNoHorizontalOverflow(page, "Vendor management desktop");
    if (SCREENSHOT_DIR) {
      fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "vendor-desktop.png"), fullPage: true });
    }

    const supplierForm = page.locator('form[data-form="supplier"]');
    await supplierForm.locator('input[name="name"]').fill("E2E Lieferant");
    await supplierForm.locator('input[name="service"]').fill("Cloud-Dienstleistung");
    await supplierForm.locator('select[name="framework"]').selectOption("NIS-2");
    await supplierForm.locator('select[name="criticality"]').selectOption("Hoch");
    await supplierForm.locator('input[name="owner"]').fill("E2E Owner");
    await supplierForm.locator('select[name="review"]').selectOption("In Prüfung");
    await supplierForm.locator('select[name="contractStatus"]').selectOption("Vorhanden");
    await supplierForm.locator('input[name="nextReview"]').fill("2026-12-31");
    await supplierForm.locator('input[name="evidence"]').fill("E2E Vertragsnachweis");
    await supplierForm.locator('button[type="submit"]').click();
    const supplierRow = page.locator('[data-register-detail^="suppliers:"]', { hasText: "E2E Lieferant" }).first();
    await supplierRow.waitFor();
    await supplierRow.click();
    await page.locator("[data-register-detail-panel]").waitFor();
    const supplierEditForm = page.locator("form[data-supplier-update]");
    await supplierEditForm.locator('input[name="owner"]').fill("E2E Vendor Owner aktualisiert");
    await supplierEditForm.locator('textarea[name="dataAccess"]').fill("Administrativer Zugriff auf den Cloud-Dienst");
    await supplierEditForm.locator('button[type="submit"]').click();
    await page.locator('form[data-supplier-update] input[name="owner"][value="E2E Vendor Owner aktualisiert"]').waitFor();
    await page.locator("[data-supplier-contract]:visible").click();
    await page.waitForURL(/#contracts$/);
    await page.getByText(/E2E Lieferant/).first().waitFor();

    await page.goto(`${baseUrl}/#assets`, { waitUntil: "domcontentloaded" });
    for (let index = 1; index <= 8; index += 1) {
      const assetForm = page.locator('form[data-form="asset"]');
      await assetForm.locator('input[name="name"]').fill(`E2E Asset ${index}`);
      await assetForm.locator('select[name="framework"]').selectOption(index % 2 ? "ISO 27001" : "NIS-2");
      await assetForm.locator('input[name="owner"]').fill("E2E Owner");
      await assetForm.locator('input[name="protection"]').fill("Intern");
      await assetForm.locator('button[type="submit"]').click();
      await page.getByText(`E2E Asset ${index}`, { exact: true }).first().waitFor();
    }
    const secondAssetPage = page.locator('[data-reference-page="assets"][data-reference-page-value="2"][aria-current="false"]');
    await secondAssetPage.waitFor();
    await secondAssetPage.click();
    await page.locator('[data-reference-page="assets"][aria-current="page"]').filter({ hasText: "2" }).waitFor();
    await page.locator('input[data-reference-search="assets"]').fill("E2E Asset 8");
    await page.waitForFunction(() => {
      const table = document.querySelector("#assetsReferenceRegister tbody");
      return table?.textContent?.includes("E2E Asset 8") && !table.textContent.includes("E2E Asset 7");
    });
    await page.locator('[data-reference-filter-reset="assets"]').click();
    await page.locator('[data-reference-scope="assets:NIS-2"]').click();
    await page.waitForFunction(() => {
      const table = document.querySelector("#assetsReferenceRegister tbody");
      return table?.textContent?.includes("E2E Asset 8") && !table.textContent.includes("E2E Asset 7");
    });
    await page.locator('[data-reference-columns-toggle="assets"]').click();
    await page.locator("#assetsReferenceRegister.reference-columns-compact").waitFor();
    await assertNoHorizontalOverflow(page, "Interactive asset register desktop");

    await page.goto(`${baseUrl}/#risks`, { waitUntil: "domcontentloaded" });
    const riskForm = page.locator('form[data-form="risk"]');
    await riskForm.locator('input[name="riskId"]').fill("E2E-R-001");
    await riskForm.locator('input[name="asset"]').fill("E2E Asset 1");
    await riskForm.locator('select[name="framework"]').selectOption("ISO 27001");
    await riskForm.locator('input[name="owner"]').fill("E2E Owner");
    await riskForm.locator('textarea[name="scenario"]').fill("E2E Risikoszenario");
    await riskForm.locator('select[name="likelihood"]').selectOption("3");
    await riskForm.locator('select[name="impact"]').selectOption("4");
    await riskForm.locator('select[name="treatmentOption"]').selectOption("Reduzieren");
    await riskForm.locator('[name="treatment"]').fill("E2E Maßnahme umsetzen");
    await riskForm.locator('button[type="submit"]').click();
    await page.getByText("E2E Risikoszenario", { exact: true }).first().waitFor();
    const riskRow = page.locator('[data-register-detail^="risks:"]', { hasText: "E2E Risikoszenario" }).first();
    await riskRow.click();
    const riskEditForm = page.locator('form[data-risk-update]');
    await riskEditForm.waitFor();
    await riskEditForm.locator('input[name="owner"]').fill("E2E Risk Owner Updated");
    await riskEditForm.locator('textarea[name="evidence"]').fill("E2E Risk Evidence");
    await riskEditForm.locator('button[type="submit"]').click();
    await page.getByText("E2E Risk Owner Updated", { exact: true }).first().waitFor();
    await assertNoHorizontalOverflow(page, "Interactive risk detail desktop");

    await page.goto(`${baseUrl}/#policies`, { waitUntil: "domcontentloaded" });
    const policyForm = page.locator('#policyManualForm form[data-form="policy"]');
    await policyForm.locator('input[name="title"]').fill("E2E Information Security Policy");
    await policyForm.locator('input[name="owner"]').fill("E2E Policy Owner");
    await policyForm.locator('input[name="version"]').fill("0.1");
    await policyForm.locator('select[name="framework"]').selectOption("ISO 27001");
    await policyForm.locator('input[name="linkedTo"]').fill("A.5.1");
    await policyForm.locator('select[name="status"]').selectOption("Entwurf");
    await policyForm.locator('input[name="review"]').fill("2026-12-31");
    await policyForm.locator('button[type="submit"]').click();
    await page.locator("details.register-detail-disclosure").first().locator("summary").click();
    await page.getByText("E2E Information Security Policy", { exact: true }).first().waitFor();
    await page.locator('[data-policy-detail]', { hasText: "E2E Information Security Policy" }).first().click();
    const policyDetailForm = page.locator('form[data-policy-detail-form]');
    await policyDetailForm.waitFor();
    await policyDetailForm.locator('[data-policy-detail-field="owner"]').fill("E2E Policy Owner Updated");
    await policyDetailForm.locator('[data-policy-detail-field="version"]').fill("0.2");
    await policyDetailForm.locator('button[type="submit"]').click();
    await page.getByText("E2E Policy Owner Updated", { exact: true }).first().waitFor();
    await assertNoHorizontalOverflow(page, "Interactive policy detail desktop");
    await page.locator('[data-policy-open]').filter({ hasText: /öffnen|Dokument|Entwurf|Vorlage/i }).first().waitFor();

    await page.goto(`${baseUrl}/#incidents`, { waitUntil: "domcontentloaded" });
    const incidentForm = page.locator('form[data-form="incident"]');
    await incidentForm.locator('input[name="title"]').fill("E2E Verdächtige Administratoranmeldung");
    await incidentForm.locator('select[name="framework"]').selectOption("ISO 27001 + NIS-2");
    await incidentForm.locator('select[name="severity"]').selectOption("Hoch");
    await incidentForm.locator('input[name="owner"]').fill("E2E Incident Owner");
    await incidentForm.locator('select[name="status"]').selectOption("In Bewertung");
    await incidentForm.locator('textarea[name="note"]').fill("Administratorkonto gesperrt und Logs gesichert.");
    await incidentForm.locator('button[type="submit"]').click();
    const incidentRow = page.locator('[data-register-detail^="incidents:"]', { hasText: "E2E Verdächtige Administratoranmeldung" }).first();
    await incidentRow.waitFor();
    await incidentRow.click();
    const incidentEditForm = page.locator('form[data-incident-update]');
    await incidentEditForm.waitFor();
    await incidentEditForm.locator('select[name="status"]').selectOption("In Behandlung");
    await incidentEditForm.locator('textarea[name="evidence"]').fill("E2E Ticket SEC-1042");
    await incidentEditForm.locator('button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelector('form[data-incident-update] textarea[name="evidence"]')?.value === "E2E Ticket SEC-1042");
    await assertNoHorizontalOverflow(page, "Interactive incident detail desktop");

    await page.goto(`${baseUrl}/#contracts`, { waitUntil: "domcontentloaded" });
    const contractForm = page.locator('form[data-form="contract"]');
    await contractForm.locator('input[name="title"]').fill("E2E SaaS-Vertrag Sicherheitsklauseln");
    await contractForm.locator('input[name="vendor"]').fill("E2E Cloud Provider GmbH");
    await contractForm.locator('select[name="framework"]').selectOption("ISO 27001 + NIS-2");
    await contractForm.locator('input[name="owner"]').fill("E2E Einkauf / Legal");
    await contractForm.locator('select[name="status"]').selectOption("Prüfen");
    await contractForm.locator('input[name="linkedTo"]').fill("A.5.20");
    await contractForm.locator('button[type="submit"]').click();
    const contractRow = page.locator('[data-register-detail^="contracts:"]', { hasText: "E2E SaaS-Vertrag Sicherheitsklauseln" }).first();
    await contractRow.waitFor();
    await contractRow.click();
    const contractEditForm = page.locator('form[data-contract-update]');
    await contractEditForm.waitFor();
    await contractEditForm.locator('select[name="status"]').selectOption("Nachbesserung");
    await contractEditForm.locator('textarea[name="evidence"]').fill("E2E AVV und Sicherheitsanlage 0.2");
    await contractEditForm.locator('input[name="review"]').fill("2026-12-31");
    await contractEditForm.locator('button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelector('form[data-contract-update] textarea[name="evidence"]')?.value === "E2E AVV und Sicherheitsanlage 0.2");
    await assertNoHorizontalOverflow(page, "Interactive contract detail desktop");

    await page.goto(`${baseUrl}/#legal`, { waitUntil: "domcontentloaded" });
    const legalForm = page.locator('form[data-form="legal"]');
    await legalForm.locator('input[name="requirement"]').fill("E2E Registrierungspflicht fachlich bewerten");
    await legalForm.locator('input[name="source"]').fill("NIS-2-Dokument, §33");
    await legalForm.locator('select[name="framework"]').selectOption("NIS-2");
    await legalForm.locator('input[name="owner"]').fill("E2E Legal / Geschäftsleitung");
    await legalForm.locator('select[name="status"]').selectOption("Prüfen");
    await legalForm.locator('input[name="due"]').fill("2026-12-31");
    await legalForm.locator('button[type="submit"]').click();
    const legalRow = page.locator('[data-register-detail^="legal:"]', { hasText: "E2E Registrierungspflicht fachlich bewerten" }).first();
    await legalRow.waitFor();
    await legalRow.click();
    const legalEditForm = page.locator('form[data-legal-update]');
    await legalEditForm.waitFor();
    await legalEditForm.locator('select[name="status"]').selectOption("Anwendbar");
    await legalEditForm.locator('textarea[name="evidence"]').fill("E2E Betroffenheitsentscheidung und Registerauszug");
    await legalEditForm.locator('textarea[name="note"]').fill("E2E Einordnung wurde dokumentiert.");
    await legalEditForm.locator('button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelector('form[data-legal-update] textarea[name="evidence"]')?.value === "E2E Betroffenheitsentscheidung und Registerauszug");
    await assertNoHorizontalOverflow(page, "Interactive legal register detail desktop");

    await page.goto(`${baseUrl}/#tasks`, { waitUntil: "domcontentloaded" });
    const taskForm = page.locator('form[data-form="task"]');
    await taskForm.locator('input[name="title"]').fill("E2E Backup-Nachweis für Q2 ergänzen");
    await taskForm.locator('select[name="module"]').selectOption("Dokumentation");
    await taskForm.locator('input[name="owner"]').fill("E2E IT-Betrieb");
    await taskForm.locator('input[name="due"]').fill("2026-12-31");
    await taskForm.locator('select[name="status"]').selectOption("Offen");
    await taskForm.locator('button[type="submit"]').click();
    const taskRow = page.locator('[data-register-detail^="tasks:"]', { hasText: "E2E Backup-Nachweis für Q2 ergänzen" }).first();
    await taskRow.waitFor();
    await taskRow.click();
    const taskEditForm = page.locator('form[data-task-update]');
    await taskEditForm.waitFor();
    await taskEditForm.locator('select[name="status"]').selectOption("In Arbeit");
    await taskEditForm.locator('textarea[name="evidence"]').fill("E2E Backup-Report Q2 und Restore-Ticket OPS-204");
    await taskEditForm.locator('textarea[name="note"]').fill("Restore-Test wurde dokumentiert.");
    await taskEditForm.locator('button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelector('form[data-task-update] textarea[name="evidence"]')?.value === "E2E Backup-Report Q2 und Restore-Ticket OPS-204");
    await assertNoHorizontalOverflow(page, "Interactive task detail desktop");

    await page.goto(`${baseUrl}/#managementreview`, { waitUntil: "domcontentloaded" });
    const managementReviewForm = page.locator("form[data-management-review-form]");
    await managementReviewForm.waitFor();
    await managementReviewForm.locator('input[name="title"]').fill("E2E Managementbewertung Informationssicherheit 2026");
    await managementReviewForm.locator('input[name="reviewPeriod"]').fill("Januar bis Juni 2026");
    await managementReviewForm.locator('input[name="meetingDate"]').fill("2026-07-20");
    await managementReviewForm.locator('input[name="nextReview"]').fill("2027-01-20");
    await managementReviewForm.locator('input[name="chair"]').fill("E2E Geschäftsführung");
    await managementReviewForm.locator('input[name="participants"]').fill("Geschäftsführung, ISB, IT");
    await managementReviewForm.locator('textarea[name="summary"]').fill("E2E Risiken, Auditergebnisse, Vorfälle und Zielerreichung wurden bewertet.");
    await managementReviewForm.locator('textarea[name="decisions"]').fill("E2E Maßnahmen werden priorisiert und Verantwortlichen zugewiesen.");
    await managementReviewForm.locator('select[name="reviewStatus"]').selectOption("in_beraterpruefung");
    await managementReviewForm.locator('input[name="auditRelevant"]').check();
    const managementSave = page.waitForResponse((response) => (
      response.url().endsWith("/api/management-review")
      && response.request().method() === "PATCH"
    ));
    await managementReviewForm.locator('button[type="submit"]').click();
    assert.equal((await managementSave).status(), 200, "Management review API save must succeed");
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.locator('form[data-management-review-form] input[name="title"]').waitFor();
    await page.waitForFunction(() => (
      document.querySelector('form[data-management-review-form] input[name="title"]')?.value
      === "E2E Managementbewertung Informationssicherheit 2026"
    ));
    assert.equal(
      await page.locator('form[data-management-review-form] input[name="title"]').inputValue(),
      "E2E Managementbewertung Informationssicherheit 2026",
      "Management review must persist after reload"
    );
    await assertNoHorizontalOverflow(page, "Management review desktop");
    if (SCREENSHOT_DIR) {
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "management-review-desktop.png"), fullPage: true });
    }

    await page.goto(`${baseUrl}/#audittrail`, { waitUntil: "domcontentloaded" });
    await page.getByRole("heading", { name: "Audit Trail und Versionierung", exact: true }).waitFor();
    await page.getByText("Hash-Kette intakt", { exact: true }).waitFor();
    await page.locator("[data-audit-integrity-refresh]").click();
    await page.getByText("Audit-Hash-Kette ist intakt.", { exact: true }).waitFor();
    await assertNoHorizontalOverflow(page, "Audit trail integrity desktop");

    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${baseUrl}/#guided`, { waitUntil: "domcontentloaded" });
    await page.getByRole("heading", { name: "Kundenmodus", exact: true }).waitFor();
    await page.locator("#mobileNavToggle").waitFor();
    await page.locator("#mainNav").waitFor({ state: "hidden" });
    await page.locator("#mobileNavToggle").click();
    await page.locator("#mainNav").waitFor({ state: "visible" });
    await page.locator("#mobileNavToggle").click();
    await page.locator("#mainNav").waitFor({ state: "hidden" });
    await assertNoHorizontalOverflow(page, "Customer mode mobile");

    await page.goto(`${baseUrl}/#suppliers`, { waitUntil: "domcontentloaded" });
    await page.locator("#supplierQuickForm").waitFor();
    await assertNoHorizontalOverflow(page, "Vendor management mobile");
    if (SCREENSHOT_DIR) {
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "vendor-mobile.png"), fullPage: true });
    }

    for (const view of platformViews) {
      await page.goto(`${baseUrl}/#${view}`, { waitUntil: "domcontentloaded" });
      await page.locator(`#appView[data-view="${view}"]`).waitFor();
      await assertPageIntegrity(page, `${view} mobile`);
    }

    const responsiveViewports = [
      { label: "tablet", width: 1024, height: 768 },
      { label: "widescreen", width: 1920, height: 1080 },
    ];
    for (const viewport of responsiveViewports) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      for (const view of platformViews) {
        await page.goto(`${baseUrl}/#${view}`, { waitUntil: "domcontentloaded" });
        await page.locator(`#appView[data-view="${view}"]`).waitFor();
        await assertPageIntegrity(page, `${view} ${viewport.label}`);
      }
    }

    assert.deepEqual(browserErrors, [], `Browser errors detected:\n${browserErrors.join("\n")}`);
    if (liveContext) await liveContext.close();
    await context.close();
    console.log("Browser E2E checks passed.");
  } finally {
    if (browser) await browser.close();
    await stopProcess(serverProcess);
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

run().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
