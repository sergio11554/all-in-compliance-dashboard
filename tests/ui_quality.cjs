const assert = require("node:assert/strict");

async function assertResponsiveLayout(page, label) {
  const result = await page.evaluate(() => {
    const visible = (node) => node.checkVisibility({ checkVisibilityCSS: true })
      && node.getBoundingClientRect().width > 0;
    const sidebar = document.querySelector(".sidebar");
    const brand = sidebar.querySelector(".brand h1");
    const context = document.querySelector(".workspace-project-context");
    const buttons = [...document.querySelectorAll("#appView button, .top-actions button")].filter(visible);
    return {
      viewport: innerWidth,
      sidebarWidth: sidebar.getBoundingClientRect().width,
      brandClipped: brand.scrollWidth > brand.clientWidth + 2 || brand.scrollHeight > brand.clientHeight + 2,
      contextHeight: context?.getBoundingClientRect().height || 0,
      contextOpen: Boolean(context?.querySelector("details[open]")),
      clippedButtons: buttons.filter((node) => node.clientWidth && node.scrollWidth > node.clientWidth + 3)
        .map((node) => `${node.textContent.trim().slice(0, 80)} (${node.clientWidth}/${node.scrollWidth}px)`),
    };
  });
  if (result.viewport <= 1100) {
    assert.ok(Math.abs(result.sidebarWidth - result.viewport) <= 2, `${label}: compact navigation must span the viewport`);
  }
  assert.equal(result.brandClipped, false, `${label}: brand name is clipped`);
  if (!result.contextOpen) {
    assert.ok(result.contextHeight < 195, `${label}: project context pushes the module down (${result.contextHeight}px)`);
  }
  assert.deepEqual(result.clippedButtons, [], `${label}: clipped action labels:\n${result.clippedButtons.join("\n")}`);
}

async function assertExecutiveData(page, baseUrl) {
  await page.goto(`${baseUrl}/#executive`, { waitUntil: "domcontentloaded" });
  await page.locator('#appView[data-view="executive"]').waitFor();
  assert.deepEqual(await page.evaluate(() => [
    reviewDatePlusDays("2026-03-28", 1),
    reviewDatePlusDays("2026-10-24", 2),
    reviewDatePlusDays("2026-12-31", 1),
    reviewSafeDate("2026-02-30"),
  ]), ["2026-03-29", "2026-10-26", "2027-01-01", ""]);
  const result = await page.evaluate(() => {
    const original = structuredClone(state);
    try {
      state.risks = [];
      state.tasks = [];
      state.policies = [];
      state.suppliers = [];
      state.contracts = [];
      const empty = document.createElement("div");
      empty.innerHTML = renderExecutiveCockpit();
      const emptyHigh = empty.querySelector('[data-executive-action="risks-high"] strong').textContent;
      const emptyDeadline = empty.querySelector('[data-executive-action="deadlines"] strong').textContent;
      const emptyCopy = empty.textContent;
      const past = new Date(`${today()}T12:00:00`);
      past.setDate(past.getDate() - 3);
      const pastDate = `${past.getFullYear()}-${String(past.getMonth() + 1).padStart(2, "0")}-${String(past.getDate()).padStart(2, "0")}`;
      state.risks = [
        { id: "quality-open", scenario: "Offenes Qualitätsrisiko", owner: "Test Owner", likelihood: 5, impact: 5, status: "Offen", treatment: "" },
        { id: "quality-closed", scenario: "Geschlossenes Qualitätsrisiko", likelihood: 5, impact: 5, status: "Geschlossen" },
      ];
      state.tasks = [
        { id: "quality-due", title: "Überfällige Testaufgabe", owner: "Test Owner", due: pastDate, status: "Offen" },
        { id: "quality-done", title: "Erledigte Testaufgabe", due: pastDate, status: "Erledigt" },
      ];
      const filled = document.createElement("div");
      filled.innerHTML = renderExecutiveCockpit();
      return {
        emptyHigh, emptyDeadline, emptyCopy,
        high: filled.querySelector('[data-executive-action="risks-high"] strong').textContent,
        riskTitles: [...filled.querySelectorAll(".executive-risk-item strong")].map((node) => node.textContent),
        actionDays: [...filled.querySelectorAll(".executive-action-item b")].map((node) => node.textContent),
        actionTitles: [...filled.querySelectorAll(".executive-action-item strong")].map((node) => node.textContent),
        deadlines: executiveWorkspaceDeadlines().map((item) => ({ title: item.title, date: item.date })),
        pastDate,
        clock: filled.querySelector("[data-live-berlin-time]").textContent,
        heading: filled.querySelector(".executive-mission-head").textContent,
        tenant: backendSessionUser.tenant.name,
      };
    } finally {
      state = original;
    }
  });
  assert.equal(result.emptyHigh, "0 High/Critical");
  assert.equal(result.emptyDeadline, "Nicht geplant");
  assert.match(result.emptyCopy, /Keine offenen hohen oder kritischen Risiken/);
  assert.doesNotMatch(result.emptyCopy, /NHD \/ Daume|68%|\+6%|Privilegierte Konten/);
  assert.equal(result.high, "1 High/Critical");
  assert.deepEqual(result.riskTitles, ["Offenes Qualitätsrisiko"]);
  assert.deepEqual(result.actionTitles, ["Überfällige Testaufgabe"]);
  assert.deepEqual(result.actionDays, ["3"]);
  assert.deepEqual(result.deadlines, [{ title: "Überfällige Testaufgabe", date: result.pastDate }]);
  assert.match(result.clock, /^Berlin:/);
  assert.ok(result.heading.includes(result.tenant), "Cockpit must display the active tenant");
  await page.locator('.executive-page-kpi[data-executive-action="decisions-open"]').click();
  await page.locator('#appView[data-view="managementreview"]').waitFor();
}

async function assertWorkspaceInteractions(page, baseUrl) {
  await page.goto(`${baseUrl}/#assets`, { waitUntil: "domcontentloaded" });
  const summary = page.locator(".workspace-project-details > summary");
  await summary.focus();
  await page.keyboard.press("Enter");
  await page.locator(".workspace-project-details[open] .workspace-context-actions").waitFor();
  await summary.focus();
  await page.keyboard.press("Enter");
  await page.locator(".workspace-context-actions").waitFor({ state: "hidden" });
  await page.locator("#importBtn").focus();
  const chooser = page.waitForEvent("filechooser");
  await page.keyboard.press("Enter");
  await (await chooser).setFiles([]);

  await page.goto(`${baseUrl}/#soa`, { waitUntil: "domcontentloaded" });
  assert.equal(await page.locator("[data-soa-row]").count(), 93);
  const last = page.locator('[data-soa-row="A.8.34"]');
  await last.scrollIntoViewIfNeeded();
  assert.ok(await last.isVisible(), "Last Annex-A control must remain reachable");
  const lastReview = last.locator('[data-soa-field="review"]');
  await lastReview.focus();
  assert.equal(await lastReview.evaluate((node) => node === document.activeElement), true);
  assert.equal(await lastReview.getAttribute("aria-label"), "A.8.34 Reviewdatum");
  const fields = await page.evaluate(() => {
    const container = document.createElement("div");
    container.innerHTML = field("Name", "name", "text", "") + selectField("Typ", "type", ["System"])
      + templateField({ name: "text", label: "Ergebnis", type: "textarea" });
    return [...container.querySelectorAll("input, select, textarea")].every((input) =>
      input.id && container.querySelector(`label[for="${input.id}"]`));
  });
  assert.ok(fields, "Shared form builders must associate each label with its field");
}

module.exports = { assertResponsiveLayout, assertExecutiveData, assertWorkspaceInteractions };
