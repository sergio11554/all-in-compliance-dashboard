const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

async function assertIntuneUi(page, baseUrl) {
  await page.goto(`${baseUrl}/#assets`);
  await page.locator(".intune-widget").waitFor();
  const before = await page.evaluate(() => JSON.stringify(state.assets));
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 960 });
    await page.locator('[data-intune="demo"]').click();
    await page.getByRole("heading", { name: "Testvorschau · keine Microsoft-Verbindung" }).waitFor();
    await page.locator('[data-intune="apply"]').click();
    await page.getByRole("heading", { name: "Test-Asset-Register" }).waitFor();
    assert.equal(await page.locator(".intune-table tbody tr").count(), 3);
    assert.equal(await page.evaluate(() => JSON.stringify(state.assets)), before, "Demo must not modify customer assets");
    await page.locator(".intune-widget").scrollIntoViewIfNeeded();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2), false, "Intune preview must not overflow viewport");
    const columns = await page.locator(".intune-table th").evaluateAll(cells => cells.map(cell => cell.getBoundingClientRect().width));
    assert.ok(columns.every(width => width >= 140), "Intune columns must remain readable on mobile");
    if (process.env.SFM_E2E_SCREENSHOT_DIR) {
      fs.mkdirSync(process.env.SFM_E2E_SCREENSHOT_DIR, { recursive: true });
      await page.screenshot({ path: path.join(process.env.SFM_E2E_SCREENSHOT_DIR, `intune-${width}.png`) });
    }
    await page.locator('[data-intune="discard"]').click();
    await page.locator('[data-intune="setup"]').click();
    const form = page.locator("[data-intune-configure]");
    await form.locator("fieldset:not([disabled])").waitFor();
    await form.locator('[name="tenantId"]').fill("11111111-1111-1111-1111-111111111111");
    await form.locator('[name="clientId"]').fill("22222222-2222-2222-2222-222222222222");
    await form.locator('[name="clientSecret"]').fill("synthetic-ui-secret-do-not-use");
    await page.locator('[data-intune="refresh"]').click();
    assert.equal(await form.locator('[name="clientSecret"]').inputValue(), "synthetic-ui-secret-do-not-use", "Status refresh must not discard an edited form");
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2), false, "Setup must fit mobile viewport");
    if (process.env.SFM_E2E_SCREENSHOT_DIR) {
      await form.scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(process.env.SFM_E2E_SCREENSHOT_DIR, `intune-setup-${width}.png`) });
    }
    // The real configuration API is used; intercept only the subsequent external-fetch trigger.
    let requestedPreview = false;
    await page.route("**/api/integrations/intune/preview", async route => {
      requestedPreview = true;
      await route.fulfill({ status: 202, contentType: "application/json", body: '{"jobId":"ui-test-no-microsoft-network"}' });
    });
    await form.locator('button[type="submit"]').click();
    await page.locator(".intune-state", { hasText: "Zugang gespeichert · noch nicht geprüft" }).waitFor();
    assert.equal(requestedPreview, true);
    assert.equal(await page.evaluate(() => JSON.stringify(state.assets)), before);
    assert.equal(await page.evaluate(() => (JSON.stringify(state) + JSON.stringify(localStorage) + JSON.stringify(sessionStorage)).includes("synthetic-ui-secret-do-not-use")), false);
    await page.unroute("**/api/integrations/intune/preview");
    await page.locator('[data-intune="setup"]').click();
    assert.equal(await form.locator('[name="clientSecret"]').inputValue(), "");
    await page.locator('[data-intune="disconnect-confirm"]').click();
    await page.locator('[data-intune="disconnect-cancel"]').click();
    assert.equal(await page.locator('[data-intune="disconnect"]').count(), 0);
    await page.locator('[data-intune="disconnect-confirm"]').click();
    await page.locator('[data-intune="disconnect"]').click();
    await page.locator(".intune-state", { hasText: "Nicht verbunden" }).waitFor();
    assert.equal(await page.evaluate(() => JSON.stringify(state.assets)), before);
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(`${baseUrl}/#integrations`);
  await page.locator(".intune-widget").waitFor();
  assert.equal(await page.locator('[data-intune="demo"]').count(), 1);
  await page.locator('[data-intune="toggle"]').click();
}

module.exports = { assertIntuneUi };
