import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const requestId = "0x" + "9".repeat(64);
const sessionId = "0x" + "1".repeat(64);
const account = "qor1" + "a".repeat(42);

async function fixture(page: Page, { denied = false, empty = false } = {}) {
  const now = Math.floor(Date.now() / 1000);
  let delivery = "";
  const request = {
    id: requestId,
    requester: account,
    role: "logs",
    service: "",
    durationSeconds: 180,
    deadline: new Date((now + 120) * 1000).toISOString(),
  };
  let active = true;
  await page.route("**/api/**", async (route) => {
    const requestPath = new URL(route.request().url()).pathname;
    const json = (data: unknown) => route.fulfill({ json: data });
    switch (requestPath) {
      case "/api/bootstrap":
      case "/api/session":
        return json({ csrf: "b".repeat(43) });
      case "/api/doors":
        return json({
          identity: account,
          doors: empty
            ? []
            : [{ account, alias: "validator-ops", target: "validator-ops" }],
        });
      case "/api/door":
        return json({
          mode: "approval",
          enabled: true,
          policyVersion: "1",
          limit: 300,
          roles: ["logs"],
          canReview: true,
          canRotate: true,
          owner: account,
          signingKey: requestId,
          registry: "0x" + "a".repeat(40),
          cardExpires: now + 1000,
        });
      case "/api/request":
      case "/api/requests":
        return json([
          {
            ...request,
            decision: delivery || undefined,
            delivered: Boolean(delivery),
            reason: requestPath.endsWith("/request")
              ? "Check host uptime."
              : undefined,
          },
        ]);
      case "/api/decision":
        delivery = route.request().postDataJSON().decision;
        return json({
          message: "Decision sent. Waiting for the Door to verify it.",
        });
      case "/api/revoke":
        active = false;
        return json({
          message:
            "Registry revocation confirmed. Waiting for the Door to verify closure.",
        });
      case "/api/sessions":
        return json({
          sessions: [
            {
              sessionId,
              state: active ? "Active" : "Closed",
              chainMonitoring: "Available",
              revocable: active,
              lastVerified: {
                requestId,
                state: active ? "Active" : "Closed",
                role: "logs",
                issued: now - 10,
                observed: now,
                deadline: now + 120,
                revokedBlock: requestId,
                closedAt: active ? undefined : now,
                cause: active ? undefined : "Revoked",
              },
            },
          ],
        });
      case "/api/history":
        return denied
          ? route.fulfill({
              status: 503,
              json: { error: "Receipt updates unavailable." },
            })
          : json({ receipts: [] });
      default:
        return route.fulfill({
          status: 404,
          json: { error: "Unexpected route." },
        });
    }
  });
}

test("operator workflow, keyboard confirmation and real routes", async ({
  page,
}) => {
  await fixture(page);
  await page.goto("/#" + "a".repeat(43));
  await expect(page).toHaveURL(/\/$/);
  await expect(
    page.getByRole("combobox", { name: "Door", exact: true }),
  ).toHaveValue("validator-ops");
  const request = page.getByRole("button", { name: /Waiting for decision/ });
  await request.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Check host uptime.")).toBeVisible();
  const approve = page.getByRole("button", { name: "Approve request" });
  await approve.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Cancel" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(approve).toBeFocused();
  await approve.click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Approve request" })
    .click();
  await expect(
    page.getByRole("button", { name: /Approval sent/ }),
  ).toBeVisible();

  await page.getByRole("link", { name: "Sessions" }).click();
  await expect(page).toHaveURL(/\/sessions$/);
  const session = page.getByRole("article");
  await expect(session.getByRole("status")).toHaveText("Active");
  await expect(session.getByRole("status")).not.toContainText("remaining");
  await expect(page.getByRole("progressbar")).toHaveAccessibleName(
    "Elapsed share of the access window",
  );
  await page.getByRole("button", { name: "Revoke access" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Revoke access" })
    .click();
  await expect(
    session
      .getByRole("status")
      .getByText("Revocation enforced", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("progressbar")).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Sessions" })).toBeVisible();
});

test("both themes pass axe and the 320 px layout stays within the viewport", async ({
  page,
}) => {
  await fixture(page);
  await page.setViewportSize({ width: 320, height: 900 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "validator-ops" }),
  ).toBeVisible();
  for (const theme of ["dark", "light"]) {
    await page.getByLabel("Theme").selectOption(theme);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await page.getByRole("button", { name: /Waiting for decision/ }).click();
    await expect(page.getByText("Check host uptime.")).toBeVisible();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - innerWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);
    const result = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze();
    expect(result.violations).toEqual([]);
  }
  await page.setViewportSize({ width: 640, height: 960 });
  await page.locator("body").evaluate((body) => {
    body.style.zoom = "2";
  });
  await expect(
    page.getByRole("button", { name: "Approve request", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(640);
  await page.reload();
  await expect(page.getByLabel("Theme")).toHaveValue("light");
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.getByLabel("Theme").selectOption("system");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "system");
});

test("denial delivery, empty Doors and unavailable History are distinct", async ({
  page,
}) => {
  await fixture(page, { denied: true });
  await page.goto("/");
  await page.getByRole("button", { name: /Waiting for decision/ }).click();
  await page.getByRole("button", { name: "Deny request" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Deny request" })
    .click();
  await expect(page.getByRole("button", { name: /Denial sent/ })).toBeVisible();
  await page.getByRole("link", { name: "History" }).click();
  await expect(
    page.getByText("Receipt updates unavailable.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("No verified receipts for this identity."),
  ).toHaveCount(0);
  await page.unrouteAll();
  await fixture(page, { empty: true });
  await page.goto("/");
  await expect(page.getByText(/No Door Cards/)).toBeVisible();
});
