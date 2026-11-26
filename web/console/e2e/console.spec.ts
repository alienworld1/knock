import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const requestId = "0x" + "9".repeat(64);
const sessionId = "0x" + "1".repeat(64);
const account = "qor1" + "a".repeat(42);
const receiptId = "0x" + "7".repeat(64);
const newerReceiptId = "0x" + "6".repeat(64);
const consumptionTx = "0x" + "2".repeat(64);

async function fixture(
  page: Page,
  {
    denied = false,
    empty = false,
    pendingRevoke = false,
    withReceipt = false,
    meteredReceipt = false,
  } = {},
) {
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
  let phase: "active" | "pending" | "closed" = "active";
  let sessionPolls = 0;
  const receipt = {
    ID: receiptId,
    Epoch: 1,
    Request: requestId,
    Session: sessionId,
    Requester: account,
    Approver: meteredReceipt ? "" : account,
    Purchase: "0x" + (meteredReceipt ? "3" : "0").repeat(64),
    ConsumptionTx: meteredReceipt ? consumptionTx : "0x" + "0".repeat(64),
    Role: meteredReceipt ? "" : "logs",
    Service: meteredReceipt ? "private-status" : "",
    Cause: meteredReceipt ? "Expired" : "Revoked",
    Cleanup: "Closed",
    CleanupObservedAt: now - 5,
    ActiveObservedAt: now - 15,
    TerminationObservedAt: now - 6,
    ActualSeconds: 9,
    RequestedSeconds: 180,
    RevocationBlock: "0x" + (meteredReceipt ? "0" : "8").repeat(64),
    Corrects: "0x" + "0".repeat(64),
  };
  const receipts = withReceipt || meteredReceipt ? [receipt] : [];
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
          approvers: [account],
          approversCanRevoke: true,
          canReview: true,
          canRevoke: true,
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
        phase = pendingRevoke ? "pending" : "closed";
        sessionPolls = 0;
        return json({
          message:
            "Registry revocation confirmed. Waiting for the Door to verify closure.",
        });
      case "/api/sessions": {
        if (phase === "pending") {
          sessionPolls++;
          if (sessionPolls > 1) phase = "closed";
        }
        const closed = phase === "closed";
        return json({
          sessions: [
            {
              sessionId,
              state: closed ? "Closed" : "Active",
              chainMonitoring: "Available",
              revocation:
                phase === "pending"
                  ? "Registry revocation confirmed"
                  : closed
                    ? "Enforced by the Door"
                    : undefined,
              revocable: phase === "active",
              lastVerified: {
                requestId,
                state: closed ? "Closed" : "Active",
                role: "logs",
                issued: now - 10,
                observed: now,
                deadline: now + 120,
                revokedBlock: requestId,
                closedAt: closed ? now : undefined,
                cause: closed ? "Revoked" : undefined,
              },
            },
          ],
        });
      }
      case "/api/history":
        return denied
          ? route.fulfill({
              status: 503,
              json: { error: "Receipt updates unavailable." },
            })
          : json({ receipts });
      default:
        return route.fulfill({
          status: 404,
          json: { error: "Unexpected route." },
        });
    }
  });
  return {
    addReceipt: () =>
      receipts.push({ ...receipt, ID: newerReceiptId, CleanupObservedAt: now }),
  };
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

test("both themes pass axe across Doors, Sessions, and History at 320 px", async ({
  page,
}) => {
  await fixture(page, { withReceipt: true });
  await page.setViewportSize({ width: 320, height: 900 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "validator-ops" }),
  ).toBeVisible();
  await page.getByRole("button", { name: /Waiting for decision/ }).click();
  await expect(page.getByText("Check host uptime.")).toBeVisible();

  for (const theme of ["dark", "light"]) {
    await page.getByLabel("Theme").selectOption(theme);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    for (const nav of ["Doors", "Sessions", "History"]) {
      await page.getByRole("link", { name: nav }).click();
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - innerWidth,
      );
      expect(overflow).toBeLessThanOrEqual(0);
      const result = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze();
      expect(result.violations).toEqual([]);
    }
    await page.getByRole("link", { name: "Doors" }).click();
  }
  await page.setViewportSize({ width: 640, height: 960 });
  await page.getByRole("button", { name: /Waiting for decision/ }).click();
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

test("pending revocation transitions to enforced closure and History auto-selects receipts", async ({
  page,
}) => {
  await fixture(page, { pendingRevoke: true, withReceipt: true });
  await page.goto("/sessions");
  const session = page.getByRole("article");
  await expect(session.getByRole("status")).toHaveText("Active");
  await page.getByRole("button", { name: "Revoke access" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Revoke access" })
    .click();
  await expect(session.getByRole("status")).toHaveText("Revocation pending");
  await expect(page.getByRole("button", { name: "Revoke access" })).toHaveCount(
    0,
  );
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(session.getByRole("status")).toHaveText("Revocation enforced");

  await page.getByRole("link", { name: "History" }).click();
  await expect(
    page.getByRole("heading", { name: "Receipt details" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Firewall, WireGuard peer, SSH authorization, contained workloads",
    ),
  ).toBeVisible();
  await page.getByText("Verification details").click();
  await expect(
    page.getByRole("button", { name: "Copy receipt ID" }),
  ).toBeVisible();
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

test("metered receipts link to the EVM transaction in the QoreChain Dashboard", async ({
  page,
}) => {
  await fixture(page, { meteredReceipt: true });
  await page.goto("/history");
  await page.getByText("Verification details").click();
  await expect(
    page.getByRole("link", {
      name: "Open consumption transaction on Diana explorer",
    }),
  ).toHaveAttribute(
    "href",
    "https://dashboard.qorechain.io/explorer/tx/" + consumptionTx,
  );
});

test("History keeps the receipt in view and copy feedback follows the value", async ({
  page,
}) => {
  const { addReceipt } = await fixture(page, { withReceipt: true });
  await page.addInitScript((rejectedValue) => {
    Object.defineProperty(navigator, "clipboard", {
      value: {
        writeText: async (value: string) => {
          if (value === rejectedValue) throw new Error("Clipboard denied");
        },
      },
    });
  }, newerReceiptId);
  await page.goto("/history");
  await page.getByText("Verification details").click();
  const detail = page.getByRole("article");
  await expect(detail.getByText(receiptId, { exact: true })).toBeVisible();

  addReceipt();
  await page.getByRole("button", { name: "Refresh" }).click();
  const newer = page.getByRole("button", { name: /0x666666/ });
  await expect(newer).toBeVisible();
  await expect(detail.getByText(receiptId, { exact: true })).toBeVisible();

  const copy = detail.getByRole("button", { name: "Copy receipt ID" });
  await copy.click();
  await expect(copy).toHaveText("Copied");
  await newer.click();
  await expect(detail.getByText(newerReceiptId, { exact: true })).toBeVisible();
  await expect(copy).toHaveText("Copy");
  await copy.click();
  await expect(
    detail.getByText("Couldn't copy. Select and copy the value."),
  ).toBeVisible();
});
