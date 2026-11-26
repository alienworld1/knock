import { expect, test } from "vitest";
import type { Session } from "./api";
import { describeSession } from "./session";

const signed = {
  sessionId: "session",
  state: "Active",
  revocable: true,
  chainMonitoring: "Available",
  lastVerified: {
    requestId: "request",
    state: "Active",
    role: "logs",
    issued: 100,
    observed: 140,
    deadline: 200,
    revokedBlock: "",
  },
} satisfies Session;

test("a fresh observation has a bounded rail; old signed records can omit issue time", () => {
  expect(describeSession(signed, 150)).toEqual({
    state: "Active",
    remaining: 50,
    progress: 0.5,
  });
  expect(
    describeSession(
      {
        ...signed,
        lastVerified: { ...signed.lastVerified, issued: undefined },
      },
      150,
    ),
  ).toEqual({ state: "Active", remaining: 50, progress: undefined });
});
test("stale observations and a zero countdown never imply host closure", () => {
  expect(describeSession(signed, 150, true).state).toMatch(/^Stale/);
  expect(describeSession(signed, 161).state).toMatch(/^Stale/);
  expect(describeSession(signed, 200)).toEqual({
    state: "Expiry reached · Closure unverified",
  });
  expect(
    describeSession(
      {
        ...signed,
        lastVerified: { ...signed.lastVerified, state: "Cleanup incomplete" },
      },
      200,
    ),
  ).toEqual({ state: "Cleanup incomplete" });
});
test("confirmed revocation closure survives fresh-data failures", () => {
  expect(
    describeSession(
      {
        ...signed,
        state: "Closed",
        lastVerified: {
          ...signed.lastVerified,
          state: "Closed",
          closedAt: 151,
          cause: "Revoked",
        },
      },
      300,
      true,
    ),
  ).toEqual({ state: "Revocation enforced" });
});
test("pending revocation does not report active before Door closure", () => {
  expect(
    describeSession(
      {
        ...signed,
        revocation: "Registry revocation confirmed",
      },
      150,
    ),
  ).toEqual({
    state: "Revocation pending",
    remaining: 50,
    progress: 0.5,
  });
  expect(
    describeSession(
      {
        ...signed,
        state: "Closing",
        revocation: "Revocation observed by the Door",
        lastVerified: { ...signed.lastVerified, state: "Closing" },
      },
      150,
    ),
  ).toEqual({ state: "Revocation pending" });
});
