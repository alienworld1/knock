import type { Session } from "./api";

export function describeSession(item: Session, now: number, stale = false) {
  const record = item.lastVerified;
  if (!record) return { state: "Status unavailable" };
  if (item.state === "Closed" && record.closedAt) {
    return {
      state:
        record.cause === "Revoked" ? "Revocation enforced" : "Closure verified",
    };
  }
  if (record.state === "Cleanup incomplete")
    return { state: "Cleanup incomplete" };
  if (record.deadline <= now)
    return { state: "Expiry reached · Closure unverified" };
  if (stale || item.state === "Unknown" || now - record.observed > 20) {
    return { state: "Stale · Last observed " + record.state.toLowerCase() };
  }
  if (item.state !== "Ready" && item.state !== "Active")
    return { state: item.state };
  const remaining = record.deadline - now;
  const progress =
    record.issued && record.issued < record.deadline
      ? Math.max(
          0,
          Math.min(
            1,
            (now - record.issued) / (record.deadline - record.issued),
          ),
        )
      : undefined;
  return { state: item.state, remaining, progress };
}
