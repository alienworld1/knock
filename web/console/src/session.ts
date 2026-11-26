import type { Session } from "./api";
import type { StatusTone } from "./components/Status";

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
  if (item.state !== "Ready" && item.state !== "Active") {
    if (item.revocation) return { state: "Revocation pending" };
    return { state: item.state };
  }
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
  if (item.revocation)
    return { state: "Revocation pending", remaining, progress };
  return { state: item.state, remaining, progress };
}

export function sessionTone(state: string): {
  tone: StatusTone;
  icon?: "clock" | "alert";
} {
  switch (state) {
    case "Active":
    case "Revocation enforced":
    case "Closure verified":
      return { tone: "success" };
    case "Cleanup incomplete":
      return { tone: "danger" };
    case "Ready":
    case "Revocation pending":
    case "Reserved":
    case "Provisioning":
    case "Closing":
      return { tone: "warning", icon: "clock" };
    default:
      return { tone: "warning", icon: "alert" };
  }
}
