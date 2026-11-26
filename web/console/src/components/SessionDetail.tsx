import {
  actions,
  danger,
  panel,
  panelHeading,
  panelIcon,
  status,
} from "./classes";
import type { ReactNode } from "react";
import { CheckCircleIcon } from "@phosphor-icons/react/CheckCircle";
import { TimerIcon } from "@phosphor-icons/react/Timer";
import type { Session } from "../api";
import { Evidence, Fields } from "./Fields";
import { Notice } from "./Notice";
import { duration, short, utc } from "../format";
import { describeSession } from "../session";
export function SessionDetail({
  item,
  now,
  stale,
  revoke,
}: {
  item: Session;
  now: number;
  stale: boolean;
  revoke: () => void;
}) {
  const record = item.lastVerified;
  const description = describeSession(item, now, stale);
  if (!record) return <Notice error>{description.state}</Notice>;
  const { state, remaining, progress } = description;
  const confirmed = state === "Active" || Boolean(record.closedAt);
  return (
    <article className={panel}>
      <div className={panelHeading}>
        <div className={panelIcon}>
          <TimerIcon size={22} aria-hidden />
        </div>
        <div>
          <h3>
            {record.service
              ? "Private service · " + record.service
              : "SSH · " + record.role}
          </h3>
          <code className="text-muted">{short(item.sessionId)}</code>
        </div>
        <span
          className={confirmed ? status + " text-success!" : status}
          role="status"
        >
          {confirmed ? <CheckCircleIcon size={16} aria-hidden /> : null} {state}
        </span>
      </div>
      <div className="mt-4 border-y border-seam py-4 [&_p]:text-muted">
        {remaining !== undefined ? (
          <div className="font-mono text-[32px]/10 font-medium tabular-nums [&>span]:font-sans [&>span]:text-sm/5.5 [&>span]:text-muted">
            {duration(remaining)} <span>remaining</span>
          </div>
        ) : null}
        {progress !== undefined ? (
          <progress
            value={progress}
            max={1}
            aria-label="Elapsed share of the access window"
          />
        ) : null}
        <p>Expires {utc(record.deadline)}</p>
      </div>
      <Fields
        items={[
          ["Last verified", utc(record.observed)],
          ["Chain monitoring", stale ? "Unknown" : item.chainMonitoring],
          ...(item.revocation
            ? [["Revocation", item.revocation] as [string, ReactNode]]
            : []),
          ...(record.cause
            ? [["Termination", record.cause] as [string, ReactNode]]
            : []),
          ...(record.receiptState
            ? [["Receipt", record.receiptState] as [string, ReactNode]]
            : []),
        ]}
      />
      <Evidence
        items={[
          ["Session ID", <code>{item.sessionId}</code>],
          ["Request ID", <code>{record.requestId}</code>],
          ["Last host observation", record.state],
          [
            "Last chain check",
            record.chainChecked ? utc(record.chainChecked) : "Unavailable",
          ],
          ...(record.closedAt
            ? [
                ["Closure verified", utc(record.closedAt)] as [
                  string,
                  ReactNode,
                ],
              ]
            : []),
          ...(record.revokedAt
            ? [
                ["Revocation block", <code>{record.revokedBlock}</code>] as [
                  string,
                  ReactNode,
                ],
              ]
            : []),
        ]}
      />
      {item.revocable && !stale && remaining !== undefined ? (
        <div className={actions}>
          <button type="button" className={danger} onClick={revoke}>
            Revoke access
          </button>
        </div>
      ) : null}
    </article>
  );
}
