import { actions, danger, panel, panelHeading, panelIcon } from "./classes";
import type { ReactNode } from "react";
import { ArrowsLeftRightIcon } from "@phosphor-icons/react/ArrowsLeftRight";
import { TerminalWindowIcon } from "@phosphor-icons/react/TerminalWindow";
import { TimerIcon } from "@phosphor-icons/react/Timer";
import type { Session } from "../api";
import { Copyable } from "./Copyable";
import { Evidence, Fields } from "./Fields";
import { Notice } from "./Notice";
import { StatusBadge } from "./Status";
import { duration, short, utc } from "../format";
import { describeSession, sessionTone } from "../session";

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
  const visual = sessionTone(state);
  const ScopeIcon = record.service
    ? ArrowsLeftRightIcon
    : record.role
      ? TerminalWindowIcon
      : TimerIcon;
  const expiryLine = record.closedAt
    ? "Ended " +
      utc(record.closedAt) +
      " · Scheduled expiry " +
      utc(record.deadline)
    : record.deadline <= now
      ? "Expired " + utc(record.deadline)
      : "Expires " + utc(record.deadline);

  return (
    <article className={panel}>
      <div className={panelHeading}>
        <div className={panelIcon}>
          <ScopeIcon size={22} aria-hidden />
        </div>
        <div>
          <h3>
            {record.service
              ? "Private service · " + record.service
              : "SSH · " + record.role}
          </h3>
          <code className="text-muted">{short(item.sessionId)}</code>
        </div>
        <StatusBadge
          role="status"
          label={state}
          tone={visual.tone}
          icon={visual.icon}
        />
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
        <p>{expiryLine}</p>
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
          [
            "Session ID",
            <Copyable value={item.sessionId} label="session ID" />,
          ],
          [
            "Request ID",
            <Copyable value={record.requestId} label="request ID" />,
          ],
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
                [
                  "Revocation block",
                  <Copyable
                    value={record.revokedBlock}
                    label="revocation block"
                  />,
                ] as [string, ReactNode],
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
