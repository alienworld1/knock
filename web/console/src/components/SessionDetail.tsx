import { actions, danger, panel, panelHeading, panelIcon } from "./classes";
import type { ReactNode } from "react";
import { ArrowsLeftRightIcon } from "@phosphor-icons/react/ArrowsLeftRight";
import { CheckCircleIcon } from "@phosphor-icons/react/CheckCircle";
import { ClockIcon } from "@phosphor-icons/react/Clock";
import { TerminalWindowIcon } from "@phosphor-icons/react/TerminalWindow";
import { TimerIcon } from "@phosphor-icons/react/Timer";
import { WarningIcon } from "@phosphor-icons/react/Warning";
import type { Session } from "../api";
import { Copyable } from "./Copyable";
import { Evidence, Fields } from "./Fields";
import { Notice } from "./Notice";
import { StatusBadge } from "./Status";
import { duration, short, utc } from "../format";
import { describeSession, sessionTone } from "../session";

type RevocationStep = {
  label: string;
  state: "done" | "pending" | "failed";
};

function revocationSteps(item: Session): RevocationStep[] {
  const record = item.lastVerified;
  const doorObserved = Boolean(
    record?.revokedAt ||
    item.revocation === "Revocation observed by the Door" ||
    item.revocation === "Enforced by the Door",
  );
  const chainConfirmed =
    doorObserved || item.revocation === "Registry revocation confirmed";
  const cleanupFailed = record?.state === "Cleanup incomplete";
  const cleanupDone = Boolean(item.state === "Closed" && record?.closedAt);

  return [
    {
      label: "Chain confirmed",
      state: chainConfirmed ? "done" : "pending",
    },
    {
      label: "Door observed",
      state: doorObserved ? "done" : "pending",
    },
    {
      label: cleanupFailed ? "Cleanup incomplete" : "Cleanup verified",
      state: cleanupFailed ? "failed" : cleanupDone ? "done" : "pending",
    },
  ];
}

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
  const showRevocationSteps = Boolean(
    item.revocation || record.cause === "Revoked",
  );

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
      {showRevocationSteps ? (
        <ol
          aria-label="Revocation progress"
          className="mt-4 grid list-none gap-2 rounded-sm border border-seam bg-canvas p-3 sm:grid-cols-3"
        >
          {revocationSteps(item).map((step) => {
            const StepIcon =
              step.state === "done"
                ? CheckCircleIcon
                : step.state === "failed"
                  ? WarningIcon
                  : ClockIcon;
            const tone =
              step.state === "done"
                ? "text-success"
                : step.state === "failed"
                  ? "text-danger"
                  : "text-warning";
            return (
              <li
                key={step.label}
                className={
                  "flex items-center gap-1.5 text-[13px] font-medium " + tone
                }
              >
                <StepIcon size={16} aria-hidden />
                <span>{step.label}</span>
              </li>
            );
          })}
        </ol>
      ) : null}
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
