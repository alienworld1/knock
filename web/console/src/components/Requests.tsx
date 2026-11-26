import {
  actions,
  panel,
  primary,
  row,
  rowCaret,
  rowTitle,
  rows,
  section,
  sectionHeading,
  splitWorkspace,
} from "./classes";
import { useState, type ReactNode } from "react";
import { ArrowClockwiseIcon } from "@phosphor-icons/react/ArrowClockwise";
import { CaretRightIcon } from "@phosphor-icons/react/CaretRight";
import { endpoint, requests, type Door } from "../api";
import type { Confirm } from "./ConfirmDialog";
import { Copyable } from "./Copyable";
import { Evidence, Fields } from "./Fields";
import { Notice } from "./Notice";
import { StatusBadge, type StatusTone } from "./Status";
import { duration, label, short, utc } from "../format";
import { useClock } from "../useClock";
import { useRemote } from "../useRemote";

export function Requests({ door, confirm }: { door: Door; confirm: Confirm }) {
  const list = useRemote(endpoint("requests", door), requests, 6000);
  const [selection, setSelection] = useState("");
  const detail = useRemote(
    selection ? endpoint("request", door, selection) : null,
    requests,
    6000,
  );
  const selected = detail.data?.[0];
  const now = useClock();
  const pendingCount = (list.data || []).filter(
    (item) => !item.decision,
  ).length;
  const decideAt = selected ? Date.parse(selected.deadline) / 1000 : 0;
  const decideRemaining = selected
    ? Math.max(0, Math.floor(decideAt - now))
    : 0;
  const isExpired = Boolean(selected && !selected.delivered && decideAt <= now);
  const selectedStatus = selected ? requestState(selected) : undefined;

  return (
    <section className={section}>
      <div className={sectionHeading}>
        <div className="flex flex-wrap items-center gap-2.5">
          <h2>Access requests</h2>
          {pendingCount > 0 ? (
            <span className="rounded-sm border border-seam bg-surface px-2 py-0.5 text-xs font-medium text-warning">
              {pendingCount} pending
            </span>
          ) : null}
        </div>
        <button type="button" disabled={list.refreshing} onClick={list.retry}>
          <ArrowClockwiseIcon size={16} aria-hidden />{" "}
          {list.refreshing ? "Checking…" : "Refresh"}
        </button>
      </div>
      {list.loading ? <Notice>Loading access requests…</Notice> : null}
      {list.error ? <Notice error>{list.error}</Notice> : null}
      {list.data?.length === 0 && !list.error ? (
        <Notice>No pending requests for this Door.</Notice>
      ) : null}
      {list.data?.length ? (
        <div className={splitWorkspace}>
          <ul className={rows}>
            {list.data.map((item) => {
              const status = requestState(item);
              return (
                <li key={item.id}>
                  <button
                    type="button"
                    className={row}
                    aria-pressed={selection === item.id}
                    onClick={() => setSelection(item.id)}
                  >
                    <span>
                      <span className={rowTitle}>
                        {item.service || "SSH · " + item.role}
                      </span>
                      <code>{short(item.requester)}</code>
                    </span>
                    <span>{duration(item.durationSeconds)}</span>
                    <StatusBadge
                      label={status.label}
                      tone={status.tone}
                      icon={status.icon}
                    />
                    <CaretRightIcon
                      size={16}
                      aria-hidden
                      className={rowCaret}
                    />
                  </button>
                </li>
              );
            })}
          </ul>
          {detail.loading ? (
            <Notice>Verifying the selected request…</Notice>
          ) : detail.error ? (
            <Notice error retry={detail.retry}>
              {detail.error}
            </Notice>
          ) : selected && selectedStatus ? (
            <section
              className={panel + " motion-safe:animate-[reveal_140ms_ease-out]"}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3>Review request</h3>
                <StatusBadge
                  label={isExpired ? "Request expired" : selectedStatus.label}
                  tone={isExpired ? "danger" : selectedStatus.tone}
                  icon={isExpired ? undefined : selectedStatus.icon}
                />
              </div>
              {selected.reason ? (
                <div className="mt-4 rounded-sm border border-seam border-l-[3px] border-l-brass bg-canvas px-3.5 py-3">
                  <div className="mb-1 text-xs font-medium text-muted">
                    Reason
                  </div>
                  <p className="m-0 wrap-anywhere whitespace-pre-wrap">
                    {selected.reason}
                  </p>
                </div>
              ) : null}
              <Fields
                items={[
                  [
                    "Requester",
                    <Copyable
                      value={selected.requester}
                      label="requester account"
                    />,
                  ],
                  ["Identity", "Verified on Diana testnet"],
                  ["Scope", selected.service || "SSH · " + selected.role],
                  ["Requested access", duration(selected.durationSeconds)],
                  [
                    "Decide by",
                    !selected.delivered && decideRemaining > 0
                      ? duration(decideRemaining) + " left · " + utc(decideAt)
                      : utc(decideAt),
                  ],
                  [
                    "Decision",
                    isExpired ? "Request expired" : selectedStatus.label,
                  ],
                ]}
              />
              {isExpired ? (
                <Notice tone="warning">
                  This request expired. No access was granted.
                </Notice>
              ) : null}
              <Evidence
                items={[
                  [
                    "Request ID",
                    <Copyable value={selected.id} label="request ID" />,
                  ],
                  [
                    "Door account",
                    <Copyable value={door.account} label="Door account" />,
                  ],
                ]}
              />
              {selected.delivered || isExpired ? null : (
                <div className={actions}>
                  {(["deny", "approve"] as const)
                    .filter(
                      (outcome) =>
                        !selected.decision || selected.decision === outcome,
                    )
                    .map((outcome) => {
                      const granted = duration(selected.durationSeconds);
                      const buttonLabel = selected.decision
                        ? outcome === "deny"
                          ? "Retry denial"
                          : "Retry grant"
                        : outcome === "deny"
                          ? "Deny"
                          : "Grant " + granted;
                      const dialogTitle =
                        outcome === "deny"
                          ? "Deny request"
                          : "Grant " + granted + " access";
                      const confirmLabel =
                        outcome === "deny"
                          ? "Deny request"
                          : "Grant " + granted;
                      return (
                        <button
                          key={outcome}
                          type="button"
                          className={outcome === "approve" ? primary : ""}
                          onClick={() =>
                            confirm({
                              title: dialogTitle,
                              confirmLabel,
                              busyLabel: "Sending…",
                              path: "decision",
                              body: {
                                door: door.target,
                                id: selected.id,
                                decision: outcome,
                              },
                              scope: (
                                <Fields
                                  items={[
                                    ["Door", label(door)],
                                    [
                                      "Requester",
                                      <code>{selected.requester}</code>,
                                    ],
                                    [
                                      "Scope",
                                      selected.service ||
                                        "SSH · " + selected.role,
                                    ],
                                    ["Duration", granted],
                                    ...(selected.reason
                                      ? [
                                          ["Reason", selected.reason] as [
                                            string,
                                            ReactNode,
                                          ],
                                        ]
                                      : []),
                                  ]}
                                />
                              ),
                              after: () => {
                                list.retry();
                                detail.retry();
                              },
                            })
                          }
                        >
                          {buttonLabel}
                        </button>
                      );
                    })}
                </div>
              )}
            </section>
          ) : (
            <div className={panel + " hidden text-muted xl:block"}>
              Select a request to read the reason and decide.
            </div>
          )}
        </div>
      ) : null}
    </section>
  );
}

function requestState(item: {
  decision?: "approve" | "deny";
  delivered: boolean;
}): { label: string; tone: StatusTone; icon?: "clock" | "alert" } {
  if (!item.decision)
    return { label: "Waiting for decision", tone: "warning", icon: "clock" };
  if (!item.delivered)
    return { label: "Delivery unconfirmed", tone: "warning", icon: "alert" };
  return item.decision === "deny"
    ? { label: "Denial sent", tone: "neutral" }
    : { label: "Approval sent", tone: "success" };
}
