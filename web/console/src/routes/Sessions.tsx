import {
  row,
  rowCaret,
  rowTitle,
  rows,
  section,
  sectionHeading,
  splitWorkspace,
} from "../components/classes";
import { useState } from "react";
import { ArrowClockwiseIcon } from "@phosphor-icons/react/ArrowClockwise";
import { CaretRightIcon } from "@phosphor-icons/react/CaretRight";
import { endpoint, sessions, type Door } from "../api";
import type { Confirm } from "../components/ConfirmDialog";
import { Fields } from "../components/Fields";
import { Notice } from "../components/Notice";
import { SessionDetail } from "../components/SessionDetail";
import { StatusBadge } from "../components/Status";
import { label, short } from "../format";
import { describeSession, sessionTone } from "../session";
import { useClock } from "../useClock";
import { useRemote } from "../useRemote";

export function Sessions({ door, confirm }: { door: Door; confirm: Confirm }) {
  const updates = useRemote(endpoint("sessions", door), sessions, 3000);
  const [selection, setSelection] = useState("");
  const items = updates.data?.sessions || [];

  const selected =
    items.find((item) => item.sessionId === selection) ?? items[0];
  const warning = updates.error || updates.data?.warning;
  const now = useClock();

  const selectedScope = selected?.lastVerified?.service
    ? "Private service · " + selected.lastVerified.service
    : selected?.lastVerified?.role
      ? "SSH · " + selected.lastVerified.role
      : "Session";

  return (
    <section className={section}>
      <div className={sectionHeading}>
        <h2>Session status</h2>
        <button
          type="button"
          disabled={updates.refreshing}
          onClick={updates.retry}
        >
          <ArrowClockwiseIcon size={16} aria-hidden />{" "}
          {updates.refreshing ? "Checking…" : "Refresh"}
        </button>
      </div>
      {updates.loading ? <Notice>Loading signed Door status…</Notice> : null}
      {warning ? <Notice error>{warning}</Notice> : null}
      {!items.length && !warning && !updates.loading ? (
        <Notice>No active or recent sessions for this identity.</Notice>
      ) : null}
      {selected ? (
        <div
          className={items.length > 1 ? splitWorkspace : "grid min-w-0 gap-4"}
        >
          {items.length > 1 ? (
            <ul className={rows}>
              {items.map((item) => {
                const described = describeSession(item, now, Boolean(warning));
                const visual = sessionTone(described.state);
                return (
                  <li key={item.sessionId}>
                    <button
                      type="button"
                      className={row}
                      aria-pressed={selected.sessionId === item.sessionId}
                      onClick={() => setSelection(item.sessionId)}
                    >
                      <span>
                        <span className={rowTitle}>
                          {item.lastVerified?.service
                            ? "Private service · " + item.lastVerified.service
                            : item.lastVerified?.role
                              ? "SSH · " + item.lastVerified.role
                              : "Session"}
                        </span>
                        <code>{short(item.sessionId)}</code>
                      </span>
                      <StatusBadge
                        label={described.state}
                        tone={visual.tone}
                        icon={visual.icon}
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
          ) : null}
          <SessionDetail
            item={selected}
            now={now}
            stale={Boolean(warning)}
            revoke={() =>
              confirm({
                title: "Revoke access",
                confirmLabel: "Revoke access",
                busyLabel: "Revoking…",
                path: "revoke",
                danger: true,
                body: { door: door.target, id: selected.sessionId },
                scope: (
                  <>
                    <p>
                      This revokes only this session on Diana. Access ends after
                      the Door observes the revocation and verifies cleanup.
                    </p>
                    <Fields
                      items={[
                        ["Door", label(door)],
                        ["Scope", selectedScope],
                        ["Session", <code>{selected.sessionId}</code>],
                      ]}
                    />
                  </>
                ),
                after: updates.retry,
              })
            }
          />
        </div>
      ) : null}
    </section>
  );
}
