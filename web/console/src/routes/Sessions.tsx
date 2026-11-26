import {
  row,
  rowTitle,
  rows,
  section,
  sectionHeading,
  status,
} from "../components/classes";
import { useState } from "react";
import { ArrowClockwiseIcon } from "@phosphor-icons/react/ArrowClockwise";
import { endpoint, sessions, type Door } from "../api";
import type { Confirm } from "../components/ConfirmDialog";
import { Fields } from "../components/Fields";
import { Notice } from "../components/Notice";
import { SessionDetail } from "../components/SessionDetail";
import { label, short } from "../format";
import { describeSession } from "../session";
import { useClock } from "../useClock";
import { useRemote } from "../useRemote";
export function Sessions({ door, confirm }: { door: Door; confirm: Confirm }) {
  const updates = useRemote(endpoint("sessions", door), sessions, 5000);
  const [selection, setSelection] = useState("");
  const items = updates.data?.sessions || [];
  const selected =
    items.find((item) => item.sessionId === selection) ?? items[0];
  const warning = updates.error || updates.data?.warning;
  const now = useClock();
  return (
    <section className={section}>
      <div className={sectionHeading}>
        <h2>Session status</h2>
        <button type="button" onClick={updates.retry}>
          <ArrowClockwiseIcon size={16} aria-hidden /> Refresh
        </button>
      </div>
      {updates.loading ? <Notice>Loading signed Door status…</Notice> : null}
      {warning ? <Notice error>{warning}</Notice> : null}
      {!items.length && !warning && !updates.loading ? (
        <Notice>No verified sessions for this identity.</Notice>
      ) : null}
      {selected ? (
        <SessionDetail
          item={selected}
          now={now}
          stale={Boolean(warning)}
          revoke={() =>
            confirm({
              title: "Revoke access",
              path: "revoke",
              danger: true,
              body: { door: door.target, id: selected.sessionId },
              scope: (
                <>
                  <p>
                    Revoke this session on Diana. Watch for signed closure from
                    the Door.
                  </p>
                  <Fields
                    items={[
                      ["Door", label(door)],
                      ["Session", <code>{selected.sessionId}</code>],
                    ]}
                  />
                </>
              ),
              after: updates.retry,
            })
          }
        />
      ) : null}
      {items.length > 1 ? (
        <ul className={rows}>
          {items.map((item) => (
            <li key={item.sessionId}>
              <button
                type="button"
                className={row}
                aria-pressed={selected?.sessionId === item.sessionId}
                onClick={() => setSelection(item.sessionId)}
              >
                <span>
                  <span className={rowTitle}>
                    {item.lastVerified?.service ||
                      item.lastVerified?.role ||
                      "Session"}
                  </span>
                  <code>{short(item.sessionId)}</code>
                </span>
                <span className={status}>
                  {describeSession(item, now, Boolean(warning)).state}
                </span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
