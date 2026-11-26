import {
  actions,
  panel,
  primary,
  row,
  rowTitle,
  rows,
  section,
  sectionHeading,
  status,
} from "./classes";
import { useState } from "react";
import { ArrowClockwiseIcon } from "@phosphor-icons/react/ArrowClockwise";
import { endpoint, requests, type Door } from "../api";
import type { Confirm } from "./ConfirmDialog";
import { Evidence, Fields } from "./Fields";
import { Notice } from "./Notice";
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
  return (
    <section className={section}>
      <div className={sectionHeading}>
        <h2>Access requests</h2>
        <button type="button" onClick={list.retry}>
          <ArrowClockwiseIcon size={16} aria-hidden /> Refresh
        </button>
      </div>
      {list.loading ? <Notice>Loading access requests…</Notice> : null}
      {list.error ? <Notice error>{list.error}</Notice> : null}
      {list.data?.length === 0 && !list.error ? (
        <Notice>No verified requests.</Notice>
      ) : null}
      {list.data?.length ? (
        <ul className={rows}>
          {list.data.map((item) => (
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
                <span className={status}>{requestState(item)}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      {detail.loading ? <Notice>Verifying the selected request…</Notice> : null}
      {detail.error ? (
        <Notice error retry={detail.retry}>
          {detail.error}
        </Notice>
      ) : null}
      {selected && !detail.error ? (
        <section className={panel}>
          <h3>Review request</h3>
          <Fields
            items={[
              ["Requester", <code>{selected.requester}</code>],
              ["Scope", selected.service || "SSH · " + selected.role],
              ["Requested access", duration(selected.durationSeconds)],
              ["Decide by", utc(Date.parse(selected.deadline) / 1000)],
              ["Reason", selected.reason],
              ["Decision", requestState(selected)],
            ]}
          />
          <Evidence
            items={[
              ["Request ID", <code>{selected.id}</code>],
              ["Door account", <code>{door.account}</code>],
            ]}
          />
          {selected.delivered ||
          Date.parse(selected.deadline) <= now * 1000 ? null : (
            <div className={actions}>
              {(["deny", "approve"] as const)
                .filter(
                  (outcome) =>
                    !selected.decision || selected.decision === outcome,
                )
                .map((outcome) => {
                  const title =
                    (selected.decision ? "Retry " : "") +
                    (outcome === "deny" ? "Deny request" : "Approve request");
                  return (
                    <button
                      key={outcome}
                      type="button"
                      className={outcome === "approve" ? primary : ""}
                      onClick={() =>
                        confirm({
                          title,
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
                                  selected.service || "SSH · " + selected.role,
                                ],
                                [
                                  "Duration",
                                  duration(selected.durationSeconds),
                                ],
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
                      {title}
                    </button>
                  );
                })}
            </div>
          )}
        </section>
      ) : null}
    </section>
  );
}

function requestState(item: {
  decision?: "approve" | "deny";
  delivered: boolean;
}) {
  if (!item.decision) return "Waiting for decision";
  if (!item.delivered) return "Delivery unconfirmed";
  return item.decision === "deny" ? "Denial sent" : "Approval sent";
}
