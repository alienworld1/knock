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
import { endpoint, history, type Door, type DoorPolicy } from "../api";
import type { Confirm } from "../components/ConfirmDialog";
import { Notice } from "../components/Notice";
import { ReceiptDetail } from "../components/ReceiptDetail";
import { Rotation } from "../components/Rotation";
import { short, utc } from "../format";
import { useRemote } from "../useRemote";
export function History({
  door,
  card,
  confirm,
}: {
  door: Door;
  card?: DoorPolicy;
  confirm: Confirm;
}) {
  const result = useRemote(endpoint("history", door), history, 10000);
  const [selection, setSelection] = useState("");
  const warning = result.error || result.data?.warning;
  const items = (result.data?.receipts || []).toSorted(
    (a, b) => b.CleanupObservedAt - a.CleanupObservedAt,
  );
  const selected = items.find((item) => item.ID === selection);
  return (
    <section className={section}>
      <div className={sectionHeading}>
        <h2>Verified receipts</h2>
        <button type="button" onClick={result.retry}>
          <ArrowClockwiseIcon size={16} aria-hidden /> Refresh
        </button>
      </div>
      {result.loading ? <Notice>Loading and verifying receipts…</Notice> : null}
      {warning ? <Notice error>{warning}</Notice> : null}
      {result.data && !items.length && !warning ? (
        <Notice>No verified receipts for this identity.</Notice>
      ) : null}
      {items.length ? (
        <ul className={rows}>
          {items.map((item) => (
            <li key={item.ID}>
              <button
                type="button"
                className={row}
                aria-pressed={selection === item.ID}
                onClick={() => setSelection(item.ID)}
              >
                <span>
                  <span className={rowTitle}>
                    {item.Service || "SSH · " + item.Role}
                  </span>
                  <code>{short(item.ID)}</code>
                </span>
                <time
                  dateTime={new Date(
                    item.CleanupObservedAt * 1000,
                  ).toISOString()}
                >
                  {utc(item.CleanupObservedAt)}
                </time>
                <span className={status}>
                  {item.Cleanup === "Closed"
                    ? "Closure verified"
                    : "Cleanup incomplete"}
                </span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      {selected ? <ReceiptDetail receipt={selected} /> : null}
      {card?.canRotate ? (
        <Rotation door={door} confirm={confirm} refresh={result.retry} />
      ) : null}
    </section>
  );
}
