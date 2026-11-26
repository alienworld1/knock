import { panel } from "./classes";
import type { ReactNode } from "react";
import type { Receipt } from "../api";
import { Evidence, Fields } from "./Fields";
import { duration, utc } from "../format";
const zero = /^0x0+$/;

export function ReceiptDetail({ receipt: r }: { receipt: Receipt }) {
  return (
    <article className={panel}>
      <h3>Receipt details</h3>
      <Fields
        items={[
          [
            "Outcome",
            r.Cleanup === "Closed" ? "Closure verified" : "Cleanup incomplete",
          ],
          ["Termination", r.Cause],
          ["Cleanup observed", utc(r.CleanupObservedAt)],
          ["Scope", r.Service || "SSH · " + r.Role],
          ["Requested duration", duration(r.RequestedSeconds)],
          [
            "Connection",
            r.ActiveObservedAt
              ? duration(r.ActualSeconds) + " observed"
              : "Unobserved",
          ],
        ]}
      />
      <Evidence
        items={[
          ["Signature", "Verified"],
          ["Audit epoch", r.Epoch],
          ["Receipt ID", <code>{r.ID}</code>],
          ["Session ID", <code>{r.Session}</code>],
          ["Request ID", <code>{r.Request}</code>],
          ["Requester", <code>{r.Requester}</code>],
          ...(r.Approver
            ? [["Approver", <code>{r.Approver}</code>] as [string, ReactNode]]
            : []),
          ...(
            [
              ["Purchase reference", r.Purchase],
              ["Consumption transaction", r.ConsumptionTx],
              ["Revocation block", r.RevocationBlock],
              ["Corrects receipt", r.Corrects],
            ] as const
          )
            .filter(([, value]) => !zero.test(value) && value)
            .map(([field, value]): [string, ReactNode] => [
              field,
              <code>{value}</code>,
            ]),
        ]}
      />
    </article>
  );
}
