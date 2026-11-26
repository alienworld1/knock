import { panel } from "./classes";
import type { ReactNode } from "react";
import type { Receipt } from "../api";
import { Copyable } from "./Copyable";
import { Evidence, Fields } from "./Fields";
import { duration, utc } from "../format";

const zero = /^0x0+$/;

export function ReceiptDetail({ receipt: r }: { receipt: Receipt }) {
  const verifiedCleanup =
    r.Cleanup === "Closed"
      ? r.Service
        ? "Firewall, WireGuard peer, private service"
        : "Firewall, WireGuard peer, SSH authorization, contained workloads"
      : undefined;

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
          ...(verifiedCleanup
            ? [["Verified cleanup", verifiedCleanup] as [string, ReactNode]]
            : []),
          [
            "Scope",
            r.Service ? "Private service · " + r.Service : "SSH · " + r.Role,
          ],
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
          ["Signature", "ML-DSA-87 + secp256k1 verified"],
          ["Audit epoch", r.Epoch],
          ["Receipt ID", <Copyable value={r.ID} label="receipt ID" />],
          ["Session ID", <Copyable value={r.Session} label="session ID" />],
          ["Request ID", <Copyable value={r.Request} label="request ID" />],
          [
            "Requester",
            <Copyable value={r.Requester} label="requester account" />,
          ],
          ...(r.Approver
            ? [
                [
                  "Approver",
                  <Copyable value={r.Approver} label="approver account" />,
                ] as [string, ReactNode],
              ]
            : []),
          ...(
            [
              ["Purchase reference", r.Purchase, undefined],
              [
                "Consumption transaction",
                r.ConsumptionTx,
                "https://dashboard.qorechain.io/explorer/tx/" + r.ConsumptionTx,
              ],
              ["Revocation block", r.RevocationBlock, undefined],
              ["Corrects receipt", r.Corrects, undefined],
            ] as const
          )
            .filter(([, value]) => !zero.test(value) && value)
            .map(([field, value, href]): [string, ReactNode] => [
              field,
              <Copyable
                value={value}
                label={field.toLowerCase()}
                href={href}
              />,
            ]),
        ]}
      />
    </article>
  );
}
