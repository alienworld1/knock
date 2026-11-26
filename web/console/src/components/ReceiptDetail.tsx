import { panel, panelHeading, panelIcon } from "./classes";
import type { ReactNode } from "react";
import { ReceiptIcon } from "@phosphor-icons/react/Receipt";
import type { Receipt } from "../api";
import { Copyable } from "./Copyable";
import { Evidence, Fields } from "./Fields";
import { StatusBadge } from "./Status";
import { duration, short, utc } from "../format";

const zero = /^0x0+$/;

export function ReceiptDetail({ receipt: r }: { receipt: Receipt }) {
  const verifiedCleanup =
    r.Cleanup === "Closed"
      ? r.Service
        ? "Firewall, WireGuard peer, private service"
        : "Firewall, WireGuard peer, SSH authorization, contained workloads"
      : undefined;
  const corrected = !zero.test(r.Corrects) && Boolean(r.Corrects);

  return (
    <article className={panel}>
      <div className={panelHeading}>
        <div className={panelIcon}>
          <ReceiptIcon size={22} aria-hidden />
        </div>
        <div>
          <h3>Receipt details</h3>
          <code className="text-muted">
            {short(r.ID)} · Epoch {r.Epoch}
            {corrected ? " · Correction" : ""}
          </code>
        </div>
        <StatusBadge
          label={
            r.Cleanup === "Closed" ? "Closure verified" : "Cleanup incomplete"
          }
          tone={r.Cleanup === "Closed" ? "success" : "danger"}
        />
      </div>
      <Fields
        items={[
          [
            "Scope",
            r.Service ? "Private service · " + r.Service : "SSH · " + r.Role,
          ],
          ["Termination", r.Cause],
          ["Cleanup observed", utc(r.CleanupObservedAt)],
          ...(verifiedCleanup
            ? [["Verified cleanup", verifiedCleanup] as [string, ReactNode]]
            : []),
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
