import { panel, panelHeading, panelIcon } from "../components/classes";
import type { ReactNode } from "react";
import { DoorIcon } from "@phosphor-icons/react/Door";
import type { Door, DoorPolicy } from "../api";
import type { Confirm } from "../components/ConfirmDialog";
import { Copyable } from "../components/Copyable";
import { Evidence, Fields } from "../components/Fields";
import { Requests } from "../components/Requests";
import { StatusBadge } from "../components/Status";
import { duration, label, utc } from "../format";

function operatorAccess(card: DoorPolicy) {
  if (card.canRotate && card.canReview) return "Owner and approver";
  if (card.canRotate) return "Owner";
  if (card.canReview && card.canRevoke) return "Approver and revoker";
  if (card.canReview) return "Approver";
  if (card.canRevoke) return "Revoker";
  return "Read-only";
}

export function Doors({
  door,
  card,
  warning,
  confirm,
}: {
  door: Door;
  card?: DoorPolicy;
  warning?: string;
  confirm: Confirm;
}) {
  const statusLabel = warning
    ? "Last verified policy"
    : !card?.enabled
      ? "Disabled"
      : card.mode === "metered"
        ? "Purchase required"
        : "Approval required";
  const statusTone = warning
    ? "warning"
    : !card?.enabled
      ? "danger"
      : "neutral";

  return (
    <>
      {card ? (
        <section className={panel}>
          <div className={panelHeading}>
            <div className={panelIcon}>
              <DoorIcon size={22} aria-hidden />
            </div>
            <div>
              <h2>{label(door)}</h2>
              <p className="text-muted">
                {card.mode === "metered" ? "Metered Door" : "Approval Door"}
              </p>
            </div>
            <StatusBadge
              label={statusLabel}
              tone={statusTone}
              icon={warning ? "alert" : undefined}
            />
          </div>
          <Fields
            items={
              card.mode === "metered"
                ? [
                    ["Service", card.service],
                    ["Pass duration", duration(card.limit)],
                    ["Price", card.price + " test QOR"],
                    ["Your access", operatorAccess(card)],
                  ]
                : [
                    ["Roles", card.roles?.join(", ") || "None"],
                    ["Access limit", duration(card.limit)],
                    ...(card.approvers !== undefined
                      ? [
                          [
                            "Approvers",
                            card.approvers.length + " configured",
                          ] as [string, ReactNode],
                        ]
                      : []),
                    ...(card.approversCanRevoke !== undefined
                      ? [
                          [
                            "Revocation",
                            card.approversCanRevoke
                              ? "Owner and approvers"
                              : "Owner only",
                          ] as [string, ReactNode],
                        ]
                      : []),
                    ["Your access", operatorAccess(card)],
                  ]
            }
          />
          <Evidence
            items={[
              [
                "Door account",
                <Copyable value={door.account} label="Door account" />,
              ],
              [
                "Door owner",
                <Copyable value={card.owner} label="Door owner" />,
              ],
              ...(card.beneficiary
                ? [
                    [
                      "Beneficiary",
                      <Copyable value={card.beneficiary} label="beneficiary" />,
                    ] as [string, ReactNode],
                  ]
                : []),
              ...(card.approvers?.length
                ? [
                    [
                      "Approver accounts",
                      <ul className="m-0 grid list-none gap-1 p-0">
                        {card.approvers.map((account) => (
                          <li key={account}>
                            <Copyable
                              value={account}
                              label="approver account"
                            />
                          </li>
                        ))}
                      </ul>,
                    ] as [string, ReactNode],
                  ]
                : []),
              ["Identity and policy", "Verified on Diana testnet"],
              ["Policy version", card.policyVersion],
              ["Door Card expires", utc(card.cardExpires)],
              [
                "Signing key fingerprint",
                <Copyable
                  value={card.signingKey}
                  label="signing key fingerprint"
                />,
              ],
              [
                "Registry",
                <Copyable
                  value={card.registry}
                  label="registry contract"
                  href={"https://explore.qore.network/address/" + card.registry}
                />,
              ],
            ]}
          />
        </section>
      ) : null}
      {card?.canReview && !warning ? (
        <Requests key={door.target} door={door} confirm={confirm} />
      ) : null}
    </>
  );
}
