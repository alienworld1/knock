import { panel, panelHeading, panelIcon, status } from "../components/classes";
import { DoorIcon } from "@phosphor-icons/react/Door";
import type { Door, DoorPolicy } from "../api";
import type { Confirm } from "../components/ConfirmDialog";
import { Evidence, Fields } from "../components/Fields";
import { duration, label, utc } from "../format";
import { Requests } from "../components/Requests";
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
            <span className={status}>
              {warning
                ? "Last verified policy"
                : !card.enabled
                  ? "Disabled"
                  : card.mode === "metered"
                    ? "Purchase required"
                    : "Approval required"}
            </span>
          </div>
          <Fields
            items={
              card.mode === "metered"
                ? [
                    ["Service", card.service],
                    ["Pass duration", duration(card.limit)],
                    ["Price", card.price + " test QOR"],
                  ]
                : [
                    ["Roles", card.roles?.join(", ") || "None"],
                    ["Access limit", duration(card.limit)],
                  ]
            }
          />
          <Evidence
            items={[
              ["Door account", <code>{door.account}</code>],
              ["Door owner", <code>{card.owner}</code>],
              ["Identity and policy", "Verified on Diana testnet"],
              ["Policy version", card.policyVersion],
              ["Door Card expires", utc(card.cardExpires)],
              ["Signing key fingerprint", <code>{card.signingKey}</code>],
              ["Registry", <code>{card.registry}</code>],
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
