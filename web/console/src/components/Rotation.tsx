import { actions, panel, primary } from "./classes";
import { useState } from "react";
import type { Door } from "../api";
import type { Confirm } from "./ConfirmDialog";
import { Fields } from "./Fields";
import { label } from "../format";
export function Rotation({
  door,
  confirm,
  refresh,
}: {
  door: Door;
  confirm: Confirm;
  refresh: () => void;
}) {
  const [epoch, setEpoch] = useState("");
  const [members, setMembers] = useState("");
  const [clear, setClear] = useState(false);
  return (
    <details className={panel}>
      <summary>Audit membership</summary>
      <form
        className="grid gap-2 [&>label:not(:last-of-type)]:grid [&>label:not(:last-of-type)]:gap-1 [&>p]:mb-2 [&>p]:text-muted"
        onSubmit={(event) => {
          event.preventDefault();
          const accounts = clear
            ? []
            : members
                .trim()
                .split(/[\s,]+/)
                .filter(Boolean);
          confirm({
            title: "Request rotation",
            path: "rotation",
            body: { door: door.target, epoch, members: accounts, clear },
            scope: (
              <>
                <Fields
                  items={[
                    ["Door", label(door)],
                    ["Current epoch", epoch],
                    [
                      "New membership",
                      clear ? (
                        "No auditors"
                      ) : (
                        <ul className="m-0 list-disc ps-4">
                          {accounts.map((account, i) => (
                            <li key={i}>
                              <code>{account}</code>
                            </li>
                          ))}
                        </ul>
                      ),
                    ],
                  ]}
                />
                <p>
                  {clear
                    ? "This pauses new receipts. Former auditors keep receipts and keys they already received."
                    : "This replaces the full membership. Removed auditors lose access to future receipts."}
                </p>
              </>
            ),
            after: refresh,
          });
        }}
      >
        <label>
          Current epoch{" "}
          <input
            value={epoch}
            onChange={(event) => setEpoch(event.target.value)}
            inputMode="numeric"
            pattern="[0-9]+"
            maxLength={20}
            required
            aria-describedby="epoch-help"
          />
        </label>
        <p id="epoch-help">
          Check the Door log for the current epoch. Use 0 for the first
          rotation.
        </p>
        <label>
          Auditor accounts{" "}
          <textarea
            className="w-full resize-y"
            value={members}
            onChange={(event) => setMembers(event.target.value)}
            required={!clear}
            disabled={clear}
            maxLength={2400}
            rows={4}
            aria-describedby="auditor-help"
          />
        </label>
        <p id="auditor-help">
          Enter the complete list of Diana accounts, one per line.
        </p>
        <label className="flex min-h-11 items-center gap-2 [&>input]:size-4.5 [&>input]:accent-action">
          <input
            type="checkbox"
            checked={clear}
            onChange={(event) => setClear(event.target.checked)}
          />{" "}
          Remove all auditors
        </label>
        <div className={actions}>
          <button className={primary} type="submit">
            Review rotation
          </button>
        </div>
      </form>
    </details>
  );
}
