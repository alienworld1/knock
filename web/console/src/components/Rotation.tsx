import { actions, panel, primary } from "./classes";
import { useState } from "react";
import type { Door } from "../api";
import type { Confirm } from "./ConfirmDialog";
import { Fields } from "./Fields";
import { label } from "../format";

const accountPattern = /^qor1[a-z0-9]{38,64}$/;

export function Rotation({
  door,
  latestEpoch = 0,
  confirm,
  refresh,
}: {
  door: Door;
  latestEpoch?: number;
  confirm: Confirm;
  refresh: () => void;
}) {
  const [epoch, setEpoch] = useState("");
  const [members, setMembers] = useState("");
  const [clear, setClear] = useState(false);
  const [error, setError] = useState("");

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
          if (!clear) {
            if (accounts.length > 16) {
              setError("Enter at most 16 auditor accounts.");
              return;
            }
            const invalid = accounts.find((a) => !accountPattern.test(a));
            if (invalid) {
              setError("Enter valid qor1 Diana account addresses.");
              return;
            }
            if (new Set(accounts).size !== accounts.length) {
              setError("Remove duplicate auditor accounts.");
              return;
            }
          }
          setError("");
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
            onChange={(event) => {
              setEpoch(event.target.value);
              setError("");
            }}
            inputMode="numeric"
            pattern="[0-9]+"
            maxLength={20}
            required
            aria-describedby="epoch-help"
          />
        </label>
        <p id="epoch-help">
          {latestEpoch > 0
            ? `Highest receipt epoch seen: ${latestEpoch}. Confirm the Door's committed epoch in its log.`
            : "Check the Door log for the current epoch. Use 0 for the first rotation."}
        </p>
        <label>
          Auditor accounts{" "}
          <textarea
            className="w-full resize-y"
            value={members}
            onChange={(event) => {
              setMembers(event.target.value);
              setError("");
            }}
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
            onChange={(event) => {
              setClear(event.target.checked);
              setError("");
            }}
          />{" "}
          Remove all auditors
        </label>
        {error ? (
          <p role="alert" className="text-danger!">
            {error}
          </p>
        ) : null}
        <div className={actions}>
          <button className={primary} type="submit">
            Review rotation
          </button>
        </div>
      </form>
    </details>
  );
}
