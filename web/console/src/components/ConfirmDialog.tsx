import { danger, primary } from "./classes";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, message } from "../api";
export type Action = {
  title: string;
  confirmLabel?: string;
  busyLabel?: string;
  scope: ReactNode;
  path: "decision" | "revoke" | "rotation";
  body: object;
  danger?: boolean;
  after: () => void;
};
export type Confirm = (action: Action) => void;
export function ConfirmDialog({
  action,
  close,
  report,
}: {
  action: Action;
  close: () => void;
  report: (text: string, error: boolean) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const inFlight = useRef(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const instance = dialog.current;
    instance?.showModal();
    return () => instance?.close();
  }, []);
  async function submit() {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    try {
      const result = await api("/api/" + action.path, message, {
        body: action.body,
      });
      report(result.message, false);
    } catch (err) {
      report(
        err instanceof TypeError
          ? "Connection lost. Refresh and check the outcome before continuing."
          : err instanceof Error
            ? err.message
            : "Action failed. Refresh before continuing.",
        true,
      );
    } finally {
      action.after();
      close();
    }
  }
  return (
    <dialog
      ref={dialog}
      aria-labelledby="confirm-heading"
      onCancel={(event) => {
        event.preventDefault();
        if (!inFlight.current) close();
      }}
    >
      <h2 id="confirm-heading" className="mb-3">
        {action.title}
      </h2>
      {action.scope}
      <div className="mt-5 flex flex-wrap justify-end gap-2 border-t border-seam pt-4">
        <button type="button" autoFocus onClick={close} disabled={busy}>
          Cancel
        </button>
        <button
          type="button"
          className={action.danger ? danger : primary}
          disabled={busy}
          onClick={() => void submit()}
        >
          {busy
            ? (action.busyLabel ?? "Sending…")
            : (action.confirmLabel ?? action.title)}
        </button>
      </div>
      <span className="sr-only" role="status">
        {busy ? "Sending. Wait for the result." : ""}
      </span>
    </dialog>
  );
}
