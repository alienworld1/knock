import type { ReactNode } from "react";
import { ArrowClockwiseIcon } from "@phosphor-icons/react/ArrowClockwise";
import { WarningCircleIcon } from "@phosphor-icons/react/WarningCircle";
export function Notice({
  children,
  error = false,
  retry,
}: {
  children: ReactNode;
  error?: boolean;
  retry?: () => void;
}) {
  return (
    <div
      className={
        "flex min-w-0 flex-wrap items-center gap-2 rounded-md border border-seam bg-surface px-4 py-3 wrap-anywhere [&>button]:inline-flex [&>button]:items-center [&>button]:gap-1.5" +
        (error ? " text-warning" : "")
      }
    >
      {error ? <WarningCircleIcon aria-hidden size={18} /> : null}
      <div className="flex-[1_1_160px]" role="status">
        {children}
      </div>
      {retry ? (
        <button type="button" onClick={retry}>
          <ArrowClockwiseIcon aria-hidden size={16} /> Refresh
        </button>
      ) : null}
    </div>
  );
}
