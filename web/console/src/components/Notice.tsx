import type { ReactNode } from "react";
import { ArrowClockwiseIcon } from "@phosphor-icons/react/ArrowClockwise";
import { CheckCircleIcon } from "@phosphor-icons/react/CheckCircle";
import { WarningIcon } from "@phosphor-icons/react/Warning";
import { WarningCircleIcon } from "@phosphor-icons/react/WarningCircle";

export type NoticeTone = "info" | "success" | "warning" | "error";

const toneStyles: Record<NoticeTone, string> = {
  info: " border-seam text-ink",
  success: " border-success/60 text-success",
  warning: " border-warning/60 text-warning",
  error: " border-danger/60 text-danger",
};

export function Notice({
  children,
  error = false,
  tone,
  retry,
}: {
  children: ReactNode;
  error?: boolean;
  tone?: NoticeTone;
  retry?: () => void;
}) {
  const resolved: NoticeTone = tone ?? (error ? "warning" : "info");
  const Icon =
    resolved === "error"
      ? WarningIcon
      : resolved === "warning"
        ? WarningCircleIcon
        : resolved === "success"
          ? CheckCircleIcon
          : null;
  return (
    <div
      className={
        "flex min-w-0 flex-wrap items-center gap-2 rounded-md border bg-surface px-4 py-3 wrap-anywhere [&>button]:inline-flex [&>button]:items-center [&>button]:gap-1.5" +
        toneStyles[resolved]
      }
    >
      {Icon ? <Icon aria-hidden size={18} /> : null}
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
