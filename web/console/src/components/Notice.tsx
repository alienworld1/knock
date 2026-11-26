import type { ReactNode } from "react";
import { ArrowClockwiseIcon } from "@phosphor-icons/react/ArrowClockwise";
import { CheckCircleIcon } from "@phosphor-icons/react/CheckCircle";
import { WarningIcon } from "@phosphor-icons/react/Warning";
import { WarningCircleIcon } from "@phosphor-icons/react/WarningCircle";
import { XIcon } from "@phosphor-icons/react/X";

export type NoticeTone = "info" | "success" | "warning" | "error";

const toneStyles: Record<NoticeTone, string> = {
  info: " border-seam border-l-seam text-ink",
  success: " border-success/60 border-l-success text-success",
  warning: " border-warning/60 border-l-warning text-warning",
  error: " border-danger/60 border-l-danger text-danger",
};

export function Notice({
  children,
  error = false,
  tone,
  retry,
  dismiss,
}: {
  children: ReactNode;
  error?: boolean;
  tone?: NoticeTone;
  retry?: () => void;
  dismiss?: () => void;
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
        "flex min-w-0 flex-wrap items-center gap-2 rounded-md border border-l-[3px] bg-surface px-4 py-3 wrap-anywhere motion-safe:animate-[reveal_140ms_ease-out] [&>button]:inline-flex [&>button]:items-center [&>button]:gap-1.5" +
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
      {dismiss ? (
        <button
          type="button"
          className="min-h-8 px-2 py-1 text-xs max-md:min-h-11"
          aria-label="Dismiss notice"
          onClick={dismiss}
        >
          <XIcon aria-hidden size={14} />
        </button>
      ) : null}
    </div>
  );
}
