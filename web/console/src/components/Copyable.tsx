import { useEffect, useState } from "react";
import { ArrowSquareOutIcon } from "@phosphor-icons/react/ArrowSquareOut";
import { CheckIcon } from "@phosphor-icons/react/Check";
import { CopyIcon } from "@phosphor-icons/react/Copy";

export function Copyable({
  value,
  label,
  href,
}: {
  value: string;
  label: string;
  href?: string;
}) {
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-2 whitespace-normal">
      <code>{value}</code>
      <span className="inline-flex items-center gap-1.5">
        <CopyButton key={value} value={value} label={label} />
        {href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex min-h-8 items-center gap-1 rounded-sm border border-control bg-surface px-2 py-1 text-xs text-brass hover:bg-elevated max-md:min-h-11"
            aria-label={"Open " + label + " on Diana explorer"}
          >
            <ArrowSquareOutIcon size={14} aria-hidden /> Explorer
          </a>
        ) : null}
      </span>
    </span>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [status, setStatus] = useState<"copied" | "failed">();

  useEffect(() => {
    if (status !== "copied") return;
    const timer = window.setTimeout(() => setStatus(undefined), 2000);
    return () => window.clearTimeout(timer);
  }, [status]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setStatus("copied");
    } catch {
      setStatus("failed");
    }
  }

  return (
    <>
      <button
        type="button"
        className={
          "inline-flex min-h-8 items-center gap-1 px-2 py-1 text-xs max-md:min-h-11" +
          (status === "copied" ? " border-success/70 text-success" : "")
        }
        aria-label={"Copy " + label}
        onClick={() => void copy()}
      >
        {status === "copied" ? (
          <>
            <CheckIcon size={14} aria-hidden /> Copied
          </>
        ) : (
          <>
            <CopyIcon size={14} aria-hidden /> Copy
          </>
        )}
      </button>
      <span
        className={status === "failed" ? "text-xs text-danger" : "sr-only"}
        role="status"
      >
        {status === "failed"
          ? "Couldn't copy. Select and copy the value."
          : status === "copied"
            ? "Copied " + label
            : ""}
      </span>
    </>
  );
}
