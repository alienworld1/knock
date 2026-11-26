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
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-2 whitespace-normal">
      <code>{value}</code>
      <span className="inline-flex items-center gap-1.5">
        <button
          type="button"
          className="inline-flex min-h-8 items-center gap-1 px-2 py-1 text-xs max-md:min-h-11"
          aria-label={copied ? "Copied " + label : "Copy " + label}
          onClick={() => void copy()}
        >
          {copied ? (
            <>
              <CheckIcon size={14} aria-hidden /> Copied
            </>
          ) : (
            <>
              <CopyIcon size={14} aria-hidden /> Copy
            </>
          )}
        </button>
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
      <span className="sr-only" role="status">
        {copied ? "Copied " + label : ""}
      </span>
    </span>
  );
}
