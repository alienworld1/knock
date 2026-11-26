import type { ReactNode } from "react";
import { CaretRightIcon } from "@phosphor-icons/react/CaretRight";

export function Fields({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="my-4 grid gap-2 [&>div]:grid [&>div]:grid-cols-[minmax(110px,145px)_minmax(0,1fr)] [&>div]:gap-3 max-[440px]:[&>div]:grid-cols-1 max-[440px]:[&>div]:gap-0 [&_dt]:text-muted [&_dd]:m-0 [&_dd]:wrap-anywhere [&_dd]:whitespace-pre-wrap">
      {items.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Evidence({ items }: { items: [string, ReactNode][] }) {
  return (
    <details className="group mt-3 border-t border-seam">
      <summary>
        <CaretRightIcon
          size={14}
          aria-hidden
          className="motion-safe:transition-transform motion-safe:duration-180 group-open:rotate-90"
        />
        Verification details
      </summary>
      <div className="motion-safe:animate-[reveal_180ms_ease-out]">
        <Fields items={items} />
      </div>
    </details>
  );
}
