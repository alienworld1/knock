import type { ReactNode } from "react";
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
    <details className="mt-3 border-t border-seam">
      <summary>Verification details</summary>
      <Fields items={items} />
    </details>
  );
}
