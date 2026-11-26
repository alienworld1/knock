import { useEffect, useRef, useState } from "react";
import { DoorIcon } from "@phosphor-icons/react/Door";
import { ReceiptIcon } from "@phosphor-icons/react/Receipt";
import { TimerIcon } from "@phosphor-icons/react/Timer";
import { NavLink, Navigate, Route, Routes, useMatch } from "react-router";
import { doorList, endpoint, policy } from "./api";
import { ConfirmDialog, type Action } from "./components/ConfirmDialog";
import { Copyable } from "./components/Copyable";
import { Mark } from "./components/Mark";
import { Notice } from "./components/Notice";
import { label, short } from "./format";
import { Doors } from "./routes/Doors";
import { History } from "./routes/History";
import { Sessions } from "./routes/Sessions";
import { useRemote } from "./useRemote";
import { useTheme } from "./useTheme";

const views = [
  { name: "Doors", path: "/", icon: DoorIcon },
  { name: "Sessions", path: "/sessions", icon: TimerIcon },
  { name: "History", path: "/history", icon: ReceiptIcon },
];

export function Console() {
  const sessions = useMatch("/sessions");
  const history = useMatch("/history");
  const title = sessions ? "Sessions" : history ? "History" : "Doors";
  const [theme, setTheme] = useTheme();
  const [target, setTarget] = useState("");
  const [action, setAction] = useState<Action>();
  const [notice, setNotice] = useState<{ text: string; error: boolean }>();
  const local = useRemote("/api/doors", doorList);
  const doors = local.data?.doors || [];
  const door = doors.find((item) => item.target === target) ?? doors[0];
  const card = useRemote(door ? endpoint("door", door) : null, policy, 15000);
  const heading = useRef<HTMLHeadingElement>(null);
  const actionTrigger = useRef<HTMLElement>(null);

  useEffect(() => {
    document.title = title + " — Knock";
  }, [title]);

  function confirm(next: Action) {
    actionTrigger.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    setAction(next);
  }

  function closeConfirmation() {
    const trigger = actionTrigger.current;
    setAction(undefined);
    window.requestAnimationFrame(() =>
      (trigger?.isConnected ? trigger : heading.current)?.focus(),
    );
  }

  return (
    <div className="grid min-h-dvh grid-cols-[224px_minmax(0,1fr)] max-md:block">
      <a
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-10 focus:bg-surface focus:p-2"
        href="#workspace"
      >
        Skip to content
      </a>
      <aside className="sticky top-0 flex min-h-dvh min-w-0 flex-col gap-6 self-start border-r border-seam bg-surface px-4 pt-7 pb-6 max-md:static max-md:grid max-md:min-h-0 max-md:grid-cols-[minmax(0,1fr)_auto] max-md:items-center max-md:gap-2 max-md:border-r-0 max-md:border-b max-md:py-3">
        <Mark />
        <nav
          aria-label="Workspace"
          className="grid gap-1 max-md:col-span-2 max-md:row-start-2 max-md:grid-cols-3"
        >
          {views.map(({ name, path, icon: Icon }) => (
            <NavLink
              end
              className="flex min-h-11 items-center gap-2.5 rounded-sm border border-transparent px-3 py-2 text-start text-ink hover:bg-elevated aria-[current=page]:border-control aria-[current=page]:bg-elevated aria-[current=page]:[&_svg]:text-brass max-md:justify-center max-md:gap-1 max-md:px-1"
              to={path}
              key={path}
              onClick={(event) => {
                if (
                  event.ctrlKey ||
                  event.metaKey ||
                  event.shiftKey ||
                  event.altKey
                )
                  return;
                setNotice(undefined);
                window.requestAnimationFrame(() => heading.current?.focus());
              }}
            >
              <Icon size={20} aria-hidden /> {name}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto grid gap-1.5 text-muted max-md:col-start-2 max-md:row-start-1 max-md:mt-0 max-md:flex max-md:items-center max-md:gap-2 max-md:[&>select]:px-1.5">
          <p className="text-xs max-md:hidden">
            Local loopback · Keys stay in knock
          </p>
          <label htmlFor="console-theme">Theme</label>
          <select
            id="console-theme"
            value={theme}
            onChange={(event) => {
              const value = event.target.value;
              if (value === "dark" || value === "light" || value === "system")
                setTheme(value);
            }}
          >
            <option value="dark">Dark</option>
            <option value="light">Light</option>
            <option value="system">System</option>
          </select>
        </div>
      </aside>
      <main
        id="workspace"
        className="grid w-full max-w-5xl content-start gap-4 px-8 pt-7 pb-12 max-md:px-4 max-md:pt-4 max-md:pb-8"
      >
        <header className="flex items-start justify-between gap-4 border-b border-seam pb-4 max-md:flex-col max-md:gap-1 [&_p]:text-muted">
          <div>
            <h1 ref={heading} tabIndex={-1}>
              {title}
            </h1>
            <p>Diana testnet</p>
          </div>
          {local.data ? (
            <details className="min-w-0 max-w-[380px] text-end text-muted max-md:text-start">
              <summary>
                Operator · <code>{short(local.data.identity)}</code>
              </summary>
              <div className="mt-1 text-start">
                <Copyable
                  value={local.data.identity}
                  label="operator account"
                />
              </div>
            </details>
          ) : null}
        </header>
        {local.loading ? <Notice>Loading local Door Cards…</Notice> : null}
        {local.error ? (
          <Notice error retry={local.retry}>
            {local.error}
          </Notice>
        ) : null}
        {!door && local.data && !local.error ? (
          <Notice>
            No Door Cards. Add a signed Card to the configured cards directory.
          </Notice>
        ) : null}
        {door ? (
          <>
            <div className="flex min-w-0 items-center gap-3 text-muted [&>select]:min-w-0 [&>select]:max-w-[min(100%,430px)] [&>select]:truncate">
              <label htmlFor="console-door">Door</label>
              <select
                id="console-door"
                value={door.target}
                onChange={(event) => {
                  setTarget(event.target.value);
                  setNotice(undefined);
                }}
              >
                {doors.map((item) => (
                  <option value={item.target} key={item.target}>
                    {label(item)}
                  </option>
                ))}
              </select>
            </div>
            {notice ? (
              <Notice tone={notice.error ? "error" : "success"}>
                {notice.text}
              </Notice>
            ) : null}
            {card.loading ? (
              <Notice>Verifying the Door Card on Diana…</Notice>
            ) : null}
            {card.error ? (
              <Notice error retry={card.retry}>
                {card.error}
              </Notice>
            ) : null}
            <Routes>
              <Route
                index
                element={
                  <Doors
                    door={door}
                    card={card.data}
                    warning={card.error}
                    confirm={confirm}
                  />
                }
              />
              <Route
                path="sessions"
                element={
                  <Sessions key={door.target} door={door} confirm={confirm} />
                }
              />
              <Route
                path="history"
                element={
                  <History
                    key={door.target}
                    door={door}
                    card={card.error ? undefined : card.data}
                    confirm={confirm}
                  />
                }
              />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </>
        ) : null}
      </main>
      {action ? (
        <ConfirmDialog
          action={action}
          close={closeConfirmation}
          report={(text, error) => setNotice({ text, error })}
        />
      ) : null}
    </div>
  );
}
