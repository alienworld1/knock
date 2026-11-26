import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { startSession } from "./api";
import { Console } from "./Console";
import { Mark } from "./components/Mark";
import { Notice } from "./components/Notice";
import "./style.css";
const root = createRoot(document.getElementById("root") ?? document.body);
root.render(
  <main className="mx-auto my-8 grid max-w-[560px] gap-4 p-4">
    <Mark />
    <Notice>Opening local console…</Notice>
  </main>,
);
void startSession().then(
  () =>
    root.render(
      <BrowserRouter>
        <Console />
      </BrowserRouter>,
    ),
  (err: unknown) =>
    root.render(
      <main className="mx-auto my-8 grid max-w-[560px] gap-4 p-4">
        <Mark />
        <Notice error>
          {err instanceof TypeError
            ? "Couldn't reach the console. Start knock console again."
            : err instanceof Error
              ? err.message
              : "Couldn't open the console."}
        </Notice>
      </main>,
    ),
);
