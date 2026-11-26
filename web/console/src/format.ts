import type { Door } from "./api";
export const clock = () => Math.floor(Date.now() / 1000);
export const utc = (seconds: number) =>
  new Date(seconds * 1000).toISOString().slice(0, 19).replace("T", " ") +
  " UTC";
export const duration = (seconds: number) =>
  [
    Math.floor(seconds / 3600) ? Math.floor(seconds / 3600) + "h" : "",
    Math.floor((seconds % 3600) / 60)
      ? Math.floor((seconds % 3600) / 60) + "m"
      : "",
    seconds % 60 || seconds === 0 ? (seconds % 60) + "s" : "",
  ]
    .filter(Boolean)
    .join(" ");
export const label = (door: Door) => door.alias || door.account;
export const short = (id: string) =>
  id.length > 24 ? id.slice(0, 11) + "…" + id.slice(-8) : id;
