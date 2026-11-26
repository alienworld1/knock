export type Door = { target: string; account: string; alias?: string };
export type DoorPolicy = {
  mode: "approval" | "metered";
  enabled: boolean;
  policyVersion: string;
  limit: number;
  roles: string[] | null;
  service?: string;
  price?: string;
  canReview: boolean;
  canRotate: boolean;
  owner: string;
  signingKey: string;
  registry: string;
  cardExpires: number;
};
export type Request = {
  id: string;
  requester: string;
  role: string;
  service: string;
  durationSeconds: number;
  deadline: string;
  reason?: string;
  decision?: "approve" | "deny";
  delivered: boolean;
};
export type Observation = {
  state: string;
  requestId: string;
  role: string;
  service?: string;
  observed: number;
  issued?: number;
  deadline: number;
  revokedAt?: number;
  revokedBlock: string;
  closedAt?: number;
  cause?: string;
  receiptState?: string;
  chainChecked?: number;
};
export type Session = {
  sessionId: string;
  state: string;
  chainMonitoring: string;
  lastVerified?: Observation;
  revocation?: string;
  revocable: boolean;
};
export type Receipt = {
  ID: string;
  Epoch: number;
  Request: string;
  Session: string;
  Requester: string;
  Approver: string;
  Purchase: string;
  ConsumptionTx: string;
  Role: string;
  Service: string;
  Cause: string;
  Cleanup: string;
  CleanupObservedAt: number;
  ActiveObservedAt: number;
  TerminationObservedAt: number;
  ActualSeconds: number;
  RequestedSeconds: number;
  RevocationBlock: string;
  Corrects: string;
};

type RecordValue = Record<string, unknown>;
const object = (value: unknown): value is RecordValue =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const strings = (value: RecordValue, ...keys: string[]) =>
  keys.every((key) => typeof value[key] === "string");
const numbers = (value: RecordValue, ...keys: string[]) =>
  keys.every(
    (key) => Number.isSafeInteger(value[key]) && Number(value[key]) >= 0,
  );
const optional = (
  value: RecordValue,
  type: "number" | "string",
  ...keys: string[]
) =>
  keys.every((key) => value[key] === undefined || typeof value[key] === type);
const booleans = (value: RecordValue, ...keys: string[]) =>
  keys.every((key) => typeof value[key] === "boolean");
const array = <T>(
  value: unknown,
  item: (entry: unknown) => entry is T,
): value is T[] => Array.isArray(value) && value.every(item);

const door = (v: unknown): v is Door =>
  object(v) &&
  strings(v, "target", "account") &&
  optional(v, "string", "alias");
export const doorList = (
  v: unknown,
): v is { doors: Door[]; identity: string } =>
  object(v) && strings(v, "identity") && array(v.doors, door);
export const policy = (v: unknown): v is DoorPolicy =>
  object(v) &&
  (v.mode === "approval" || v.mode === "metered") &&
  booleans(v, "enabled", "canReview", "canRotate") &&
  strings(v, "policyVersion", "owner", "signingKey", "registry") &&
  numbers(v, "limit", "cardExpires") &&
  optional(v, "string", "price", "service") &&
  (v.mode !== "metered" || strings(v, "price", "service")) &&
  (v.roles === null ||
    array(v.roles, (r): r is string => typeof r === "string"));
const request = (v: unknown): v is Request =>
  object(v) &&
  strings(v, "id", "requester", "role", "service", "deadline") &&
  typeof v.deadline === "string" &&
  Number.isFinite(Date.parse(v.deadline)) &&
  numbers(v, "durationSeconds") &&
  booleans(v, "delivered") &&
  optional(v, "string", "reason") &&
  (v.decision === undefined ||
    v.decision === "approve" ||
    v.decision === "deny");
export const requests = (v: unknown): v is Request[] => array(v, request);
const observation = (v: unknown): v is Observation =>
  object(v) &&
  strings(v, "state", "requestId", "role", "revokedBlock") &&
  numbers(v, "observed", "deadline") &&
  optional(v, "number", "issued", "revokedAt", "closedAt", "chainChecked") &&
  optional(v, "string", "service", "cause", "receiptState");
const session = (v: unknown): v is Session =>
  object(v) &&
  strings(v, "sessionId", "state", "chainMonitoring") &&
  booleans(v, "revocable") &&
  optional(v, "string", "revocation") &&
  (v.lastVerified === undefined || observation(v.lastVerified));
export const sessions = (
  v: unknown,
): v is { sessions: Session[]; warning?: string } =>
  object(v) && optional(v, "string", "warning") && array(v.sessions, session);
const receipt = (v: unknown): v is Receipt =>
  object(v) &&
  strings(
    v,
    "ID",
    "Request",
    "Session",
    "Requester",
    "Approver",
    "Purchase",
    "ConsumptionTx",
    "Role",
    "Service",
    "Cause",
    "Cleanup",
    "RevocationBlock",
    "Corrects",
  ) &&
  numbers(
    v,
    "Epoch",
    "CleanupObservedAt",
    "ActiveObservedAt",
    "TerminationObservedAt",
    "ActualSeconds",
    "RequestedSeconds",
  );
export const history = (
  v: unknown,
): v is { receipts: Receipt[]; warning?: string } =>
  object(v) && optional(v, "string", "warning") && array(v.receipts, receipt);
const sessionToken = (v: unknown): v is { csrf: string } =>
  object(v) && typeof v.csrf === "string" && /^[\w-]{43}$/.test(v.csrf);
export const message = (v: unknown): v is { message: string } =>
  object(v) && strings(v, "message");

let csrf = "";

export async function api<T>(
  path: string,
  check: (body: unknown) => body is T,
  options?: { body: object; signal?: AbortSignal } | { signal: AbortSignal },
): Promise<T> {
  const headers: Record<string, string> = { "X-Knock-Console": "1" };
  const post = options && "body" in options;
  if (post) {
    headers["Content-Type"] = "application/json";
    if (csrf) headers["X-Knock-CSRF"] = csrf;
  }
  const response = await fetch(path, {
    method: post ? "POST" : "GET",
    headers,
    signal: options?.signal,
    body: post ? JSON.stringify(options.body) : undefined,
    mode: "same-origin",
    redirect: "error",
  });
  const value: unknown = await response.json();
  if (!response.ok) {
    throw new Error(
      object(value) && typeof value.error === "string"
        ? value.error
        : "Console request failed.",
    );
  }
  if (!check(value))
    throw new Error("Couldn't read the console response. Restart the console.");
  return value;
}

export async function startSession() {
  const fragment = location.hash.slice(1);
  const token = /^[\w-]{43}$/.test(fragment) ? fragment : "";
  if (token)
    window.history.replaceState(null, "", location.pathname + location.search);
  const response = token
    ? await api("/api/bootstrap", sessionToken, { body: { token } })
    : await api("/api/session", sessionToken);
  csrf = response.csrf;
}

export function endpoint(path: string, door: Door, id?: string) {
  const params = new URLSearchParams({ door: door.target });
  if (id) params.set("id", id);
  return "/api/" + path + "?" + params;
}
