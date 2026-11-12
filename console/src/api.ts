import type {
  ActionRow, AllowRow, Analysis, AuditRow, EmailAnalysis, EventDetail, EventRow, FileAnalysis, IntelHealth, MailboxStatus, UrlAnalysis,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

type Fetch = typeof fetch;

/** The only way the console talks to the core. Every call carries the token; a 401 signs you out. */
export function createApi(fetchImpl: Fetch, getToken: () => string | null, onAuthFail: () => void) {
  async function call<T>(method: string, path: string, body?: unknown, raw?: { type: string; headers?: Record<string, string> }): Promise<T> {
    const token = getToken();
    if (!token) {
      onAuthFail();
      throw new ApiError(401, "not signed in");
    }
    let response: Response;
    try {
      response = await fetchImpl(path, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { "Content-Type": raw?.type ?? "application/json" }),
          ...(raw?.headers ?? {}),
        },
        body: body === undefined ? undefined : raw ? (body as BodyInit) : JSON.stringify(body),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      });
    } catch {
      throw new ApiError(0, "The core is not reachable.");
    }
    if (response.status === 401) {
      onAuthFail();
      throw new ApiError(401, "The token was not accepted.");
    }
    if (!response.ok) {
      throw new ApiError(response.status, explain(response.status));
    }
    return (await response.json()) as T;
  }

  const q = (params: Record<string, string | number | undefined>): string => {
    const parts = Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`);
    return parts.length ? `?${parts.join("&")}` : "";
  };

  return {
    health: () => call<{ status: string }>("GET", "/health"),
    mailbox: () => call<MailboxStatus>("GET", "/v1/mailbox/status"),
    events: (state?: string, limit = 50) => call<EventRow[]>("GET", `/v1/events${q({ state, limit })}`),
    event: (id: string) => call<EventDetail>("GET", `/v1/events/${encodeURIComponent(id)}`),
    actions: (state?: string, limit = 100) => call<ActionRow[]>("GET", `/v1/actions${q({ state, limit })}`),
    approve: (id: string) => call<{ state: string; changed: boolean }>("POST", `/v1/actions/${encodeURIComponent(id)}/approve`),
    dismiss: (id: string) => call<{ state: string; changed: boolean }>("POST", `/v1/actions/${encodeURIComponent(id)}/dismiss`),
    restore: (id: string) => call<{ state: string; changed: boolean }>("POST", `/v1/actions/${encodeURIComponent(id)}/restore`),
    allowList: () => call<AllowRow[]>("GET", "/v1/allowlist"),
    allowAdd: (sha256: string, days: number | null) => call<AllowRow>("POST", "/v1/allowlist", { sha256, days }),
    allowRemove: (sha256: string) => call<{ removed: boolean }>("DELETE", `/v1/allowlist/${encodeURIComponent(sha256)}`),
    audit: (limit = 100) => call<AuditRow[]>("GET", `/v1/audit${q({ limit })}`),
    intelHealth: () => call<IntelHealth>("GET", "/v1/intel/health"),
    // The analysis workbench. A URL goes as JSON; a message or a file goes as raw bytes, exactly as the agent sends them.
    analyzeUrl: async (url: string): Promise<UrlAnalysis> => ({ ...(await call<Omit<UrlAnalysis, "type">>("POST", "/v1/urls/analyze", { url })), type: "url" }),
    // D1: opens the page in the sandboxed browser container; the core refuses unless detonation is on.
    detonateUrl: async (url: string): Promise<UrlAnalysis> => ({ ...(await call<Omit<UrlAnalysis, "type">>("POST", "/v1/urls/detonate", { url })), type: "url" }),
    analyzeEmail: async (bytes: ArrayBuffer): Promise<EmailAnalysis> => ({
      ...(await call<Omit<EmailAnalysis, "type">>("POST", "/v1/emails/analyze", bytes, { type: "message/rfc822" })), type: "email",
    }),
    analyzeFile: async (name: string, sha256: string, bytes: ArrayBuffer): Promise<FileAnalysis> => ({
      ...(await call<Omit<FileAnalysis, "type">>("POST", "/v1/files/analyze", bytes, {
        type: "application/octet-stream",
        headers: { "X-Lynceus-Name": encodeURIComponent(name), "X-Lynceus-Sha256": sha256 },
      })), type: "file",
    }),
  };
}

export type Api = ReturnType<typeof createApi>;
export type { Analysis };

function explain(status: number): string {
  if (status === 404) return "That no longer exists.";
  if (status === 409) return "That is not possible any more: the state changed. Refresh and look again.";
  if (status === 422) return "The core refused that request.";
  if (status === 503) return "The core cannot do that now (is the database configured?).";
  if (status === 429) return "Too many requests. Wait a moment.";
  if (status === 413) return "That is larger than Lynceus reads.";
  if (status === 415) return "The core did not accept that kind of content.";
  return `The core answered ${status}.`;
}