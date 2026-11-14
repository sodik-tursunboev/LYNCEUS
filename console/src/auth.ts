// The console holds only its own session token (H1 A1), in sessionStorage (this tab only). It never keeps the
// API token: `#code=...` from `Lynceus.Agent --open-console` is a one-time code, read once and removed from
// the address at once, then traded for a session; a typed API token is traded the same way and forgotten.
const KEY = "lynceus.token";

export interface Env {
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">;
  location: Pick<Location, "hash" | "pathname" | "search">;
  history: Pick<History, "replaceState">;
}

/** The one-time code in the address, if there is a well-formed one; any `#code=` or `#token=` is removed. */
export function takeCodeFromFragment(env: Env): string | null {
  const match = /^#code=([A-Za-z0-9_-]{16,128})$/.exec(env.location.hash);
  if (env.location.hash.startsWith("#code=") || env.location.hash.startsWith("#token=")) {
    env.history.replaceState(null, "", env.location.pathname + env.location.search);
  }
  return match?.[1] ?? null;
}

type Fetch = typeof fetch;

/** Trade a one-time code, or the API token typed at sign-in, for a console session. Null if refused. */
export async function openSession(fetchImpl: Fetch, how: { code: string } | { apiToken: string }): Promise<string | null> {
  try {
    const response = await fetchImpl("/v1/console/session", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...("apiToken" in how ? { Authorization: `Bearer ${how.apiToken.trim()}` } : {}) },
      body: JSON.stringify("code" in how ? { code: how.code } : {}),
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { token?: unknown };
    return typeof body.token === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(body.token) ? body.token : null;
  } catch {
    return null;
  }
}

/** End the session on the core too, then forget it here. */
export async function signOut(fetchImpl: Fetch, env: Pick<Env, "storage">): Promise<void> {
  const token = getToken(env);
  clearToken(env);
  if (!token) return;
  try {
    await fetchImpl("/v1/console/session", { method: "DELETE", headers: { Authorization: `Bearer ${token}` }, cache: "no-store", credentials: "omit", redirect: "error" });
  } catch {
    // the core is down: the session dies with it
  }
}

export const getToken = (env: Pick<Env, "storage">): string | null => env.storage.getItem(KEY);
export const setToken = (env: Pick<Env, "storage">, token: string): void => env.storage.setItem(KEY, token.trim());
export const clearToken = (env: Pick<Env, "storage">): void => env.storage.removeItem(KEY);
