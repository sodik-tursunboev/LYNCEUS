// The API token lives in sessionStorage (this tab only) and is never put in a URL by the console.
// `#token=...` is accepted once, from `Mirage.Agent --open-console`, and removed from the address at once.
const KEY = "mirage.token";

export interface Env {
  storage: Pick<Storage, "getItem" | "setItem" | "removeItem">;
  location: Pick<Location, "hash" | "pathname" | "search">;
  history: Pick<History, "replaceState">;
}

export function takeTokenFromFragment(env: Env): void {
  const match = /^#token=([A-Za-z0-9_\-+/=.]{16,512})$/.exec(env.location.hash);
  if (match?.[1]) env.storage.setItem(KEY, match[1]);
  if (env.location.hash.startsWith("#token=")) {
    env.history.replaceState(null, "", env.location.pathname + env.location.search);
  }
}

export const getToken = (env: Pick<Env, "storage">): string | null => env.storage.getItem(KEY);
export const setToken = (env: Pick<Env, "storage">, token: string): void => env.storage.setItem(KEY, token.trim());
export const clearToken = (env: Pick<Env, "storage">): void => env.storage.removeItem(KEY);