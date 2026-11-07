import type { State } from "./protocol";

/** A tiny key-value store. In the browser it is `chrome.storage.session` (memory only, gone when the browser closes). */
export interface KV {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
}

export const sessionKV = (area: chrome.storage.StorageArea): KV => ({
  get: async (key) => (await area.get(key))[key],
  set: (key, value) => area.set({ [key]: value }),
});

export async function keyOf(url: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(url));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Only web pages are checked; the browser's own pages, extension pages, files and odd schemes never leave the browser. */
export function isCheckable(url: string): boolean {
  if (url.length === 0 || url.length > 8192) return false;
  if (/[\u0000-\u001f\u007f]/.test(url)) return false;
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export interface Entry {
  state: State;
  score: number | null;
  reasons: string[];
  explanation: string | null;
  expires: number;
}

export const GOOD_FOR_MS = 5 * 60_000;
export const BAD_FOR_MS = 30 * 60_000;
export const MAX_ENTRIES = 500;

type Table<T> = Record<string, T>;

/** Read-modify-write on one storage key, one at a time, so two navigations cannot overwrite each other. */
class Table_<T> {
  private chain: Promise<unknown> = Promise.resolve();
  constructor(
    private readonly kv: KV,
    private readonly name: string,
  ) {}

  async read(): Promise<Table<T>> {
    const v = await this.kv.get(this.name);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Table<T>) : {};
  }

  update<R>(fn: (t: Table<T>) => R): Promise<R> {
    const run = this.chain.then(async () => {
      const t = await this.read();
      const result = fn(t);
      await this.kv.set(this.name, t);
      return result;
    });
    this.chain = run.catch(() => undefined);
    return run;
  }
}

/** Verdicts by hash of the exact URL string: no URL parsing parity with the core is needed. */
export class VerdictCache {
  private readonly table: Table_<Entry>;
  constructor(kv: KV, private readonly now: () => number = Date.now) {
    this.table = new Table_<Entry>(kv, "lynceus.verdicts");
  }

  async get(key: string): Promise<Entry | null> {
    const entry = (await this.table.read())[key];
    return entry && entry.expires > this.now() ? entry : null;
  }

  async put(key: string, entry: Omit<Entry, "expires">): Promise<Entry> {
    const full: Entry = { ...entry, expires: this.now() + (entry.state === "MALICIOUS" || entry.state === "SUSPICIOUS" ? BAD_FOR_MS : GOOD_FOR_MS) };
    await this.table.update((t) => {
      t[key] = full;
      const keys = Object.keys(t);
      if (keys.length > MAX_ENTRIES) {
        for (const k of keys.sort((a, b) => (t[a]?.expires ?? 0) - (t[b]?.expires ?? 0)).slice(0, keys.length - MAX_ENTRIES)) delete t[k];
      }
    });
    return full;
  }
}

/** "Continue anyway" decisions: one exact URL, until a deadline. */
export class Overrides {
  private readonly table: Table_<number>;
  constructor(kv: KV, private readonly now: () => number = Date.now) {
    this.table = new Table_<number>(kv, "lynceus.overrides");
  }

  async active(key: string): Promise<boolean> {
    const until = (await this.table.read())[key];
    return typeof until === "number" && until > this.now();
  }

  async allow(key: string, until: number): Promise<void> {
    await this.table.update((t) => {
      t[key] = until;
      for (const k of Object.keys(t)) if ((t[k] ?? 0) <= this.now()) delete t[k];
    });
  }
}

/** The redirect rules installed so far, so they can be removed again. */
export class RuleBook {
  private readonly table: Table_<number>;
  constructor(kv: KV) {
    this.table = new Table_<number>(kv, "lynceus.rules");
  }

  /** The rule id for a key, allocating the next free one; `existing` says it was already there. */
  take(key: string, limit: number): Promise<{ id: number; existing: boolean; evicted: number[] }> {
    return this.table.update((t) => {
      const have = t[key];
      if (have !== undefined) return { id: have, existing: true, evicted: [] };
      const evicted: number[] = [];
      const keys = Object.keys(t);
      while (keys.length >= limit) {
        const oldest = keys.shift();
        if (oldest === undefined) break;
        evicted.push(t[oldest] ?? 0);
        delete t[oldest];
      }
      const id = Math.max(0, ...Object.values(t)) + 1;
      t[key] = id;
      return { id, existing: false, evicted };
    });
  }

  release(key: string): Promise<number | null> {
    return this.table.update((t) => {
      const id = t[key];
      delete t[key];
      return id ?? null;
    });
  }
}
