import { vi } from "vitest";
import type { Browser } from "../src/guard";
import type { Reply } from "../src/protocol";
import type { KV } from "../src/store";

export const memoryKV = (): KV & { data: Map<string, unknown> } => {
  const data = new Map<string, unknown>();
  return {
    data,
    get: async (k) => structuredClone(data.get(k)),
    set: async (k, v) => void data.set(k, structuredClone(v)),
  };
};

export interface FakePort {
  postMessage: ReturnType<typeof vi.fn>;
  onMessage: { addListener: (f: (m: unknown) => void) => void };
  onDisconnect: { addListener: (f: () => void) => void };
  deliver(message: unknown): void;
  drop(): void;
  sent: unknown[];
}

export function fakePort(): FakePort {
  const messageListeners: Array<(m: unknown) => void> = [];
  const disconnectListeners: Array<() => void> = [];
  const sent: unknown[] = [];
  return {
    sent,
    postMessage: vi.fn((m: unknown) => void sent.push(m)),
    onMessage: { addListener: (f) => void messageListeners.push(f) },
    onDisconnect: { addListener: (f) => void disconnectListeners.push(f) },
    deliver: (m) => messageListeners.forEach((f) => f(m)),
    drop: () => disconnectListeners.forEach((f) => f()),
  };
}

export const verdict = (id: string, state: string, extra: Record<string, unknown> = {}): unknown => ({
  v: 1, type: "verdict", id, state, score: state === "MALICIOUS" ? 91 : null, recommended: "NONE", explanation: "because", reasons: ["a reason"], ...extra,
});

export interface FakeBrowser extends Browser {
  tabs: Array<{ tabId: number; url: string }>;
  badges: Array<{ text: string; title: string }>;
  rules: chrome.declarativeNetRequest.Rule[];
  removed: number[];
  failRules: boolean;
}

export function fakeBrowser(): FakeBrowser {
  const b: FakeBrowser = {
    tabs: [], badges: [], rules: [], removed: [], failRules: false,
    getURL: (path) => `chrome-extension://testid/${path}`,
    updateTab: async (tabId, url) => void b.tabs.push({ tabId, url }),
    setBadge: (text, _color, title) => void b.badges.push({ text, title }),
    updateSessionRules: async (change) => {
      if (b.failRules) throw new Error("no host access");
      b.removed.push(...(change.removeRuleIds ?? []));
      b.rules = b.rules.filter((r) => !(change.removeRuleIds ?? []).includes(r.id));
      b.rules.push(...(change.addRules ?? []));
    },
  };
  return b;
}

/** A stand-in for the native link whose answers a test scripts. */
export function scriptedLink(answer: (req: { type: string; url?: string }) => Reply | Promise<Reply>) {
  const calls: Array<{ type: string; url?: string }> = [];
  return {
    calls,
    state: "up" as const,
    connect: () => true,
    request: vi.fn(async (req: { type: string; url?: string }) => {
      calls.push(req);
      return answer(req);
    }),
  };
}
