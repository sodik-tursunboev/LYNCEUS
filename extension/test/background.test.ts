import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fakePort, type FakePort } from "./helpers";

type Listener = (...args: any[]) => any; // eslint-disable-line @typescript-eslint/no-explicit-any

function installChrome() {
  const port = fakePort();
  const listeners: Record<string, Listener[]> = {};
  const event = (name: string) => ({ addListener: (f: Listener) => void (listeners[name] ??= []).push(f) });
  const chromeFake = {
    runtime: { id: "testid", getURL: (p: string) => `chrome-extension://testid/${p}`, connectNative: vi.fn(() => port), onMessage: event("onMessage"), lastError: undefined },
    storage: { session: { store: {} as Record<string, unknown>, get: async function (this: { store: Record<string, unknown> }, k: string) { return { [k]: this.store[k] }; }, set: async function (this: { store: Record<string, unknown> }, o: Record<string, unknown>) { Object.assign(this.store, o); } } },
    webNavigation: { onBeforeNavigate: event("onBeforeNavigate"), onCommitted: event("onCommitted") },
    tabs: { update: vi.fn(async () => undefined), onRemoved: event("onRemoved") },
    action: { setBadgeText: vi.fn(), setBadgeBackgroundColor: vi.fn(), setTitle: vi.fn() },
    declarativeNetRequest: { updateSessionRules: vi.fn(async () => undefined) },
  };
  vi.stubGlobal("chrome", chromeFake);
  return { chromeFake, listeners, port: port as FakePort };
}

describe("the service worker wiring", () => {
  beforeEach(() => vi.resetModules());
  afterEach(() => vi.unstubAllGlobals());

  it("registers its listeners as the worker starts and opens the native port", async () => {
    const { chromeFake, listeners } = installChrome();
    await import("../src/background");
    expect(chromeFake.runtime.connectNative).toHaveBeenCalledWith("com.mirage.agent");
    for (const name of ["onBeforeNavigate", "onCommitted", "onRemoved", "onMessage"]) expect(listeners[name]).toHaveLength(1);
  });

  it("a top-level navigation is sent to the agent and a bad verdict replaces the tab", async () => {
    const { chromeFake, listeners, port } = installChrome();
    await import("../src/background");
    listeners.onBeforeNavigate![0]!({ tabId: 5, frameId: 0, url: "https://paypal-login.test/x" });
    await vi.waitFor(() => expect(port.sent).toHaveLength(1));
    const sent = port.sent[0] as { id: string; type: string; url: string };
    expect(sent).toMatchObject({ v: 1, type: "check_url", url: "https://paypal-login.test/x" });
    port.deliver({ v: 1, type: "verdict", id: sent.id, state: "MALICIOUS", score: 90, recommended: null, explanation: null, reasons: [] });
    await vi.waitFor(() => expect(chromeFake.tabs.update).toHaveBeenCalledTimes(1));
    expect((chromeFake.tabs.update.mock.calls[0] as unknown[])[1]).toMatchObject({ url: expect.stringContaining("warning.html?k=") });
  });

  it("an override is accepted only from the top frame of the warning page of this extension", async () => {
    const { listeners, port } = installChrome();
    await import("../src/background");
    // the extension itself judges the page bad first: only then can an override exist
    listeners.onBeforeNavigate![0]!({ tabId: 5, frameId: 0, url: "https://x.test/" });
    await vi.waitFor(() => expect(port.sent).toHaveLength(1));
    port.deliver({ v: 1, type: "verdict", id: (port.sent[0] as { id: string }).id, state: "MALICIOUS", score: 90, recommended: null, explanation: null, reasons: [] });
    await vi.waitFor(() => expect(port.sent).toHaveLength(1));
    await new Promise((r) => setTimeout(r, 20));

    const handler = listeners.onMessage![0]!;
    const msg = { type: "override", url: "https://x.test/" };
    const page = "chrome-extension://testid/warning.html?k=1";
    const top = { id: "testid", url: page, frameId: 0, tab: { id: 5 } };
    expect(handler(msg, { ...top, id: "otherext" }, vi.fn())).toBe(false);
    expect(handler(msg, { ...top, url: "https://evil.test/" }, vi.fn())).toBe(false);
    expect(handler(msg, { ...top, url: "chrome-extension://testid/popup.html" }, vi.fn())).toBe(false);
    expect(handler({ ...msg, url: 5 }, top, vi.fn())).toBe(false);
    expect(handler("text", top, vi.fn())).toBe(false);
    // a copy of the warning page framed inside another site (clickjacking): a sub-frame, refused
    expect(handler(msg, { ...top, frameId: 3 }, vi.fn())).toBe(false);
    expect(handler(msg, { id: "testid", url: page, tab: { id: 5 } }, vi.fn())).toBe(false); // no frame id
    expect(handler(msg, { id: "testid", url: page, frameId: 0 }, vi.fn())).toBe(false); // not in a tab
    expect(port.sent).toHaveLength(1); // still only the original check
    expect(handler(msg, top, vi.fn())).toBe(true);
    await vi.waitFor(() => expect(port.sent).toHaveLength(2));
    expect(port.sent[1]).toMatchObject({ type: "override", url: "https://x.test/", state: "MALICIOUS", minutes: 15 });
  });

  it("a top-frame warning page cannot override a URL the extension never judged bad", async () => {
    const { listeners, port } = installChrome();
    await import("../src/background");
    const respond = vi.fn();
    const top = { id: "testid", url: "chrome-extension://testid/warning.html?k=1", frameId: 0, tab: { id: 5 } };
    expect(listeners.onMessage![0]!({ type: "override", url: "https://never-seen.test/" }, top, respond)).toBe(true);
    await vi.waitFor(() => expect(respond).toHaveBeenCalledWith({ ok: false }));
    expect(port.sent).toHaveLength(0); // the agent was never asked, so no override record exists
  });

  it("unknown message types are ignored", async () => {
    const { listeners } = installChrome();
    await import("../src/background");
    expect(listeners.onMessage![0]!({ type: "reboot" }, { id: "testid", url: "chrome-extension://testid/warning.html" }, vi.fn())).toBe(false);
  });
});

describe("the built manifest", () => {
  const manifest = JSON.parse(readFileSync(new URL("../manifest.template.json", import.meta.url), "utf8")) as Record<string, unknown>;

  it("asks for the permissions the plan approved and nothing more", () => {
    expect([...(manifest.permissions as string[])].sort()).toEqual(["declarativeNetRequestWithHostAccess", "nativeMessaging", "storage", "webNavigation"]);
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
    expect(manifest.optional_host_permissions).toEqual(["http://*/*", "https://*/*"]);
    expect(manifest.manifest_version).toBe(3);
  });

  it("exposes only the warning page and what it needs", () => {
    expect(JSON.stringify(manifest.web_accessible_resources)).not.toContain("background");
  });

  it("the pinned key gives exactly the extension ID the native host allows", () => {
    const der = Buffer.from(readFileSync(new URL("../manifest-key.txt", import.meta.url), "utf8").trim(), "base64");
    const id = [...createHash("sha256").update(der).digest("hex").slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
    const endpoints = readFileSync(new URL("../../agent/Mirage.Ipc/Endpoints.cs", import.meta.url), "utf8");
    expect(endpoints).toContain(`ExtensionId = "${id}"`);
  });
});
