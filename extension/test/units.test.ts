import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { NativeLink } from "../src/native";
import { parseReply } from "../src/protocol";
import { BAD_FOR_MS, GOOD_FOR_MS, MAX_ENTRIES, Overrides, RuleBook, VerdictCache, isCheckable, keyOf } from "../src/store";
import { readParams, wording } from "../src/warning";
import { fakePort, memoryKV, verdict } from "./helpers";

describe("parseReply", () => {
  const ok = [
    verdict("a", "MALICIOUS"),
    verdict("a", "UNKNOWN", { score: null, recommended: null, explanation: null, reasons: [] }),
    { v: 1, type: "error", id: null, error: "agent_unavailable" },
    { v: 1, type: "error", error: "malformed" },
    { v: 1, type: "override_ok", id: "o", expires_at: "2026-11-05T12:00:00Z" },
    { v: 1, type: "status", id: "s", agent: "ok", judged: 3, waiting: 0 },
  ];
  it.each(ok.map((m, i) => [i, m] as const))("accepts valid reply %i", (_i, m) => {
    expect(parseReply(m)).not.toBeNull();
  });

  const bad: Array<[string, unknown]> = [
    ["null", null],
    ["array", []],
    ["string", "verdict"],
    ["no version", { type: "error", error: "x" }],
    ["wrong version", { v: 2, type: "error", error: "x" }],
    ["unknown type", { v: 1, type: "launch", id: "a" }],
    ["invented state", verdict("a", "SAFE")],
    ["lower-case state", verdict("a", "malicious")],
    ["verdict without id", { ...(verdict("a", "BENIGN") as object), id: undefined }],
    ["score as text", verdict("a", "BENIGN", { score: "high" })],
    ["score NaN", verdict("a", "BENIGN", { score: Number.NaN })],
    ["reasons not an array", verdict("a", "BENIGN", { reasons: "x" })],
    ["too many reasons", verdict("a", "BENIGN", { reasons: Array(9).fill("r") })],
    ["a reason that is not text", verdict("a", "BENIGN", { reasons: [1] })],
    ["a huge explanation", verdict("a", "BENIGN", { explanation: "x".repeat(601) })],
    ["id too long", verdict("a".repeat(65), "BENIGN")],
    ["error without text", { v: 1, type: "error" }],
    ["override_ok without expiry", { v: 1, type: "override_ok", id: "o" }],
    ["status with text counts", { v: 1, type: "status", id: "s", agent: "ok", judged: "3", waiting: 0 }],
  ];
  it.each(bad)("refuses %s", (_name, m) => {
    expect(parseReply(m)).toBeNull();
  });
});

describe("isCheckable", () => {
  it.each(["http://example.test/", "https://example.test/a?b=c#d", "https://xn--e1afmkfd.test/"])("checks %s", (u) => {
    expect(isCheckable(u)).toBe(true);
  });
  it.each([
    "", "chrome://settings", "edge://extensions", "chrome-extension://abc/warning.html", "moz-extension://abc/x", "file:///C:/a.html",
    "about:blank", "data:text/html,hi", "javascript:alert(1)", "ftp://x.test/", "blob:https://x.test/uuid", "not a url", "https://x.test/\u0000", "https://x.test/\n",
    "https://x.test/" + "a".repeat(8200),
  ])("does not check %j", (u) => {
    expect(isCheckable(u)).toBe(false);
  });
});

describe("keyOf", () => {
  it("is a stable 64-hex hash of the exact string", async () => {
    const a = await keyOf("https://x.test/a");
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await keyOf("https://x.test/a")).toBe(a);
    expect(await keyOf("https://x.test/a?")).not.toBe(a);
    expect(await keyOf("https://X.test/a")).not.toBe(a);
  });
});

describe("stores", () => {
  let now = 1_000_000;
  beforeEach(() => void (now = 1_000_000));

  it("a cached verdict expires: bad ones later than good ones", async () => {
    const cache = new VerdictCache(memoryKV(), () => now);
    await cache.put("bad", { state: "MALICIOUS", score: 90, reasons: [], explanation: null });
    await cache.put("good", { state: "UNKNOWN", score: null, reasons: [], explanation: null });
    now += GOOD_FOR_MS + 1;
    expect(await cache.get("good")).toBeNull();
    expect((await cache.get("bad"))?.state).toBe("MALICIOUS");
    now += BAD_FOR_MS;
    expect(await cache.get("bad")).toBeNull();
  });

  it("the cache is bounded, dropping the soonest to expire", async () => {
    const kv = memoryKV();
    const cache = new VerdictCache(kv, () => now);
    for (let i = 0; i < MAX_ENTRIES + 20; i++) {
      now += 1;
      await cache.put(`k${i}`, { state: "UNKNOWN", score: null, reasons: [], explanation: null });
    }
    const table = kv.data.get("lynceus.verdicts") as Record<string, unknown>;
    expect(Object.keys(table)).toHaveLength(MAX_ENTRIES);
    expect(await cache.get("k0")).toBeNull();
    expect(await cache.get(`k${MAX_ENTRIES + 19}`)).not.toBeNull();
  });

  it("concurrent writes do not lose each other", async () => {
    const cache = new VerdictCache(memoryKV(), () => now);
    await Promise.all(Array.from({ length: 25 }, (_, i) => cache.put(`k${i}`, { state: "UNKNOWN", score: null, reasons: [], explanation: null })));
    for (let i = 0; i < 25; i++) expect(await cache.get(`k${i}`)).not.toBeNull();
  });

  it("an override lasts until its deadline and is for one key only", async () => {
    const o = new Overrides(memoryKV(), () => now);
    await o.allow("a", now + 1000);
    expect(await o.active("a")).toBe(true);
    expect(await o.active("b")).toBe(false);
    now += 1001;
    expect(await o.active("a")).toBe(false);
  });

  it("rule ids are reused per key, evict the oldest at the limit and are released", async () => {
    const book = new RuleBook(memoryKV());
    const a = await book.take("a", 2);
    expect(await book.take("a", 2)).toEqual({ id: a.id, existing: true, evicted: [] });
    const b = await book.take("b", 2);
    const c = await book.take("c", 2);
    expect(c.evicted).toEqual([a.id]);
    expect(new Set([b.id, c.id]).size).toBe(2);
    expect(await book.release("b")).toBe(b.id);
    expect(await book.release("b")).toBeNull();
  });
});

describe("warning page parameters", () => {
  const key = "a".repeat(64);
  it("reads a valid address", () => {
    expect(readParams(`?k=${key}&s=MALICIOUS&u=${encodeURIComponent("https://x.test/p?q=1")}`)).toEqual({ key, state: "MALICIOUS", url: "https://x.test/p?q=1" });
  });
  it.each([
    "", `?k=short&s=MALICIOUS&u=https%3A%2F%2Fx.test`, `?k=${key}&s=BENIGN2&u=https%3A%2F%2Fx.test`, `?k=${key}&s=MALICIOUS`, `?k=${key}&s=MALICIOUS&u=`,
    `?k=${key}&s=MALICIOUS&u=${"a".repeat(8193)}`, `?k=${"A".repeat(64)}&s=MALICIOUS&u=x`,
  ])("refuses %j", (search) => {
    expect(readParams(search)).toBeNull();
  });
  it("words the two bad states differently", () => {
    expect(wording("MALICIOUS").title).not.toBe(wording("SUSPICIOUS").title);
  });
});

describe("NativeLink", () => {
  beforeEach(() => void vi.useFakeTimers());
  afterEach(() => void vi.useRealTimers());

  const make = () => {
    const ports = [fakePort()];
    const states: string[] = [];
    const runtime = { connectNative: vi.fn(() => ports[ports.length - 1] as unknown as chrome.runtime.Port) };
    const link = new NativeLink(runtime, (s) => states.push(s));
    return { ports, states, runtime, link };
  };
  const idOf = (m: unknown): string => (m as { id: string }).id;

  it("matches a reply to its request by id and goes up", async () => {
    const { ports, link, states } = make();
    const p = link.request({ type: "check_url", url: "https://x.test/" });
    const port = ports[0]!;
    const sent = port.sent[0] as { v: number; type: string; url: string };
    expect(sent).toMatchObject({ v: 1, type: "check_url", url: "https://x.test/" });
    port.deliver(verdict(idOf(sent), "MALICIOUS"));
    expect(await p).toMatchObject({ type: "verdict", state: "MALICIOUS" });
    expect(states).toEqual(["up"]);
  });

  it("ignores replies it does not understand or that carry another id", async () => {
    const { ports, link } = make();
    const p = link.request({ type: "status" }, 1000);
    const port = ports[0]!;
    port.deliver({ v: 1, type: "verdict", id: "other", state: "BENIGN", score: null, recommended: null, explanation: null, reasons: [] });
    port.deliver("garbage");
    port.deliver({ v: 1, type: "verdict", id: idOf(port.sent[0]), state: "SAFE" });
    await vi.advanceTimersByTimeAsync(1001);
    expect(await p).toMatchObject({ type: "error", error: "agent_timeout" });
  });

  it("an agent_unavailable answer makes the link down", async () => {
    const { ports, link, states } = make();
    const p = link.request({ type: "status" });
    ports[0]!.deliver({ v: 1, type: "error", id: idOf(ports[0]!.sent[0]), error: "agent_unavailable" });
    expect(await p).toMatchObject({ error: "agent_unavailable" });
    expect(link.state).toBe("down");
    expect(states).toEqual([]); // it was down already; nothing changed
  });

  it("a dropped port ends waiting requests at once and is reopened after a growing pause", async () => {
    const { ports, link, runtime } = make();
    const p = link.request({ type: "status" });
    ports[0]!.drop();
    expect(await p).toMatchObject({ type: "error", error: "agent_unavailable" });
    expect(runtime.connectNative).toHaveBeenCalledTimes(1);
    ports.push(fakePort());
    await vi.advanceTimersByTimeAsync(999);
    expect(runtime.connectNative).toHaveBeenCalledTimes(1); // first pause: one second
    await vi.advanceTimersByTimeAsync(2);
    expect(runtime.connectNative).toHaveBeenCalledTimes(2);
    ports[1]!.drop();
    ports.push(fakePort());
    await vi.advanceTimersByTimeAsync(1999);
    expect(runtime.connectNative).toHaveBeenCalledTimes(2); // second pause: two seconds
    await vi.advanceTimersByTimeAsync(2);
    expect(runtime.connectNative).toHaveBeenCalledTimes(3);
  });

  it("a connect that throws is a down link, not an exception", async () => {
    const link = new NativeLink({ connectNative: () => { throw new Error("no host"); } });
    expect(await link.request({ type: "status" })).toMatchObject({ error: "agent_unavailable" });
  });

  it("a post that throws is a down link, not an exception", async () => {
    const { ports, link } = make();
    ports[0]!.postMessage.mockImplementation(() => { throw new Error("closed"); });
    expect(await link.request({ type: "status" })).toMatchObject({ error: "agent_unavailable" });
  });

  it("a silent agent costs one timeout", async () => {
    const { link } = make();
    const p = link.request({ type: "status" }, 500);
    await vi.advanceTimersByTimeAsync(501);
    expect(await p).toMatchObject({ error: "agent_timeout" });
    expect(link.state).toBe("down");
  });
});
