import { beforeEach, describe, expect, it, vi } from "vitest";
import { Guard, MAX_RULES } from "../src/guard";
import type { NativeLink } from "../src/native";
import type { Reply } from "../src/protocol";
import { Overrides, RuleBook, VerdictCache, keyOf } from "../src/store";
import { fakeBrowser, memoryKV, scriptedLink, type FakeBrowser } from "./helpers";

const BAD = "https://paypal-login.test/login.php?token=SECRET";
const ok = (state: string): Reply => ({ type: "verdict", id: "1", state: state as "MALICIOUS", score: 90, recommended: null, explanation: "why", reasons: ["r1"] });
const err = (error: string): Reply => ({ type: "error", id: "1", error });

function setup(answer: (req: { type: string; url?: string }) => Reply | Promise<Reply>) {
  const kv = memoryKV();
  const link = scriptedLink(answer);
  const browser = fakeBrowser();
  let now = 1_000_000;
  const guard = new Guard(link as unknown as NativeLink, new VerdictCache(kv, () => now), new Overrides(kv, () => now), new RuleBook(kv), browser, () => now);
  return { guard, link, browser, kv, tick: (ms: number) => void (now += ms) };
}
const nav = (url: string, tabId = 1, frameId = 0) => ({ tabId, frameId, url });

describe("a navigation to a bad page", () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => void (t = setup((r) => (r.type === "check_url" ? ok("MALICIOUS") : err("rejected")))));

  it("replaces the tab with the warning page carrying the key and the state, not the verdict text", async () => {
    await t.guard.onNavigation(nav(BAD));
    const key = await keyOf(BAD);
    expect(t.link.calls).toEqual([{ type: "check_url", url: BAD }]);
    expect(t.browser.tabs).toEqual([{ tabId: 1, url: `chrome-extension://testid/warning.html?k=${key}&s=MALICIOUS&u=${encodeURIComponent(BAD)}` }]);
  });

  it("installs one exact-URL redirect rule so the next visit is stopped before the request", async () => {
    await t.guard.onNavigation(nav(BAD + "#frag"));
    const [rule] = t.browser.rules;
    expect(t.browser.rules).toHaveLength(1);
    expect(rule?.condition).toMatchObject({ urlFilter: `|${BAD}|`, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame"] });
    expect(rule?.action.type).toBe("redirect");
    expect(rule?.action.redirect?.extensionPath).toMatch(/^\/warning\.html\?k=[0-9a-f]{64}&s=MALICIOUS&u=/);
    await t.guard.onNavigation(nav(BAD + "#frag"));
    expect(t.browser.rules).toHaveLength(1);
  });

  it("asks the agent once: the second visit is answered from the cache", async () => {
    await t.guard.onNavigation(nav(BAD));
    await t.guard.onNavigation(nav(BAD, 2));
    expect(t.link.calls).toHaveLength(1);
    expect(t.browser.tabs.map((x) => x.tabId)).toEqual([1, 2]);
  });

  it("a cache hit expires and the agent is asked again", async () => {
    await t.guard.onNavigation(nav(BAD));
    t.tick(31 * 60_000);
    await t.guard.onNavigation(nav(BAD));
    expect(t.link.calls).toHaveLength(2);
  });

  it("does not redirect a tab that has already moved on to another page", async () => {
    const waiting: Array<(r: Reply) => void> = [];
    const slow = setup((r) => (r.url === BAD ? new Promise<Reply>((res) => waiting.push(res)) : ok("BENIGN")));
    const first = slow.guard.onNavigation(nav(BAD));
    await vi.waitFor(() => expect(waiting).toHaveLength(1));
    await slow.guard.onNavigation(nav("https://elsewhere.test/"));
    waiting[0]!(ok("MALICIOUS"));
    await first;
    expect(slow.browser.tabs).toHaveLength(0);
  });

  it("with no site access the rule is refused and the tab redirect still happens", async () => {
    t.browser.failRules = true;
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.tabs).toHaveLength(1);
    expect(t.browser.rules).toHaveLength(0);
  });

  it("a URL a filter cannot express still gets the tab redirect, without a rule", async () => {
    for (const u of ["https://x.test/a*b", "https://x.test/a^b", "https://x.test/a|b"]) await t.guard.onNavigation(nav(u));
    expect(t.browser.tabs).toHaveLength(3);
    expect(t.browser.rules).toHaveLength(0);
  });

  it("keeps the number of rules bounded", async () => {
    for (let i = 0; i < MAX_RULES + 5; i++) await t.guard.onNavigation(nav(`https://p${i}.test/`, i));
    expect(t.browser.rules.length).toBeLessThanOrEqual(MAX_RULES);
    expect(t.browser.tabs).toHaveLength(MAX_RULES + 5);
  });
});

describe("what is left alone", () => {
  it.each(["BENIGN", "UNKNOWN", "ERROR"])("a %s verdict changes nothing", async (state) => {
    const t = setup(() => ok(state));
    await t.guard.onNavigation(nav("https://example.test/"));
    expect(t.browser.tabs).toHaveLength(0);
    expect(t.browser.rules).toHaveLength(0);
  });

  it("a SUSPICIOUS page is warned about too", async () => {
    const t = setup(() => ok("SUSPICIOUS"));
    await t.guard.onNavigation(nav("https://example.test/"));
    expect(t.browser.tabs[0]?.url).toContain("s=SUSPICIOUS");
  });

  it.each(["chrome://settings", "edge://flags", "chrome-extension://testid/warning.html", "file:///C:/a.html", "about:blank", "javascript:1"])("%s is never sent to the agent", async (url) => {
    const t = setup(() => ok("MALICIOUS"));
    await t.guard.onNavigation(nav(url));
    expect(t.link.calls).toHaveLength(0);
  });

  it("only the top frame counts", async () => {
    const t = setup(() => ok("MALICIOUS"));
    await t.guard.onNavigation(nav(BAD, 1, 3));
    expect(t.link.calls).toHaveLength(0);
  });
});

describe("when the agent cannot answer, the browser carries on and says so", () => {
  it.each(["agent_unavailable", "agent_timeout"])("%s: no redirect, badge says not protected", async (code) => {
    const t = setup(() => err(code));
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.tabs).toHaveLength(0);
    expect(t.browser.badges.at(-1)).toMatchObject({ text: "!" });
    expect(t.browser.badges.at(-1)?.title).toContain("not protecting");
  });

  it("core_unavailable: no redirect, a different badge", async () => {
    const t = setup(() => err("core_unavailable"));
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.tabs).toHaveLength(0);
    expect(t.browser.badges.at(-1)).toMatchObject({ text: "?" });
  });

  it("a refusal of one message does not touch the badge", async () => {
    const t = setup(() => err("rejected"));
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.badges).toHaveLength(0);
  });

  it("a failure is not cached: the next visit asks again, and a good answer clears the badge", async () => {
    let up = false;
    const t = setup(() => (up ? ok("BENIGN") : err("agent_unavailable")));
    await t.guard.onNavigation(nav(BAD));
    up = true;
    await t.guard.onNavigation(nav(BAD));
    expect(t.link.calls).toHaveLength(2);
    expect(t.browser.badges.at(-1)).toMatchObject({ text: "" });
  });

  it("a non-verdict reply to a check is treated as a failure, never as safe or bad", async () => {
    const t = setup(() => ({ type: "status", id: "1", agent: "ok", judged: 0, waiting: 0 }));
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.tabs).toHaveLength(0);
  });
});

describe("continuing anyway", () => {
  const until = (ms: number) => new Date(1_000_000 + ms).toISOString();

  it("is allowed only after the agent recorded it, for that exact URL, and removes the rule", async () => {
    const t = setup((r) => (r.type === "override" ? { type: "override_ok", id: "1", expires_at: until(900_000) } : ok("MALICIOUS")));
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.rules).toHaveLength(1);
    expect(await t.guard.override(BAD)).toEqual({ ok: true });
    expect(t.link.calls.at(-1)).toMatchObject({ type: "override", url: BAD, state: "MALICIOUS", minutes: 15 });
    expect(t.browser.rules).toHaveLength(0);

    const before = t.browser.tabs.length;
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.tabs).toHaveLength(before); // not blocked again
    await t.guard.onNavigation(nav(BAD + "&x=1"));
    expect(t.browser.tabs.length).toBe(before + 1); // a different URL is still judged
  });

  it("blocks again once the time is up", async () => {
    const t = setup((r) => (r.type === "override" ? { type: "override_ok", id: "1", expires_at: until(900_000) } : ok("MALICIOUS")));
    await t.guard.onNavigation(nav(BAD));
    await t.guard.override(BAD);
    t.tick(901_000);
    const before = t.browser.tabs.length;
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.tabs.length).toBe(before + 1);
  });

  it.each(["override_not_recorded", "agent_unavailable", "agent_timeout"])("is refused if the agent says %s", async (code) => {
    const t = setup((r) => (r.type === "override" ? err(code) : ok("MALICIOUS")));
    await t.guard.onNavigation(nav(BAD));
    expect(await t.guard.override(BAD)).toEqual({ ok: false });
    const before = t.browser.tabs.length;
    await t.guard.onNavigation(nav(BAD));
    expect(t.browser.tabs.length).toBe(before + 1); // still blocked
  });

  it.each([until(-1000), "not a date", ""])("is refused if the recorded deadline is %j", async (when) => {
    const t = setup((r) => (r.type === "override" ? { type: "override_ok", id: "1", expires_at: when } : ok("MALICIOUS")));
    await t.guard.onNavigation(nav(BAD));
    expect(await t.guard.override(BAD)).toEqual({ ok: false });
  });

  it.each(["chrome://settings", "file:///C:/a", "javascript:1", ""])("is refused for %j", async (url) => {
    const t = setup(() => ({ type: "override_ok", id: "1", expires_at: until(900_000) }));
    expect(await t.guard.override(url)).toEqual({ ok: false });
    expect(t.link.calls).toHaveLength(0);
  });

  it("is refused for a URL the extension has no bad verdict for, without asking the agent (a forged warning page)", async () => {
    const t = setup(() => ({ type: "override_ok", id: "1", expires_at: until(900_000) }));
    expect(await t.guard.override(BAD)).toEqual({ ok: false }); // never judged
    expect(t.link.calls).toHaveLength(0);
    const good = setup((r) => (r.type === "check_url" ? ok("BENIGN") : { type: "override_ok", id: "1", expires_at: until(900_000) }));
    await good.guard.onNavigation(nav("https://fine.test/"));
    expect(await good.guard.override("https://fine.test/")).toEqual({ ok: false }); // judged fine: nothing to override
    expect(good.link.calls.filter((c) => c.type === "override")).toHaveLength(0);
  });

  it("tells the agent the state the extension cached, whatever the page claims", async () => {
    const t = setup((r) => (r.type === "override" ? { type: "override_ok", id: "1", expires_at: until(900_000) } : ok("SUSPICIOUS")));
    await t.guard.onNavigation(nav(BAD));
    await t.guard.override(BAD);
    expect(t.link.calls.at(-1)).toMatchObject({ type: "override", state: "SUSPICIOUS" });
  });
});

describe("status", () => {
  it("reports the agent up with its counts", async () => {
    const t = setup(() => ({ type: "status", id: "1", agent: "ok", judged: 7, waiting: 2 }));
    expect(await t.guard.status()).toEqual({ agent: "up", judged: 7, waiting: 2 });
  });
  it("reports the agent down when it cannot answer", async () => {
    const t = setup(() => err("agent_unavailable"));
    expect(await t.guard.status()).toEqual({ agent: "down", judged: 0, waiting: 0 });
    expect(t.browser.badges.at(-1)).toMatchObject({ text: "!" });
  });
});

export type { FakeBrowser };
