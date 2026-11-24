// DA5 1b: a page the agent is opening in its sandbox gets ONE more question when that look is due.
import { describe, expect, it } from "vitest";
import { Guard } from "../src/guard";
import type { NativeLink } from "../src/native";
import { parseReply, type Reply } from "../src/protocol";
import { Overrides, RuleBook, VerdictCache, keyOf } from "../src/store";
import { fakeBrowser, memoryKV, scriptedLink, verdict } from "./helpers";

const PAGE = "https://account-review.test/login";
const nav = (url: string, tabId = 1) => ({ tabId, frameId: 0, url });

/** An agent answer as it arrives from the native host: through the real parser, so the whitelist is part of the test. */
const said = (state: string, extra: Record<string, unknown> = {}): Reply => {
  const reply = parseReply(verdict("1", state, extra));
  if (reply === null) throw new Error("the parser refused a test reply");
  return reply;
};
const running = (seconds: number | string = 12) => ({ deeper: { state: "running", retry_after_s: seconds } });

/** `script(n)` is the agent's answer to the n-th check; the timer is a list the test fires by hand. */
function setup(script: (nth: number) => Reply) {
  const kv = memoryKV();
  let checks = 0;
  const link = scriptedLink((req) => (req.type === "override" ? { type: "override_ok", id: "1", expires_at: new Date(Date.now() + 900_000).toISOString() } : script(++checks)));
  const browser = fakeBrowser();
  const timers: Array<{ run: () => Promise<void>; ms: number }> = [];
  const guard = new Guard(link as unknown as NativeLink, new VerdictCache(kv), new Overrides(kv), new RuleBook(kv), browser, Date.now, (run, ms) => void timers.push({ run, ms }));
  const asked = () => link.calls.filter((c) => c.type === "check_url" && c.url === PAGE).length;
  const cached = async () => new VerdictCache(kv).get(await keyOf(PAGE));
  return { guard, link, browser, timers, asked, cached };
}

describe("a page whose deeper look is running", () => {
  it("asks again once after the deeper look is due", async () => {
    const t = setup((n) => (n === 1 ? said("UNKNOWN", running(12)) : said("MALICIOUS")));
    await t.guard.onNavigation(nav(PAGE));
    expect(t.asked()).toBe(1);
    expect(t.browser.tabs).toHaveLength(0); // UNKNOWN: the page is left alone, as before
    expect(t.timers.map((x) => x.ms)).toEqual([12_000]); // the agent said 12 seconds

    await t.timers[0]!.run();
    expect(t.asked()).toBe(2);
    expect(t.link.calls.at(-1)).toEqual({ type: "check_url", url: PAGE });

    // the hint is checked like everything else the agent says: a wrong one is no hint, the verdict still counts
    const parsed = parseReply(verdict("1", "UNKNOWN", running(12)));
    expect(parsed).toMatchObject({ type: "verdict", state: "UNKNOWN", deeperAfterS: 12 });
    const odd: unknown[] = [running(0).deeper, running(61).deeper, running(1.5).deeper, running("12").deeper, { state: "done", retry_after_s: 12 }, { state: "running" }, "running", null, [12]];
    for (const deeper of odd) {
      expect(parseReply(verdict("1", "UNKNOWN", { deeper }))).toMatchObject({ type: "verdict", state: "UNKNOWN" });
      expect(parseReply(verdict("1", "UNKNOWN", { deeper }))).not.toHaveProperty("deeperAfterS");
      const quiet = setup(() => said("UNKNOWN", { deeper }));
      await quiet.guard.onNavigation(nav(PAGE));
      expect(quiet.timers).toHaveLength(0);
    }
    const old = setup(() => said("UNKNOWN")); // an agent that says nothing about a deeper look: nothing to wait for
    await old.guard.onNavigation(nav(PAGE));
    expect(old.timers).toHaveLength(0);
  });

  it("replaces the tab only when the deeper verdict is graver", async () => {
    const cases: Array<[string, string, string[]]> = [
      ["UNKNOWN", "MALICIOUS", ["MALICIOUS"]],
      ["UNKNOWN", "SUSPICIOUS", ["SUSPICIOUS"]],
      ["SUSPICIOUS", "MALICIOUS", ["SUSPICIOUS", "MALICIOUS"]], // warned already, now graver
      ["SUSPICIOUS", "SUSPICIOUS", ["SUSPICIOUS"]], // the same: no second page
      ["UNKNOWN", "UNKNOWN", []],
    ];
    for (const [first, second, warned] of cases) {
      const t = setup((n) => (n === 1 ? said(first, running()) : said(second)));
      await t.guard.onNavigation(nav(PAGE));
      await t.timers[0]!.run();
      const key = await keyOf(PAGE);
      expect(t.browser.tabs.map((x) => x.url), `${first} then ${second}`).toEqual(warned.map((s) => `chrome-extension://testid/warning.html?k=${key}&s=${s}&u=${encodeURIComponent(PAGE)}`));
      if (warned.length > 0) {
        expect(t.browser.rules).toHaveLength(1); // the next visit is stopped too, at the graver state
        expect(t.browser.rules[0]?.action.redirect?.extensionPath).toContain(`&s=${warned.at(-1)}&`);
        expect((await t.cached())?.state).toBe(warned.at(-1)); // and the warning page reads the graver verdict
      }
    }

    // a tab that has moved on, or was closed, is not asked about and not touched
    for (const leave of [(g: Guard) => g.onNavigation(nav("https://elsewhere.test/")), async (g: Guard) => g.forgetTab(1)]) {
      // answer 2 is for the page the tab moved to (if any); a re-ask of PAGE would be answer 2 or 3 and graver
      const t = setup((n) => (n === 1 ? said("UNKNOWN", running()) : n === 2 ? said("BENIGN") : said("MALICIOUS")));
      await t.guard.onNavigation(nav(PAGE));
      await leave(t.guard);
      await t.timers[0]!.run();
      expect(t.asked()).toBe(1);
      expect(t.browser.tabs).toHaveLength(0);
    }

    // the user already chose to continue past the first warning: that choice stands
    const chose = setup((n) => (n === 1 ? said("SUSPICIOUS", running()) : said("MALICIOUS")));
    await chose.guard.onNavigation(nav(PAGE));
    await chose.guard.override(PAGE);
    await chose.timers[0]!.run();
    expect(chose.browser.tabs).toHaveLength(1);
    expect(chose.browser.rules).toHaveLength(0);
  });

  it("never lowers or hides a verdict", async () => {
    const later: Array<[string, Reply]> = [
      ["BENIGN", said("BENIGN")],
      ["UNKNOWN", said("UNKNOWN")],
      ["ERROR", said("ERROR")],
      ["an agent that is gone", { type: "error", id: "1", error: "agent_unavailable" }],
      ["a reply that is not a verdict", { type: "status", id: "1", agent: "ok", judged: 0, waiting: 0 }],
    ];
    for (const [what, reply] of later) {
      const t = setup((n) => (n === 1 ? said("SUSPICIOUS", { score: 55, ...running() }) : reply));
      await t.guard.onNavigation(nav(PAGE));
      const warning = [...t.browser.tabs];
      expect(warning, what).toHaveLength(1);
      await t.timers[0]!.run();
      expect(t.browser.tabs, what).toEqual(warning); // the warning stays, and nothing replaced it
      expect(t.browser.rules, what).toHaveLength(1);
      expect(t.browser.removed, what).toEqual([]);
      expect(await t.cached(), what).toMatchObject({ state: "SUSPICIOUS", score: 55 }); // the stored verdict is not overwritten
    }

    // an unknown page stays as it was: a lower answer does not even replace the cached UNKNOWN
    const t = setup((n) => (n === 1 ? said("UNKNOWN", { score: null, ...running() }) : said("BENIGN")));
    await t.guard.onNavigation(nav(PAGE));
    await t.timers[0]!.run();
    expect(await t.cached()).toMatchObject({ state: "UNKNOWN" });
    expect(t.browser.tabs).toHaveLength(0);
  });

  it("stops asking after one re-ask", async () => {
    // the answer to the re-ask says "still running" again: nobody asks a third time
    const t = setup(() => said("UNKNOWN", running(5)));
    await t.guard.onNavigation(nav(PAGE));
    await t.timers[0]!.run();
    expect(t.asked()).toBe(2);
    expect(t.timers).toHaveLength(1);
    await t.timers[0]!.run(); // even a timer that fires twice asks nothing more
    expect(t.asked()).toBe(2);

    // the same, when the re-ask makes the verdict graver and says "running" once more
    const g = setup((n) => (n === 1 ? said("SUSPICIOUS", running()) : said("MALICIOUS", running())));
    await g.guard.onNavigation(nav(PAGE));
    await g.timers[0]!.run();
    expect(g.browser.tabs).toHaveLength(2);
    expect(g.timers).toHaveLength(1);
    expect(g.asked()).toBe(2);

    // one navigation is reported twice by the browser (before it starts and when it commits): still one re-ask
    const both = setup(() => said("UNKNOWN", running()));
    await Promise.all([both.guard.onNavigation(nav(PAGE)), both.guard.onNavigation(nav(PAGE))]);
    expect(both.timers).toHaveLength(1);
    const before = both.asked();
    await both.timers[0]!.run();
    expect(both.asked() - before).toBe(1);
  });
});
