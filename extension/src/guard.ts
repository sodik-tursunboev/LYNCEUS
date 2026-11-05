import type { LinkState, NativeLink } from "./native";
import { AGENT_DOWN, AGENT_SLOW, isBad, type State } from "./protocol";
import { isCheckable, keyOf, Overrides, RuleBook, VerdictCache, type Entry } from "./store";

export const MAX_RULES = 500;

/** The parts of the browser the guard uses; tests give it a fake. */
export interface Browser {
  getURL(path: string): string;
  updateTab(tabId: number, url: string): Promise<unknown>;
  setBadge(text: string, color: string, title: string): void;
  updateSessionRules(change: { addRules?: chrome.declarativeNetRequest.Rule[]; removeRuleIds?: number[] }): Promise<void>;
}

export interface NavigationDetails {
  tabId: number;
  frameId: number;
  url: string;
}

/**
 * Decides what to do with each top-level navigation. It never holds a navigation: the check
 * runs beside it, and a bad verdict replaces the tab with the warning page. A URL already judged
 * bad also gets a redirect rule, so the next visit is stopped before the request is sent (that
 * only works once the user has granted site access on the options page). When the agent is
 * down the browser carries on as normal and the toolbar says so ("fail open").
 */
export class Guard {
  private readonly tabUrl = new Map<number, string>();

  constructor(
    private readonly link: NativeLink,
    private readonly cache: VerdictCache,
    private readonly overrides: Overrides,
    private readonly rules: RuleBook,
    private readonly browser: Browser,
    private readonly now: () => number = Date.now,
  ) {}

  /** The warning page for a URL, with the verdict carried by key and state only. */
  warningUrl(url: string, key: string, state: State): string {
    return `${this.browser.getURL("warning.html")}?k=${key}&s=${state}&u=${encodeURIComponent(url)}`;
  }

  async onNavigation(d: NavigationDetails): Promise<void> {
    if (d.frameId !== 0 || !isCheckable(d.url)) return;
    this.tabUrl.set(d.tabId, d.url);
    const key = await keyOf(d.url);
    if (await this.overrides.active(key)) return;

    let entry = await this.cache.get(key);
    if (!entry) {
      const reply = await this.link.request({ type: "check_url", url: d.url });
      if (reply.type !== "verdict") {
        this.afterFailure(reply.type === "error" ? reply.error : "unexpected");
        return;
      }
      this.badge("ok");
      entry = await this.cache.put(key, { state: reply.state, score: reply.score, reasons: reply.reasons, explanation: reply.explanation });
    }
    if (!isBad(entry.state)) return;
    await this.installRule(d.url, key, entry.state);
    if (this.tabUrl.get(d.tabId) === d.url && !(await this.overrides.active(key))) {
      await this.browser.updateTab(d.tabId, this.warningUrl(d.url, key, entry.state)).catch(() => undefined);
    }
  }

  /** From the warning page: the user clicked "continue anyway". Allowed only if the agent recorded it. */
  async override(url: string, state: State): Promise<{ ok: boolean }> {
    if (!isCheckable(url)) return { ok: false };
    const reply = await this.link.request({ type: "override", url, state, minutes: 15 });
    if (reply.type !== "override_ok") {
      this.afterFailure(reply.type === "error" ? reply.error : "unexpected");
      return { ok: false };
    }
    const until = Date.parse(reply.expires_at);
    if (!Number.isFinite(until) || until <= this.now()) return { ok: false };
    const key = await keyOf(url);
    await this.overrides.allow(key, until);
    await this.removeRule(key);
    return { ok: true };
  }

  async status(): Promise<{ agent: LinkState; judged: number; waiting: number }> {
    const reply = await this.link.request({ type: "status" }, 3000);
    if (reply.type === "status") {
      this.badge("ok");
      return { agent: "up", judged: reply.judged, waiting: reply.waiting };
    }
    this.afterFailure(reply.type === "error" ? reply.error : "unexpected");
    return { agent: "down", judged: 0, waiting: 0 };
  }

  forgetTab(tabId: number): void {
    this.tabUrl.delete(tabId);
  }

  badge(state: "ok" | "down" | "core"): void {
    if (state === "ok") this.browser.setBadge("", "#000000", "MIRAGE is protecting this browser");
    else if (state === "down") this.browser.setBadge("!", "#c62828", "MIRAGE is not protecting this browser: the agent is not running");
    else this.browser.setBadge("?", "#b26a00", "MIRAGE agent is running but cannot reach its analysis engine");
  }

  private afterFailure(code: string): void {
    if (code === AGENT_DOWN || code === AGENT_SLOW) this.badge("down");
    else if (code === "core_unavailable") this.badge("core");
    // anything else (a refusal of one message) says nothing about protection
  }

  private async installRule(url: string, key: string, state: State): Promise<void> {
    const plain = url.split("#")[0] ?? url;
    if (/[*^|]/.test(plain)) return; // not expressible as an exact URL filter: the tab redirect still applies
    try {
      const slot = await this.rules.take(key, MAX_RULES);
      if (slot.existing) return;
      const target = new URL(this.warningUrl(url, key, state));
      await this.browser.updateSessionRules({
        removeRuleIds: slot.evicted,
        addRules: [
          {
            id: slot.id,
            priority: 1,
            action: { type: "redirect" as chrome.declarativeNetRequest.RuleActionType, redirect: { extensionPath: target.pathname + target.search } },
            condition: { urlFilter: `|${plain}|`, isUrlFilterCaseSensitive: true, resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType] },
          },
        ],
      });
    } catch {
      await this.rules.release(key); // without site access this can be refused: the tab redirect is the fallback
    }
  }

  private async removeRule(key: string): Promise<void> {
    const id = await this.rules.release(key);
    if (id !== null) await this.browser.updateSessionRules({ removeRuleIds: [id] }).catch(() => undefined);
  }
}

export type { Entry };
