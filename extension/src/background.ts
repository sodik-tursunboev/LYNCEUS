// The service worker. Event listeners are registered at the top level, as Manifest V3 requires,
// so a worker the browser stopped is woken by the next event and reconnects to the agent.
import { Guard } from "./guard";
import { NativeLink } from "./native";
import { Overrides, RuleBook, sessionKV, VerdictCache } from "./store";

const kv = sessionKV(chrome.storage.session);
let guard: Guard | undefined;

const link = new NativeLink(chrome.runtime, (state) => {
  if (guard) guard.badge(state === "up" ? "ok" : "down");
});

guard = new Guard(
  link,
  new VerdictCache(kv),
  new Overrides(kv),
  new RuleBook(kv),
  {
    getURL: (path) => chrome.runtime.getURL(path),
    updateTab: (tabId, url) => chrome.tabs.update(tabId, { url }),
    setBadge: (text, color, title) => {
      void chrome.action.setBadgeText({ text });
      void chrome.action.setBadgeBackgroundColor({ color });
      void chrome.action.setTitle({ title });
    },
    updateSessionRules: (change) => chrome.declarativeNetRequest.updateSessionRules(change),
  },
);

link.connect();

const onNav = (d: { tabId: number; frameId: number; url: string }): void => {
  void guard?.onNavigation({ tabId: d.tabId, frameId: d.frameId, url: d.url });
};
chrome.webNavigation.onBeforeNavigate.addListener(onNav);
chrome.webNavigation.onCommitted.addListener(onNav); // the page a redirect ended on
chrome.tabs.onRemoved.addListener((tabId) => guard?.forgetTab(tabId));

/**
 * Messages come only from this extension's own pages. Only the warning page may ask for an override, and
 * only when it is the top frame of a tab: warning.html is reachable by any website, so a copy framed
 * inside an attacker's page (to catch a click) has a sub-frame sender and is refused.
 */
chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || typeof message !== "object" || message === null) return false;
  const m = message as { type?: unknown; url?: unknown; mistake?: unknown };
  if (m.type === "status") {
    void guard?.status().then(sendResponse);
    return true;
  }
  const fromWarningPage =
    typeof sender.url === "string" &&
    sender.url.startsWith(chrome.runtime.getURL("warning.html")) &&
    sender.frameId === 0 &&
    typeof sender.tab?.id === "number";
  if (m.type === "override" && fromWarningPage && typeof m.url === "string") {
    void guard?.override(m.url, m.mistake === true).then(sendResponse);
    return true;
  }
  return false;
});
