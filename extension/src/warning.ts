import { STATES, type State } from "./protocol";
import { VerdictCache, sessionKV } from "./store";

/** What the warning page is told by its own address: the verdict key, the state, and the page it stopped. */
export function readParams(search: string): { key: string; state: State; url: string } | null {
  const q = new URLSearchParams(search);
  const key = q.get("k") ?? "";
  const url = q.get("u") ?? "";
  const state = STATES.find((s) => s === q.get("s"));
  if (!/^[0-9a-f]{64}$/.test(key) || state === undefined || url.length === 0 || url.length > 8192) return null;
  return { key, state, url };
}

/** The same page is used for both bad verdicts; only the wording and the weight of the buttons differ. */
export function wording(state: State): { title: string; lead: string } {
  return state === "MALICIOUS"
    ? { title: "This page looks like phishing", lead: "Lynceus stopped this page before it loaded. It matched several signs of a phishing attempt." }
    : { title: "This page looks suspicious", lead: "Lynceus stopped this page. It showed some signs of phishing, but not enough to be sure." };
}

function text(id: string, value: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = value; // text only: nothing from a URL or a reason is ever parsed as HTML
}

async function main(): Promise<void> {
  if (window.top !== window) {
    // Framed inside another page (any website can do that): show nothing it could be clicked through.
    text("title", "Lynceus warning page");
    text("lead", "This warning is only shown on its own, not inside another page.");
    document.getElementById("actions")?.setAttribute("hidden", "");
    return;
  }
  const params = readParams(location.search);
  if (!params) {
    text("title", "Lynceus warning page");
    text("lead", "This page was opened without the information it needs.");
    document.getElementById("actions")?.setAttribute("hidden", "");
    return;
  }
  const { title, lead } = wording(params.state);
  document.title = title;
  document.body.dataset.state = params.state;
  text("title", title);
  text("lead", lead);
  text("url", params.url);
  const entry = await new VerdictCache(sessionKV(chrome.storage.session)).get(params.key);
  if (entry?.explanation) text("why", entry.explanation);
  const list = document.getElementById("reasons");
  for (const reason of entry?.reasons ?? []) {
    const li = document.createElement("li");
    li.textContent = reason;
    list?.append(li);
  }

  document.getElementById("back")?.addEventListener("click", () => {
    if (history.length > 1) history.back();
    else window.close();
  });
  const proceed = (mistake: boolean) => (event: Event) => {
    if (!event.isTrusted) return; // only a real click counts
    text("status", mistake ? "Recording your report and your decision..." : "Recording your decision...");
    chrome.runtime.sendMessage({ type: "override", url: params.url, ...(mistake ? { mistake: true } : {}) }).then(
      (answer: { ok?: boolean } | undefined) => {
        if (answer?.ok) location.replace(params.url);
        else text("status", "The decision could not be recorded, so the page stays blocked. Is the Lynceus agent running?");
      },
      () => text("status", "The decision could not be recorded, so the page stays blocked."),
    );
  };
  document.getElementById("continue")?.addEventListener("click", proceed(false));
  // H1 B3: the same recorded continue, plus "this warning was wrong" for the rules that fired
  document.getElementById("report")?.addEventListener("click", proceed(true));
}

if (typeof document !== "undefined" && document.getElementById("title")) void main();
