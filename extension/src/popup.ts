// The toolbar popup: is the agent there?
const set = (id: string, value: string): void => {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
};

export async function render(): Promise<void> {
  try {
    const s = (await chrome.runtime.sendMessage({ type: "status" })) as { agent?: string; judged?: number; waiting?: number } | undefined;
    if (s?.agent === "up") {
      set("head", "MIRAGE is protecting this browser");
      set("line", `Files judged: ${s.judged ?? 0}. Waiting: ${s.waiting ?? 0}.`);
    } else {
      set("head", "MIRAGE is not protecting this browser");
      set("line", "The MIRAGE agent is not running. Pages open as normal and are not checked.");
    }
  } catch {
    set("head", "MIRAGE is not protecting this browser");
    set("line", "The extension could not reach its background worker.");
  }
}

if (typeof document !== "undefined" && document.getElementById("head")) void render();
