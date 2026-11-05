// Site access is optional: asked for here, once, from a real click.
const ORIGINS = ["http://*/*", "https://*/*"];
const set = (value: string): void => {
  const el = document.getElementById("state");
  if (el) el.textContent = value;
};

export async function refresh(): Promise<void> {
  const granted = await chrome.permissions.contains({ origins: ORIGINS });
  set(granted ? "Instant blocking is on." : "Instant blocking is off: a bad page may start loading before the warning replaces it.");
  const button = document.getElementById("grant") as HTMLButtonElement | null;
  if (button) button.hidden = granted;
}

if (typeof document !== "undefined" && document.getElementById("grant")) {
  document.getElementById("grant")?.addEventListener("click", () => {
    chrome.permissions.request({ origins: ORIGINS }).then(() => refresh(), () => set("The browser did not grant access."));
  });
  void refresh();
}
