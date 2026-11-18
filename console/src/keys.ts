// Keyboard shortcuts (UI2): "g" then a letter goes to a page, "/" jumps to the page's search or link box, "?" opens
// the Guide. Never while you are typing in a field, and never with Ctrl, Alt or the Windows key held (those belong
// to the browser and to Windows).
export const GO: ReadonlyArray<readonly [key: string, hash: string, label: string]> = [
  ["o", "#/", "Overview"],
  ["e", "#/events", "Events"],
  ["r", "#/actions", "Responses"],
  ["a", "#/analyze", "Analyze"],
  ["l", "#/allow", "Allow list"],
  ["f", "#/feedback", "Feedback"],
  ["u", "#/audit", "Audit log"],
  ["p", "#/protection", "Protection"],
  ["h", "#/guide", "Guide"],
];

export interface KeyLike { key: string; ctrlKey?: boolean; metaKey?: boolean; altKey?: boolean }
export type KeyResult = { go: string } | { search: true } | null;

/** True when the key press lands in something you type into. */
export function isTyping(target: { tagName?: string; isContentEditable?: boolean; type?: string } | null): boolean {
  if (!target?.tagName) return false;
  const tag = target.tagName.toUpperCase();
  if (tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable) return true;
  return tag === "INPUT" && !["checkbox", "radio", "button", "submit", "reset", "file"].includes(String(target.type ?? "text").toLowerCase());
}

/**
 * One step of the shortcut reader. `waiting` is true after a lone "g"; the caller keeps it (and drops it after a
 * moment). Returns what to do and whether a "g" is now waiting.
 */
export function readKey(e: KeyLike, waiting: boolean, typing: boolean): { result: KeyResult; waiting: boolean } {
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return { result: null, waiting: false };
  if (waiting) {
    const target = GO.find(([k]) => k === e.key.toLowerCase());
    return { result: target ? { go: target[1] } : null, waiting: false };
  }
  if (e.key === "g" || e.key === "G") return { result: null, waiting: true };
  if (e.key === "/") return { result: { search: true }, waiting: false };
  if (e.key === "?") return { result: { go: "#/guide" }, waiting: false };
  return { result: null, waiting: false };
}
