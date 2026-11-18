import { describe, expect, it } from "vitest";
import { collapseRepeats, plural, ruleWords } from "../src/format";
import { GO, isTyping, readKey } from "../src/keys";
import { applyTheme, readTheme, THEME_KEY, writeTheme } from "../src/prefs";

function store(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  return { map, getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => void map.set(k, v), removeItem: (k: string) => void map.delete(k) };
}

describe("the theme choice", () => {
  it("is System unless Dark or Light was chosen, whatever else is stored", () => {
    expect(readTheme(store())).toBe("system");
    expect(readTheme(store({ [THEME_KEY]: "light" }))).toBe("light");
    expect(readTheme(store({ [THEME_KEY]: "dark" }))).toBe("dark");
    expect(readTheme(store({ [THEME_KEY]: "<script>" }))).toBe("system");
    expect(readTheme(null)).toBe("system");
    expect(readTheme({ getItem: () => { throw new Error("refused"); } })).toBe("system");
  });

  it("keeps one word under one key, and forgets it when System is chosen", () => {
    const s = store();
    writeTheme(s, "light");
    expect([...s.map]).toEqual([[THEME_KEY, "light"]]);
    writeTheme(s, "system");
    expect(s.map.size).toBe(0);
    expect(() => writeTheme({ getItem: () => null, setItem: () => { throw new Error("full"); }, removeItem: () => undefined }, "dark")).not.toThrow();
  });

  it("sets data-theme on the page for Dark and Light, and removes it for System", () => {
    const attrs = new Map<string, string>();
    const root = { setAttribute: (k: string, v: string) => void attrs.set(k, v), removeAttribute: (k: string) => void attrs.delete(k) };
    applyTheme(root, "dark");
    expect(attrs.get("data-theme")).toBe("dark");
    applyTheme(root, "system");
    expect(attrs.has("data-theme")).toBe(false);
  });
});

describe("the keyboard shortcuts", () => {
  it("go to a page with g then a letter, for every page in the list", () => {
    for (const [key, hash] of GO) {
      const first = readKey({ key: "g" }, false, false);
      expect(first).toEqual({ result: null, waiting: true });
      expect(readKey({ key }, first.waiting, false)).toEqual({ result: { go: hash }, waiting: false });
    }
    expect(new Set(GO.map(([k]) => k)).size).toBe(GO.length); // no letter is used twice
  });

  it("jump to the search with / and open the Guide with ?", () => {
    expect(readKey({ key: "/" }, false, false).result).toEqual({ search: true });
    expect(readKey({ key: "?" }, false, false).result).toEqual({ go: "#/guide" });
  });

  it("do nothing while typing, with a modifier held, or after g and an unknown letter", () => {
    expect(readKey({ key: "g" }, false, true)).toEqual({ result: null, waiting: false });
    expect(readKey({ key: "/", ctrlKey: true }, false, false).result).toBeNull();
    expect(readKey({ key: "o", altKey: true }, true, false).result).toBeNull();
    expect(readKey({ key: "z" }, true, false)).toEqual({ result: null, waiting: false });
    expect(isTyping({ tagName: "INPUT", type: "text" })).toBe(true);
    expect(isTyping({ tagName: "textarea" })).toBe(true);
    expect(isTyping({ tagName: "DIV", isContentEditable: true })).toBe(true);
    expect(isTyping({ tagName: "INPUT", type: "checkbox" })).toBe(false);
    expect(isTyping({ tagName: "BUTTON" })).toBe(false);
    expect(isTyping(null)).toBe(false);
  });
});

describe("the overview feed", () => {
  const ev = (kind: string, host: string | null, state: string, id: string) => ({ id, kind, host, state });

  it("collapses repeats of the same thing judged the same way, newest first, with a count", () => {
    const rows = collapseRepeats([
      ev("URL", "a.test", "MALICIOUS", "1"), ev("URL", "b.test", "SUSPICIOUS", "2"), ev("URL", "a.test", "MALICIOUS", "3"),
      ev("URL", "a.test", "SUSPICIOUS", "4"), ev("FILE", null, "MALICIOUS", "5"), ev("FILE", null, "MALICIOUS", "6"),
    ]);
    expect(rows.map((r) => [r.item.id, r.count])).toEqual([["1", 2], ["2", 1], ["4", 1], ["5", 2]]);
    expect(collapseRepeats([])).toEqual([]);
  });

  it("shows rule words instead of rule ids", () => {
    expect(ruleWords("url.brand_in_subdomain")).toBe("brand in subdomain");
    expect(ruleWords("email.sender.combosquat")).toBe("sender combosquat");
    expect(ruleWords("learned_domain")).toBe("learned domain");
    expect(ruleWords("")).toBe("");
    expect(plural(1, "event")).toBe("1 event");
    expect(plural(1200, "entry", "entries")).toBe("1,200 entries");
  });
});
