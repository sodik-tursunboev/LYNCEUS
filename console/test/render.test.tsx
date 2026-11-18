import { readFileSync, readdirSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Badge, ErrorLine, Hash } from "../src/ui";

describe("everything from the core is shown as text", () => {
  it("escapes hostile text in badges, hashes and errors", () => {
    const evil = "<img src=x onerror=alert(1)>";
    expect(renderToStaticMarkup(<Badge value={evil} />)).not.toContain("<img");
    expect(renderToStaticMarkup(<Hash value={evil + "a".repeat(20)} />)).not.toContain("<img");
    expect(renderToStaticMarkup(<ErrorLine error={evil} />)).not.toContain("<img");
    expect(renderToStaticMarkup(<ErrorLine error={null} />)).toBe("");
  });

  it("uses no way of putting markup, code or inline style into the page", () => {
    const dir = new URL("../src/", import.meta.url);
    const files = readdirSync(dir, { recursive: true }).filter((f) => /\.(ts|tsx)$/.test(f));
    expect(files.length).toBeGreaterThan(5);
    for (const f of files) {
      const text = readFileSync(new URL(f, dir), "utf8");
      for (const banned of ["dangerouslySetInnerHTML", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "style={", "document.cookie"]) {
        expect(text, `${f} contains ${banned}`).not.toContain(banned);
      }
      // UI2: the theme choice is the one thing kept between visits, in exactly one place
      if (String(f).replaceAll("\\", "/") !== "prefs.ts") expect(text, `${f} uses localStorage`).not.toContain("localStorage");
    }
  });

  it("keeps nothing between visits but the theme choice: one key, two accepted words", () => {
    const prefs = readFileSync(new URL("../src/prefs.ts", import.meta.url), "utf8");
    expect(prefs.match(/localStorage/g)).toHaveLength(1);
    expect(prefs).toContain('THEME_KEY = "lynceus.theme"');
    const boot = readFileSync(new URL("../static/theme.js", import.meta.url), "utf8");
    expect(boot.match(/localStorage\.\w+\("([^"]+)"/g)).toEqual(['localStorage.getItem("lynceus.theme"']); // reads, never writes
    expect(boot).not.toMatch(/setItem|innerHTML|eval|cookie|fetch|https?:/);
    const statics = readdirSync(new URL("../static/", import.meta.url), { recursive: true }).filter((f) => f.endsWith(".js"));
    expect(statics).toEqual(["theme.js"]); // the only script besides the bundle
  });

  it("the page loads only its own files", () => {
    const html = readFileSync(new URL("../static/index.html", import.meta.url), "utf8");
    expect(html).not.toMatch(/https?:\/\//);
    expect(html).not.toMatch(/<script(?![^>]*src=)/);
    expect(html).not.toMatch(/\sstyle=|\sonclick=|\sonload=/);
    expect([...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1]).sort()).toEqual(["console.css", "console.js", "favicon.svg", "theme.js"]);
  });
});
describe("feedback on a verdict (H1 B3)", () => {
  it("offers 'false alarm' on a flagged verdict and 'missed phishing' on an unflagged one", async () => {
    const { renderToString } = await import("react-dom/server");
    const { FeedbackPanel } = await import("../src/pages");
    const api = {} as never;
    const flagged = renderToString(<FeedbackPanel api={api} id="e1" state="SUSPICIOUS" given={null} />);
    expect(flagged).toContain("False alarm");
    expect(flagged).not.toContain("Missed phishing");
    const quiet = renderToString(<FeedbackPanel api={api} id="e2" state="UNKNOWN" given="missed" />);
    expect(quiet).toContain("Missed phishing");
    expect(quiet).toContain("You said this was phishing that Lynceus missed.");
  });
});
