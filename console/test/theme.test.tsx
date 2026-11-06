import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Icon } from "../src/Icon";
import { ICONS } from "../src/icons.generated";
import { ACTION_ICON, ACTION_TONE, CATEGORY, KIND_ICON, VERDICT, categoryMeta, flagText, kindIcon, verdictMeta } from "../src/theme";
import type { ActionState, VerdictState } from "../src/types";
import { Badge, Chip, Confidence, Distribution, Gauge, WeightBar } from "../src/ui";

const STATES: VerdictState[] = ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "ERROR"];
const ACTIONS: ActionState[] = ["PENDING", "APPROVED", "APPLIED", "DISMISSED", "FAILED", "RESTORE_REQUESTED", "RESTORED"];

describe("icons", () => {
  it("every icon the design refers to exists in the set, in all three weights", () => {
    const names = new Set<string>([
      ...Object.values(VERDICT).map((v) => v.icon), ...Object.values(CATEGORY).map((c) => c.icon),
      ...Object.values(KIND_ICON), ...Object.values(ACTION_ICON),
    ]);
    for (const name of names) {
      expect(ICONS, name).toHaveProperty(name);
      const weights = (ICONS as unknown as Record<string, Record<string, readonly unknown[]>>)[name]!;
      for (const weight of ["regular", "duotone", "fill"]) expect(weights[weight]!.length, `${name} ${weight}`).toBeGreaterThan(0);
    }
  });

  it("draws decorative icons hidden from screen readers, and labelled ones as images", () => {
    expect(renderToStaticMarkup(<Icon name="Skull" />)).toContain('aria-hidden="true"');
    const labelled = renderToStaticMarkup(<Icon name="Skull" label="Malicious" />);
    expect(labelled).toContain('role="img"');
    expect(labelled).toContain('aria-label="Malicious"');
    expect(labelled).not.toContain("aria-hidden");
  });

  it("draws plain shapes and nothing else (no script, no foreign content, no external reference)", () => {
    const markup = renderToStaticMarkup(<Icon name="ShieldCheck" weight="duotone" />);
    expect(markup).toMatch(/^<svg [^>]*viewBox="0 0 256 256"/);
    expect(markup).not.toMatch(/<script|<foreignObject|href=|xlink|onload|style=/i);
  });
});

describe("what a verdict looks like", () => {
  it("every verdict has an icon, a tone and words; unknown and error are never styled as safe", () => {
    for (const s of STATES) {
      const m = verdictMeta(s);
      expect(m.headline.length, s).toBeGreaterThan(8);
      expect(m.meaning.length, s).toBeGreaterThan(20);
    }
    expect(VERDICT.UNKNOWN.tone).not.toBe("ok");
    expect(VERDICT.ERROR.tone).not.toBe("ok");
    expect(VERDICT.UNKNOWN.meaning).toMatch(/not safe/i);
    expect(VERDICT.ERROR.meaning).toMatch(/never a statement that it is safe/i);
    expect(verdictMeta("something new")).toBe(VERDICT.UNKNOWN); // an unrecognised state is "unknown", never "benign"
  });

  it("every response state has a tone and an icon", () => {
    for (const a of ACTIONS) {
      expect(ACTION_TONE[a], a).toBeTruthy();
      expect(ACTION_ICON[a], a).toBeTruthy();
    }
  });

  it("badges carry the words as well as the colour and escape hostile text", () => {
    const html = renderToStaticMarkup(<Badge value="MALICIOUS" />);
    expect(html).toContain("MALICIOUS");
    expect(html).toContain("tone-bad");
    expect(renderToStaticMarkup(<Badge value="RESTORE_REQUESTED" />)).toContain("RESTORE REQUESTED");
    expect(renderToStaticMarkup(<Badge value={"<b onmouseover=1>x</b>"} />)).not.toContain("<b ");
  });

  it("maps link-scoped categories to the same icon and says so", () => {
    expect(categoryMeta("impersonation")).toEqual(CATEGORY.impersonation);
    expect(categoryMeta("link.impersonation")).toEqual({ icon: CATEGORY.impersonation!.icon, label: "Impersonation (in a link)" });
    expect(categoryMeta("brand_new_kind")).toEqual({ icon: "Tag", label: "brand new kind" });
    expect(kindIcon("qr")).toBe("QrCode");
    expect(kindIcon("never seen")).toBe("File");
  });

  it("explains every URL flag in plain words, and shows an unknown one readably", () => {
    expect(flagText("USERINFO")).toMatch(/ignores everything before the @/);
    expect(flagText("SOME_NEW_FLAG")).toBe("some new flag");
  });
});

describe("the pieces the analysis page is made of", () => {
  it("the risk ring states the score in words, and 'not scored' when there is none", () => {
    expect(renderToStaticMarkup(<Gauge score={91} state="MALICIOUS" />)).toContain("Risk score 91 out of 100");
    const none = renderToStaticMarkup(<Gauge score={null} state="UNKNOWN" />);
    expect(none).toContain("Risk score: not scored");
    expect(none).toContain("not scored");
    expect(none).toContain("band-none");
  });

  it("a weight is a labelled meter with its number", () => {
    const html = renderToStaticMarkup(<WeightBar weight={0.7} />);
    expect(html).toContain('role="meter"');
    expect(html).toContain('aria-valuenow="70"');
    expect(html).toContain("0.70");
    expect(renderToStaticMarkup(<WeightBar weight={4} />)).toContain('aria-valuenow="100"');
  });

  it("the verdict distribution reads out its numbers and stays valid with nothing in it", () => {
    const html = renderToStaticMarkup(<Distribution items={[{ state: "MALICIOUS" }, { state: "MALICIOUS" }, { state: "UNKNOWN" }]} />);
    expect(html).toContain("2 malicious, 0 suspicious, 1 unknown, 0 error, 0 benign");
    expect(renderToStaticMarkup(<Distribution items={[]} />)).toContain("dist-empty");
  });

  it("confidence is words with bars, and chips escape what they are given", () => {
    expect(renderToStaticMarkup(<Confidence level="HIGH" />)).toContain("high confidence");
    expect(renderToStaticMarkup(<Chip>{"<img src=x>"}</Chip>)).not.toContain("<img");
  });
});
