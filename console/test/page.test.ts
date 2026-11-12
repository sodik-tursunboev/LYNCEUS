import { describe, expect, it } from "vitest";
import { categoryMeta } from "../src/theme";

describe("page categories (D1)", () => {
  it("are named for what the page did, not as a link inside a message", () => {
    expect(categoryMeta("page.impersonation").label).toBe("The page impersonates a brand");
    expect(categoryMeta("page.exfiltration").icon).toBe("Target");
    expect(categoryMeta("link.impersonation").label).toBe("Impersonation (in a link)");
  });
});
