import { describe, expect, it } from "vitest";
import {
  FACT_HELP, GAUGE_LENGTH, LIMITS, classifyPaste, confidenceBars, destination, explainFact, formatBytes, gaugeFill, hashRows, relativeTime,
  rolesPresent, scoreBand, segments, sha256Hex, sizeProblem, sortLinks, sortSignals, urlParts, verdictCounts,
} from "../src/analysis";
import { categoryMeta } from "../src/theme";
import { parseTime, when } from "../src/format";
import type { Anatomy, LinkRow } from "../src/types";

const anatomy = (over: Partial<Anatomy> = {}): Anatomy => ({
  scheme: "https", username: null, has_password: false, host: "login.secure-check.co.uk", host_unicode: "login.secure-check.co.uk", host_kind: "DOMAIN",
  subdomain: "login", registered_domain: "secure-check.co.uk", public_suffix: "co.uk", private_suffix: false, port: null, path: "/a", query: "", fragment: "", ...over,
});

describe("the anatomy of a link", () => {
  it("cuts a domain into subdomain, owner and suffix, in reading order, so the owner can be picked out", () => {
    const parts = urlParts(anatomy({ port: 8443, query: "x=1", fragment: "f" }));
    expect(parts.map((p) => [p.role, p.text])).toEqual([
      ["scheme", "https://"], ["subdomain", "login."], ["name", "secure-check"], ["dot", "."], ["suffix", "co.uk"],
      ["port", ":8443"], ["path", "/a"], ["query", "?x=1"], ["fragment", "#f"],
    ]);
    expect(parts.map((p) => p.text).join("")).toBe("https://login.secure-check.co.uk:8443/a?x=1#f");
  });

  it("shows the user name in front of the @ (the deception) and never a password", () => {
    const parts = urlParts(anatomy({ username: "www.paypal.com", has_password: true, subdomain: "", host: "evil.test", registered_domain: "evil.test", public_suffix: "test" }));
    const user = parts.find((p) => p.role === "userinfo");
    expect(user?.text).toBe("www.paypal.com:••••@");
    expect(parts.map((p) => p.text).join("")).not.toMatch(/secret/);
  });

  it("lays out an IP address, an IPv6 address and a name with no registered domain as one host", () => {
    expect(urlParts(anatomy({ host: "203.0.113.5", host_kind: "IPV4", registered_domain: null, public_suffix: null, subdomain: "", path: "" })).map((p) => [p.role, p.text]))
      .toEqual([["scheme", "https://"], ["host", "203.0.113.5"]]);
    expect(urlParts(anatomy({ host: "2001:db8::1", host_kind: "IPV6", registered_domain: null, public_suffix: null, subdomain: "", path: "" }))[1]).toEqual({ role: "host", text: "[2001:db8::1]" });
    expect(urlParts(anatomy({ host: "localhost", registered_domain: null, public_suffix: null, subdomain: "", path: "" }))[1]).toEqual({ role: "host", text: "localhost" });
  });

  it("says where the browser really goes, and lists each kind of part once", () => {
    expect(destination(anatomy())).toBe("secure-check.co.uk");
    expect(destination(anatomy({ registered_domain: null, host: "203.0.113.5" }))).toBe("203.0.113.5");
    expect(rolesPresent(urlParts(anatomy()))).toEqual(["scheme", "subdomain", "name", "suffix", "path"]);
  });

  it("copes with a registered domain that does not end in its suffix", () => {
    const parts = urlParts(anatomy({ registered_domain: "weird", public_suffix: "co.uk", subdomain: "" }));
    expect(parts.filter((p) => p.role === "name" || p.role === "suffix").map((p) => p.text)).toEqual(["weird"]);
  });
});

describe("the risk ring", () => {
  it("fills in proportion to the score, clamps, and is empty for no score", () => {
    expect(gaugeFill(0)).toBe(0);
    expect(gaugeFill(50)).toBeCloseTo(GAUGE_LENGTH / 2);
    expect(gaugeFill(100)).toBeCloseTo(GAUGE_LENGTH);
    expect(gaugeFill(250)).toBeCloseTo(GAUGE_LENGTH);
    expect(gaugeFill(-5)).toBe(0);
    expect(gaugeFill(null)).toBe(0);
    expect(gaugeFill(Number.NaN)).toBe(0);
  });
  it("bands a score, and keeps 'not scored' apart from a low score", () => {
    expect([null, 0, 29, 30, 59, 60, 100].map(scoreBand)).toEqual(["none", "low", "low", "medium", "medium", "high", "high"]);
  });
  it("shows confidence as filled bars", () => {
    expect(["LOW", "MEDIUM", "HIGH", "?"].map(confidenceBars)).toEqual([1, 2, 3, 0]);
  });
});

describe("counts, order and sizes", () => {
  it("counts verdicts, including none of some kinds, and ignores anything else", () => {
    expect(verdictCounts([{ state: "MALICIOUS" }, { state: "MALICIOUS" }, { state: "BENIGN" }, { state: "weird" }])).toEqual({ MALICIOUS: 2, SUSPICIOUS: 0, BENIGN: 1, UNKNOWN: 0, ERROR: 0 });
  });
  it("lays the verdict bar out as segments that add up to the strip, with gaps", () => {
    const segs = segments({ MALICIOUS: 2, SUSPICIOUS: 1, BENIGN: 0, UNKNOWN: 1, ERROR: 0 });
    expect(segs.map((s) => s.state)).toEqual(["MALICIOUS", "SUSPICIOUS", "UNKNOWN"]);
    const last = segs[segs.length - 1]!;
    expect(last.x + last.width).toBeCloseTo(100);
    expect(segs[1]!.x).toBeGreaterThan(segs[0]!.x + segs[0]!.width);
    expect(segments({ MALICIOUS: 0, SUSPICIOUS: 0, BENIGN: 0, UNKNOWN: 0, ERROR: 0 })).toEqual([]);
    expect(segments({ MALICIOUS: 0, SUSPICIOUS: 0, BENIGN: 3, UNKNOWN: 0, ERROR: 0 })).toEqual([{ state: "BENIGN", x: 0, width: 100 }]);
  });
  it("puts the strongest sign first and keeps ties in a stable order", () => {
    const s = (rule_id: string, weight: number) => ({ rule_id, weight });
    expect(sortSignals([s("b", 0.5), s("a", 0.5), s("c", 0.9), s("d", 0.1)]).map((x) => x.rule_id)).toEqual(["c", "a", "b", "d"]);
  });
  it("puts the riskiest link first and unscored links last", () => {
    const l = (host: string, risk_score: number | null) => ({ host, risk_score }) as LinkRow;
    expect(sortLinks([l("c", null), l("a", 40), l("b", 90), l("d", 0)]).map((x) => x.host)).toEqual(["b", "a", "d", "c"]);
  });
  it("formats sizes and times", () => {
    expect([0, 900, 2048, 5 * 1024 * 1024].map(formatBytes)).toEqual(["0 B", "900 B", "2.0 KB", "5.0 MB"]);
    const now = Date.parse("2026-11-06T12:00:00Z");
    expect([
      "2026-11-06T11:59:50Z", "2026-11-06T11:59:00Z", "2026-11-06T11:30:00Z", "2026-11-06T07:00:00Z", "2026-11-04T12:00:00Z",
    ].map((t) => relativeTime(t, now))).toEqual(["just now", "a minute ago", "30 min ago", "5 h ago", "2 d ago"]);
    expect(relativeTime(null, now)).toBe("");
    expect(relativeTime("not a date", now)).toBe("");
  });
  it("reads the core's zone-less UTC times as UTC, not as local time", () => {
    expect(parseTime("2026-11-06T10:50:00").toISOString()).toBe("2026-11-06T10:50:00.000Z");
    expect(parseTime("2026-11-06T10:50:00Z").toISOString()).toBe("2026-11-06T10:50:00.000Z");
    expect(parseTime("2026-11-06T12:50:00+02:00").toISOString()).toBe("2026-11-06T10:50:00.000Z");
    expect(relativeTime("2026-11-06T11:59:50", Date.parse("2026-11-06T12:00:00Z"))).toBe("just now");
    expect(when("")).toBe("");
  });
});

describe("what can be analysed", () => {
  it("refuses what the core would refuse, saying why", () => {
    expect(sizeProblem("email", 0)).toBe("That file is empty.");
    expect(sizeProblem("email", LIMITS.email)).toBeNull();
    expect(sizeProblem("email", LIMITS.email + 1)).toMatch(/MIRAGE reads up to 10\.0 MB/);
    expect(sizeProblem("file", LIMITS.file + 1)).toMatch(/up to 16\.0 MB/);
    expect(sizeProblem("file", 1)).toBeNull();
  });
  it("tells a pasted link from the source of a message", () => {
    expect(classifyPaste("")).toBe("empty");
    expect(classifyPaste("   ")).toBe("empty");
    expect(classifyPaste("https://example.test/a?b=c")).toBe("url");
    expect(classifyPaste("hxxps://evil[.]test/login")).toBe("url");
    expect(classifyPaste("example.test/login")).toBe("url");
    expect(classifyPaste("Received: from x\nFrom: a@b.test\nSubject: hi\n\nbody")).toBe("email");
    expect(classifyPaste("From: a@b.test")).toBe("unclear"); // one header line is not a message
    expect(classifyPaste("just some words")).toBe("unclear");
  });
  it("fingerprints bytes with SHA-256", async () => {
    const abc = new TextEncoder().encode("abc");
    expect(await sha256Hex(abc.buffer.slice(abc.byteOffset, abc.byteOffset + abc.byteLength) as ArrayBuffer)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // pragma: allowlist secret (the published SHA-256 of "abc")
    );
  });
});

describe("what was found inside a file", () => {
  it("says each fixed word in plain English, with or without a count in front", () => {
    expect(explainFact("download")).toMatch(/Internet/);
    expect(explainFact("3x exec shell")).toBe(FACT_HELP["exec shell"]);
    expect(explainFact("2 entries hashed")).toBeNull();
    expect(explainFact("")).toBeNull();
  });

  it("explains every indicator the core can report", () => {
    const indicators = [
      "exec shell", "download", "execute dynamic", "encoded command", "base64 decode", "hidden window", "bypass policy", "persistence",
      "lolbin proxy", "defense evasion", "process injection", "credential access", "credential prompt", "anti analysis", "string obfuscation",
      "high entropy blob", "autoexec", "macro code", "remote template", "dde", "ole object", "equation editor", "lnk interpreter",
      "lnk hidden args", "lnk icon lure", "pe packed", "pe rwx", "pe injection apis", "pe downloader apis", "pe overlay",
    ];
    for (const name of indicators) expect(explainFact(name), name).not.toBeNull();
  });

  it("lists the fingerprints in a fixed order and skips what the core did not compute", () => {
    const rows = hashRows({ md5: "m".repeat(32), sha256: "s".repeat(64), sha1: "" });
    expect(rows.map((r) => r.label)).toEqual(["SHA-256", "MD5"]);
    expect(hashRows(undefined)).toEqual([]);
    expect(hashRows({ other: "x" })).toEqual([]);
  });

  it("gives the new evidence categories an icon and a plain label", () => {
    for (const c of ["code_behavior", "obfuscation", "evasion", "persistence", "known_bad"]) {
      expect(categoryMeta(c).label, c).not.toMatch(/_/);
    }
    expect(categoryMeta("known_bad").label).toBe("Known malware");
  });
});
