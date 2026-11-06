import { parseTime } from "./format";
import type { Anatomy, LinkRow, VerdictState } from "./types";

// ---- the anatomy of a URL ----------------------------------------------------------------------------

export type Role = "scheme" | "userinfo" | "subdomain" | "name" | "suffix" | "host" | "dot" | "port" | "path" | "query" | "fragment";
export interface UrlPart { role: Role; text: string }

/**
 * The URL cut into parts, in reading order, each with a role. The server does the cutting (it has the Public Suffix
 * List); this only lays the parts out so that the one part that decides where the browser goes stands out.
 * A password is never shown, even though the server only reports that there was one.
 */
export function urlParts(a: Anatomy): UrlPart[] {
  const parts: UrlPart[] = [{ role: "scheme", text: `${a.scheme}://` }];
  if (a.username !== null || a.has_password) {
    parts.push({ role: "userinfo", text: `${a.username ?? ""}${a.has_password ? ":••••" : ""}@` });
  }
  if (a.host_kind === "DOMAIN" && a.registered_domain) {
    if (a.subdomain) parts.push({ role: "subdomain", text: `${a.subdomain}.` });
    const suffix = a.public_suffix ?? "";
    const owned = a.registered_domain;
    const name = suffix && owned.endsWith(`.${suffix}`) ? owned.slice(0, -(suffix.length + 1)) : owned;
    parts.push({ role: "name", text: name });
    if (suffix && name !== owned) parts.push({ role: "dot", text: "." }, { role: "suffix", text: suffix });
  } else if (a.host) {
    parts.push({ role: "host", text: a.host_kind === "IPV6" ? `[${a.host}]` : a.host });
  }
  if (a.port !== null) parts.push({ role: "port", text: `:${a.port}` });
  if (a.path) parts.push({ role: "path", text: a.path });
  if (a.query) parts.push({ role: "query", text: `?${a.query}` });
  if (a.fragment) parts.push({ role: "fragment", text: `#${a.fragment}` });
  return parts;
}

/** The site the browser really connects to: the registered domain, or the bare host (an IP, an unusual name). */
export const destination = (a: Anatomy): string | null => a.registered_domain ?? a.host;

export const ROLE_TEXT: Record<Exclude<Role, "dot">, { label: string; help: string }> = {
  scheme: { label: "Scheme", help: "How the browser talks to the site. https means encrypted, not trustworthy." },
  userinfo: { label: "User name", help: "Placed before the @. The browser ignores it when it picks where to go, so attackers put a trusted-looking name here." },
  subdomain: { label: "Subdomain", help: "Chosen freely by whoever owns the domain: anyone can make login.paypal.com.example.test." },
  name: { label: "Owner", help: "The registered domain minus its suffix: who actually owns this address. This is where the browser goes." },
  suffix: { label: "Suffix", help: "The public suffix the domain is registered under (.com, .co.uk)." },
  host: { label: "Host", help: "A bare address or a name without a registered domain." },
  port: { label: "Port", help: "A non-standard port is unusual for a real login page." },
  path: { label: "Path", help: "Which page on the site. Words like login or verify here prove nothing about the site." },
  query: { label: "Query", help: "Extra data sent with the request. It can carry an e-mail address or a redirect target." },
  fragment: { label: "Fragment", help: "Handled by the browser only; never sent to the site." },
};

export const rolesPresent = (parts: UrlPart[]): Array<Exclude<Role, "dot">> => {
  const seen: Array<Exclude<Role, "dot">> = [];
  for (const p of parts) if (p.role !== "dot" && !seen.includes(p.role)) seen.push(p.role);
  return seen;
};

// ---- the risk gauge ------------------------------------------------------------------------------------

export const GAUGE_RADIUS = 54;
export const GAUGE_LENGTH = 2 * Math.PI * GAUGE_RADIUS;

export type Band = "none" | "low" | "medium" | "high";
export const scoreBand = (score: number | null): Band => (score === null ? "none" : score >= 60 ? "high" : score >= 30 ? "medium" : "low");

/** How much of the ring is filled for a score. A missing score is an empty ring, never a full or a zero one by accident. */
export function gaugeFill(score: number | null): number {
  if (score === null || Number.isNaN(score)) return 0;
  return (Math.min(100, Math.max(0, score)) / 100) * GAUGE_LENGTH;
}

// ---- lists and counts ------------------------------------------------------------------------------------

export const STATES: VerdictState[] = ["MALICIOUS", "SUSPICIOUS", "UNKNOWN", "ERROR", "BENIGN"];

export function verdictCounts(items: Array<{ state: string }>): Record<VerdictState, number> {
  const counts: Record<VerdictState, number> = { MALICIOUS: 0, SUSPICIOUS: 0, BENIGN: 0, UNKNOWN: 0, ERROR: 0 };
  for (const item of items) if (item.state in counts) counts[item.state as VerdictState] += 1;
  return counts;
}

/** The verdict bar as segments of a 100-wide strip, in STATES order, with a small gap between them. */
export function segments(counts: Record<VerdictState, number>): Array<{ state: VerdictState; x: number; width: number }> {
  const total = STATES.reduce((n, s) => n + counts[s], 0);
  if (total === 0) return [];
  const present = STATES.filter((s) => counts[s] > 0);
  const gap = present.length > 1 ? 1 : 0;
  const room = 100 - gap * (present.length - 1);
  let x = 0;
  return present.map((state) => {
    const width = (counts[state] / total) * room;
    const seg = { state, x, width };
    x += width + gap;
    return seg;
  });
}

/** Strongest sign first; ties keep a stable order by rule id so the page does not shuffle. */
export const sortSignals = <T extends { weight: number; rule_id: string }>(signals: T[]): T[] =>
  [...signals].sort((a, b) => b.weight - a.weight || a.rule_id.localeCompare(b.rule_id));

/** Riskiest link first, unscored links last. */
export const sortLinks = (links: LinkRow[]): LinkRow[] =>
  [...links].sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1) || (a.host ?? "").localeCompare(b.host ?? ""));

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function relativeTime(iso: string | null | undefined, now: number): string {
  if (!iso) return "";
  const then = parseTime(iso).getTime();
  if (Number.isNaN(then)) return "";
  const s = Math.round((now - then) / 1000);
  if (s < 45) return "just now";
  if (s < 90) return "a minute ago";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return d < 8 ? `${d} d ago` : parseTime(iso).toLocaleDateString();
}

// ---- what can be analysed ----------------------------------------------------------------------------------

/** The same limits the core enforces (core/config.py); checking here only saves a pointless upload. */
export const LIMITS = { email: 10 * 1024 * 1024, file: 16 * 1024 * 1024 - 4096, url: 8192 };

export function sizeProblem(kind: "email" | "file", size: number): string | null {
  if (size === 0) return "That file is empty.";
  return size > LIMITS[kind] ? `That is ${formatBytes(size)}; MIRAGE reads up to ${formatBytes(LIMITS[kind])}.` : null;
}

export type Pasted = "empty" | "url" | "email" | "unclear";

/** What a pasted block of text most likely is: a link, or the source of a message. */
export function classifyPaste(text: string): Pasted {
  const t = text.trim();
  if (!t) return "empty";
  if (/^(?:received|return-path|from|to|subject|mime-version|content-type|date|message-id|delivered-to|x-[\w-]+):/im.test(t) && t.includes("\n")) return "email";
  if (!/\s/.test(t) && (/^[a-z][a-z0-9+.-]*:\/\//i.test(t) || /^[\w-]+(\.[\w-]+)+(:\d+)?([/?#].*)?$/.test(t) || /^hxxps?:\/\//i.test(t))) return "url";
  return "unclear";
}

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A confidence word as a number of filled bars (of three). */
export const confidenceBars = (c: string): number => (c === "HIGH" ? 3 : c === "MEDIUM" ? 2 : c === "LOW" ? 1 : 0);
