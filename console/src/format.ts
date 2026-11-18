export const shortHash = (h: string | null | undefined): string => (h ? h.slice(0, 12) : "");

/** The core sends UTC times, but without a zone ("2026-11-06T10:50:00"): a bare date-time would be read as local time. */
export function parseTime(iso: string): Date {
  return new Date(/(?:Z|[+-]\d\d:?\d\d)$/.test(iso) || !/T\d\d:\d\d/.test(iso) ? iso : `${iso}Z`);
}

export function when(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = parseTime(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export const score = (n: number | null): string => (n === null ? "not scored" : String(n));

/**
 * A rule id in words, for lists where the id itself would be noise: "url.brand_in_subdomain" is "brand in
 * subdomain", "email.sender.combosquat" is "sender combosquat". The id stays in the tooltip and on the event page.
 */
export function ruleWords(id: string): string {
  const parts = id.split(".").filter(Boolean);
  const rest = parts.length > 1 ? parts.slice(1) : parts;
  return rest.join(" ").replaceAll("_", " ").trim() || id;
}

/**
 * The same thing judged the same way several times (a link opened again, a file re-checked) shown once, with how
 * many times. Order is kept: each group sits where its newest member was.
 */
export function collapseRepeats<T extends { kind: string; host: string | null; state: string }>(items: readonly T[]): Array<{ item: T; count: number }> {
  const groups = new Map<string, { item: T; count: number }>();
  for (const item of items) {
    const key = `${item.kind}\u0000${item.host ?? ""}\u0000${item.state}`;
    const seen = groups.get(key);
    if (seen) seen.count += 1;
    else groups.set(key, { item, count: 1 });
  }
  return [...groups.values()];
}

/** A count with its noun: "1 event", "3 events". */
export const plural = (n: number, one: string, many = `${one}s`): string => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** Detail objects from the audit log, as one line of plain text. */
export function compact(detail: Record<string, unknown> | null): string {
  if (!detail) return "";
  return Object.entries(detail)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(", ");
}