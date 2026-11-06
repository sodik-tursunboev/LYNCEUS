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

/** Detail objects from the audit log, as one line of plain text. */
export function compact(detail: Record<string, unknown> | null): string {
  if (!detail) return "";
  return Object.entries(detail)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(", ");
}