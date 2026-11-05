export const shortHash = (h: string | null | undefined): string => (h ? h.slice(0, 12) : "");

export function when(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
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