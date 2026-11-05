// Messages between the extension and the MIRAGE agent (through the native host). Replies are
// validated strictly: anything that is not exactly one of these shapes is dropped, so a confused
// or hostile host can never make the extension treat an unknown thing as a verdict.

export const STATES = ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "ERROR"] as const;
export type State = (typeof STATES)[number];

export interface VerdictReply {
  type: "verdict";
  id: string;
  state: State;
  score: number | null;
  recommended: string | null;
  explanation: string | null;
  reasons: string[];
}
export interface ErrorReply {
  type: "error";
  id: string | null;
  error: string;
}
export interface OverrideOk {
  type: "override_ok";
  id: string;
  expires_at: string;
}
export interface StatusReply {
  type: "status";
  id: string;
  agent: string;
  judged: number;
  waiting: number;
}
export type Reply = VerdictReply | ErrorReply | OverrideOk | StatusReply;

export type Request =
  | { type: "check_url"; url: string }
  | { type: "override"; url: string; state?: State; minutes?: number }
  | { type: "status" };

export const AGENT_DOWN = "agent_unavailable";
export const AGENT_SLOW = "agent_timeout";

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown, max: number): string | null => (typeof v === "string" && v.length <= max ? v : null);
const nullableStr = (v: unknown, max: number): string | null | undefined =>
  v === null || v === undefined ? null : str(v, max) ?? undefined;

export function parseReply(raw: unknown): Reply | null {
  if (!isObj(raw) || raw.v !== 1 || typeof raw.type !== "string") return null;
  const id = raw.id === undefined || raw.id === null ? null : str(raw.id, 64);
  switch (raw.type) {
    case "verdict": {
      const state = STATES.find((s) => s === raw.state);
      const score = raw.score === null ? null : typeof raw.score === "number" && Number.isFinite(raw.score) ? raw.score : undefined;
      const recommended = nullableStr(raw.recommended, 200);
      const explanation = nullableStr(raw.explanation, 600);
      const reasons = raw.reasons;
      if (
        id === null || state === undefined || score === undefined || recommended === undefined || explanation === undefined ||
        !Array.isArray(reasons) || reasons.length > 8 || !reasons.every((r) => typeof r === "string" && r.length <= 300)
      ) {
        return null;
      }
      return { type: "verdict", id, state, score, recommended, explanation, reasons: reasons as string[] };
    }
    case "error": {
      const error = str(raw.error, 64);
      return error === null ? null : { type: "error", id, error };
    }
    case "override_ok": {
      const expires = str(raw.expires_at, 64);
      return id === null || expires === null ? null : { type: "override_ok", id, expires_at: expires };
    }
    case "status": {
      const agent = str(raw.agent, 32);
      if (id === null || agent === null || typeof raw.judged !== "number" || typeof raw.waiting !== "number") return null;
      return { type: "status", id, agent, judged: raw.judged, waiting: raw.waiting };
    }
    default:
      return null;
  }
}

export const isBad = (state: State): boolean => state === "MALICIOUS" || state === "SUSPICIOUS";
