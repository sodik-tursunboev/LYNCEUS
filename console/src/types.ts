export type VerdictState = "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN" | "ERROR";
export type ActionState =
  | "PENDING" | "APPROVED" | "APPLIED" | "DISMISSED" | "FAILED" | "RESTORE_REQUESTED" | "RESTORED";

export interface EventRow {
  id: string;
  kind: string;
  host: string | null;
  source: string;
  state: VerdictState;
  risk_score: number | null;
  created_at: string;
  recommended: string;
  applied: string;
  explanation: string;
  rules: string[];
  action_id: string | null;
  action_state: ActionState | null;
}

export interface Signal { rule_id: string; category: string; weight: number; description: string; attack: string | null }
export interface EvidenceRow { kind: string; summary: string; sha256: string | null }
export interface ProviderRow { provider: string; status: string; state: string | null; queried_at: string; provenance: string }
export interface EventDetail extends EventRow { signals: Signal[]; evidence: EvidenceRow[]; providers: ProviderRow[] }

export interface ActionRow {
  id: string;
  verdict_id: string;
  kind: string;
  state: ActionState;
  sha256: string;
  decided_by: string | null;
  reason: string | null;
  created_at: string;
  decided_at: string | null;
  finished_at: string | null;
  verdict_state: VerdictState;
  risk_score: number | null;
}

export interface AllowRow { sha256: string; created_by: string; created_at: string; expires_at: string | null }
export interface AuditRow {
  id: string; at: string; actor: string; action: string; target_type: string; target_id: string | null;
  detail: Record<string, unknown> | null;
}
export interface MailboxStatus { state: string; last_poll?: string | null; analysed?: number; flagged?: unknown[] }