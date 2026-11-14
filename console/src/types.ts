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
export type FeedbackLabel = "false_alarm" | "missed" | "correct";
export interface EventDetail extends EventRow { signals: Signal[]; evidence: EvidenceRow[]; providers: ProviderRow[]; feedback?: FeedbackLabel | null }
/** Per rule, what you said about the verdicts it fired on (H1 B3). */
export interface RuleFeedback { rule_id: string; false_alarm: number; correct: number; missed: number }

export interface ActionRow {
  id: string;
  verdict_id: string;
  kind: string; // FILE_QUARANTINE or MAIL_QUARANTINE
  provider?: string | null; // gmail or outlook, for email actions
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
// ---- the analysis workbench: the shapes the analyze endpoints answer with ---------------------------------

export type Confidence = "LOW" | "MEDIUM" | "HIGH";
export type ResponseAction = "NONE" | "WARN" | "BLOCK" | "QUARANTINE";

export interface FullSignal {
  rule_id: string;
  category: string;
  weight: number; // 0..1
  description: string;
  evidence_ids: string[];
  attack: string | null; // an ATT&CK technique id such as T1566.002
}
export interface ProviderResultRow {
  provider: string;
  status: "OK" | "TIMEOUT" | "ERROR" | "RATE_LIMITED" | "UNAVAILABLE";
  state: VerdictState | null;
  queried_at: string;
  latency_ms: number;
  provenance: string;
  detail: string | null;
}
export interface Verdict {
  id: string;
  state: VerdictState;
  risk_score: number | null;
  confidence: Confidence;
  signals: FullSignal[];
  provider_results: ProviderResultRow[];
  recommended_response: ResponseAction;
  applied_response: ResponseAction;
  explanation: string;
  engine_version: string;
  ruleset_version: string;
  created_at: string;
}
export interface AnalysisEvidence { id: string; kind: string; summary: string; sha256: string | null }

export interface Anatomy {
  scheme: string;
  username: string | null;
  has_password: boolean;
  host: string | null;
  host_unicode: string | null;
  host_kind: "DOMAIN" | "IPV4" | "IPV6" | "OPAQUE" | string;
  subdomain: string;
  registered_domain: string | null;
  public_suffix: string | null;
  private_suffix: boolean;
  port: number | null;
  path: string;
  query: string;
  fragment: string;
}

export interface LinkRow {
  part: string;
  kind: string;
  flags: string[];
  normalized_url: string | null;
  host: string | null;
  state: VerdictState | null;
  risk_score: number | null;
  rules: string[];
}
export interface FileRow { part: string; kind: string; status: string; facts: string[] }
export interface MessageSummary {
  size: number;
  parts: number;
  attachments: number;
  links: number;
  links_analyzed: number;
  relative_links_skipped: number;
  limits_hit: string[];
  defects: string[];
}

interface Common { verdict: Verdict; evidence: AnalysisEvidence[]; reason: string | null; persisted: boolean }
export interface UrlAnalysis extends Common {
  type: "url";
  normalized_url: string | null;
  flags: string[];
  intel_skipped: Array<{ provider: string; reason: string }>;
  anatomy: Anatomy | null;
  page?: PageSummary; // present after "Open in sandbox" (D1)
}
/** What the sandboxed browser saw (D1). Shown once, never stored. */
export interface PageSummary {
  status: "ok" | "partial" | "dead" | "error";
  error: string | null;
  http_status: number | null;
  final_url: string;
  chain_hosts: string[];
  title: string;
  forms: number;
  password_fields: number;
  markers: string[];
  downloads: string[];
  hosts_contacted: number;
  tls_valid_from: number | null;
  screenshot_jpeg: string | null;
  elapsed_ms: number;
}
export interface EmailAnalysis extends Common {
  type: "email";
  summary: MessageSummary | null;
  links: LinkRow[];
  files: FileRow[];
}
/** A hash of the file (or of an entry inside an archive) that is on a known-bad list on this machine. */
export interface HashMatch { algorithm: string; source: string; where: string }
export interface FileAnalysis extends Common {
  type: "file";
  inspected: boolean;
  files: FileRow[];
  links: LinkRow[];
  action_id: string | null;
  allow_listed: boolean;
  hashes?: Record<string, string>;
  hash_matches?: HashMatch[];
  hash_lists?: number;
}
export type Analysis = UrlAnalysis | EmailAnalysis | FileAnalysis;

export interface IntelHealth {
  providers: Array<{ provider: string; sends: string; breaker: string; usable: boolean }>;
  feeds: Array<{ feed: string; downloaded: boolean; entries: number; age_hours: number | null; stale: boolean }>;
}