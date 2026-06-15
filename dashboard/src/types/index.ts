/** Types that mirror the Rust structs in waf-types. Keep in sync. */

export type Tier = "critical" | "high" | "medium" | "catch_all";

export type Decision =
  | { type: "allow" }
  | { type: "block"; reason: string }
  | { type: "challenge"; challenge_type: "js_challenge" | "proof_of_work" }
  | { type: "rate_limit"; retry_after_secs: number };

export interface AuditEntry {
  request_id: string;
  ts_ms: number;
  ip: string;
  device_fp: string | null;
  session_id: string | null;
  method: string;
  path: string;
  risk_score: number;
  rule_id: string | null;
  action: Decision;
  tier: Tier;
}

export interface Rule {
  id: string;
  priority: number;
  scope: unknown; // matches RuleScope enum
  condition: unknown; // matches Condition enum
  action: string;
  risk_score_delta: number;
}

export interface MetricsSnapshot {
  total_requests: number;
  blocked: number;
  challenged: number;
  rate_limited: number;
  by_attack_type: Record<string, number>;
  top_ips: Array<{ ip: string; requests: number }>;
  route_heatmap: Record<string, number>;
}

export interface ConfigPatch {
  allow_threshold?: number;
  challenge_threshold?: number;
  default_rps_per_ip?: number;
  default_rps_per_session?: number;
}
