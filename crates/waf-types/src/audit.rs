use serde::{Deserialize, Serialize};

use crate::{decision::Decision, tier::Tier};

/// One entry written to the append-only SIEM audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique request identifier (UUIDv4).
    pub request_id: String,
    /// Unix timestamp in milliseconds.
    pub ts_ms: i64,
    pub ip: String,
    pub device_fp: Option<String>,
    pub session_id: Option<String>,
    pub method: String,
    pub path: String,
    pub risk_score: u32,
    /// ID of the rule that triggered the action, if any.
    pub rule_id: Option<String>,
    pub action: Decision,
    pub tier: Tier,
}
