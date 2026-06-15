use serde::{Deserialize, Serialize};

/// An event that mutates the accumulated risk score for a client identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskEvent {
    // ── score-increasing events ──────────────────────────────────────────
    RuleMatch { rule_id: String, delta: i32 },
    FailedChallenge,
    BehaviouralAnomaly(AnomalyKind),
    SuspiciousAsn,
    DeviceFingerprintConflict,
    /// Client hit a canary/honeypot endpoint — immediately max score.
    CanaryHit,

    // ── score-decreasing events ──────────────────────────────────────────
    SuccessfulChallenge,
    /// Sustained normal behaviour decays the score over time.
    NormalBehaviourDecay,
}

/// Specific behavioural anomaly kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    UniformRequestTiming,
    ZeroDepthSession,
    MissingRefererOnSensitiveRoute,
    InterRequestIntervalTooFast,
    TransactionSequenceViolation,
}

/// Accumulated risk score for a `{IP + device_fp + session}` identity.
/// Does not reset between requests.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct RiskScore(pub u32);

impl RiskScore {
    pub const MAX: RiskScore = RiskScore(100);
    pub const ZERO: RiskScore = RiskScore(0);

    pub fn value(self) -> u32 {
        self.0
    }

    pub fn is_max(self) -> bool {
        self.0 >= Self::MAX.0
    }
}
