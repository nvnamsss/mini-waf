use serde::{Deserialize, Serialize};

/// Final enforcement decision taken by the WAF for a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block { reason: String },
    Challenge(ChallengeKind),
    RateLimit { retry_after_secs: u64 },
}

/// Type of challenge to issue to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    /// Browser-side JavaScript challenge.
    JsChallenge,
    /// CPU-bound proof-of-work challenge.
    ProofOfWork,
}
