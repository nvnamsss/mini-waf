use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use waf_types::{
    decision::{ChallengeKind, Decision},
    risk::{RiskEvent, RiskScore},
};

use crate::config::schema::RiskConfig;

/// Persistent risk scores keyed by `{ip}:{device_fp}:{session_id}`.
#[derive(Clone)]
#[allow(dead_code)]
pub struct RiskStore(Arc<RwLock<HashMap<String, RiskScore>>>);

impl RiskStore {
    pub fn new() -> Self {
        RiskStore(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Accumulate a risk event for the given identity key.
    pub fn accumulate(&self, _key: &str, _event: &RiskEvent) {
        todo!("apply delta from event to stored score; clamp to [0, MAX]")
    }

    /// Return the current score for a key (default ZERO for unknown identities).
    pub fn get(&self, _key: &str) -> RiskScore {
        todo!("look up score or return RiskScore::ZERO")
    }
}

/// Convert the current score to an enforcement decision based on configured thresholds.
pub fn threshold_decision(score: RiskScore, config: &RiskConfig) -> Decision {
    let v = score.value();
    if v < config.allow_threshold {
        Decision::Allow
    } else if v < config.challenge_threshold {
        Decision::Challenge(ChallengeKind::JsChallenge)
    } else {
        Decision::Block {
            reason: format!("risk score {} exceeds block threshold", v),
        }
    }
}
