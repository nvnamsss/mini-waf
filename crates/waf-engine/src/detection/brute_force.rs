use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects brute-force login attacks and credential stuffing patterns:
/// per-user failed authentication counters and password-spraying
/// (many different users from the same source IP).
pub struct BruteForceDetector;

impl Detector for BruteForceDetector {
    fn name(&self) -> &'static str {
        "brute_force"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("check per-user failed login count; detect password spraying via per-IP unique-user counter")
    }
}
