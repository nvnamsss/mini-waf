use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects request body abuse: malformed JSON, oversized payloads,
/// deeply nested objects, and Content-Type mismatches.
pub struct BodyAbuseDetector;

impl Detector for BodyAbuseDetector {
    fn name(&self) -> &'static str {
        "body_abuse"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("validate JSON structure, check payload size vs limit, verify content-type matches body format")
    }
}
