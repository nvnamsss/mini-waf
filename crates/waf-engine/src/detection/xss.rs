use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects reflected and stored XSS payloads in query strings,
/// form data, and JSON bodies.
pub struct XssDetector;

impl Detector for XssDetector {
    fn name(&self) -> &'static str {
        "xss"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("scan request fields for script injection patterns")
    }
}
