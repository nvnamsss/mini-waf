use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects Host header injection, CRLF response-splitting, and
/// X-Forwarded-For spoofing.
pub struct HeaderInjectionDetector;

impl Detector for HeaderInjectionDetector {
    fn name(&self) -> &'static str {
        "header_injection"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("scan Host header for injection; check for CRLF (\\r\\n) in header values; validate XFF format")
    }
}
