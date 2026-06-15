use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects Server-Side Request Forgery attempts targeting internal IP ranges
/// (10.x, 172.16.x, 192.168.x, 169.254.x) and cloud metadata endpoints.
pub struct SsrfDetector;

impl Detector for SsrfDetector {
    fn name(&self) -> &'static str {
        "ssrf"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("parse URLs in request body/params; check against internal IP ranges and metadata endpoints")
    }
}
