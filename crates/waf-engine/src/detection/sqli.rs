use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects classic, blind, time-based, and UNION-based SQL injection
/// in URL params, headers, and JSON request body.
pub struct SqliDetector;

impl Detector for SqliDetector {
    fn name(&self) -> &'static str {
        "sqli"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("scan URL params, headers, body for SQLi patterns using regex signatures")
    }
}
