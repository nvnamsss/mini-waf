use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects `../` sequences and their URL-encoded variants (`%2e%2e`)
/// in URL path and query parameters.
pub struct PathTraversalDetector;

impl Detector for PathTraversalDetector {
    fn name(&self) -> &'static str {
        "path_traversal"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("check decoded path and query for directory traversal sequences")
    }
}
