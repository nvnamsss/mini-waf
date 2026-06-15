use waf_types::risk::RiskEvent;

use crate::{context::RequestContext, detection::Detector};

/// Detects error-based reconnaissance: rapid 4xx/5xx response patterns,
/// endpoint enumeration, and OPTIONS method abuse.
pub struct ReconDetector;

impl Detector for ReconDetector {
    fn name(&self) -> &'static str {
        "recon"
    }

    fn detect(&self, _ctx: &RequestContext) -> Option<RiskEvent> {
        todo!("track per-IP 4xx/5xx rate; flag OPTIONS requests; detect sequential endpoint scanning")
    }
}
