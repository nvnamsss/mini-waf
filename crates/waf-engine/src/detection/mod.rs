pub mod body_abuse;
pub mod brute_force;
pub mod header_injection;
pub mod path_traversal;
pub mod recon;
pub mod sqli;
pub mod ssrf;
pub mod xss;

use waf_types::risk::RiskEvent;

use crate::context::RequestContext;

/// Common interface for every attack detector.
pub trait Detector: Send + Sync {
    /// Unique name used in logs and rule IDs.
    fn name(&self) -> &'static str;

    /// Inspect `ctx` and return a `RiskEvent` if an attack is detected.
    fn detect(&self, ctx: &RequestContext) -> Option<RiskEvent>;
}
