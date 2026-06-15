use waf_types::risk::RiskEvent;

use crate::context::RequestContext;

/// Inspect the request context for behavioural anomalies and return any
/// detected risk events.
pub fn detect(_ctx: &RequestContext) -> Vec<RiskEvent> {
    todo!(
        "check: uniform inter-request timing, zero-depth session hitting CRITICAL, \
         missing Referer on sensitive route, inter-request interval < 50ms"
    )
}

/// Returns `true` if the session has a zero-depth profile — no prior request
/// to homepage/public routes before hitting a CRITICAL endpoint.
pub fn is_zero_depth_session(_ctx: &RequestContext) -> bool {
    todo!("check session history in state store for prior non-critical requests")
}

/// Returns `true` if consecutive requests from this identity are suspiciously
/// uniform (bot-like timing).
pub fn has_uniform_timing(_identity_key: &str, _now_ms: i64) -> bool {
    todo!("compute variance of inter-request intervals from stored history")
}
