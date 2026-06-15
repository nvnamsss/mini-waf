use waf_types::risk::RiskEvent;

use crate::context::RequestContext;

/// Track cross-route transaction sequences per user to detect fraud patterns:
/// - Login → OTP → Deposit within N seconds
/// - Withdrawal velocity after deposit
/// - Rapid limit-change then withdrawal
pub fn check_sequence(_ctx: &RequestContext) -> Option<RiskEvent> {
    todo!("look up per-user route history from state; detect forbidden sequence patterns")
}

/// Record this request's route in the per-user sequence log.
pub fn record_step(_ctx: &RequestContext) {
    todo!("append (user_id, route, timestamp_ms) to per-user sequence store")
}
