use waf_types::decision::Decision;
use waf_types::risk::RiskScore;

use crate::rules::rete::engine::outcome_to_decision;
use crate::{context::RequestContext, state::store::AppState};

/// Run all inbound checks against the request in priority order.
/// The current implementation delegates to the compiled RETE rule engine;
/// rate-limit / risk-threshold / behavioural checks plug in here later.
pub async fn run_inbound(ctx: &mut RequestContext, state: &AppState) -> Decision {
    let engine  = state.rules.engine();
    let outcome = engine.fire(ctx);

    if let Some(rule_id) = outcome.matched_rules.first() {
        ctx.matched_rule_id = Some(rule_id.clone());
    }

    // Apply the accumulated risk delta from all fired rules.
    if outcome.risk_delta != 0 {
        let new_score = (ctx.risk_score.value() as i64 + outcome.risk_delta)
            .clamp(0, RiskScore::MAX.value() as i64) as u32;
        ctx.risk_score = RiskScore(new_score);
    }

    outcome_to_decision(&outcome)
}

/// Run outbound response filtering before bytes are returned to the client:
///   1. Stack-trace / internal-IP leak detection
///   2. Sensitive field redaction
///   3. PII header removal (X-Debug, X-Internal-*)
///
/// Returns the (possibly rewritten) response body, or a `Decision::Block`
/// to replace the response entirely.
pub async fn run_outbound(
    _ctx: &RequestContext,
    _response_status: u16,
    _response_headers: &mut std::collections::HashMap<String, String>,
    response_body: Vec<u8>,
    _state: &AppState,
) -> Result<Vec<u8>, Decision> {
    // TODO: orchestrate outbound pipeline
    Ok(response_body)
}
