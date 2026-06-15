//! `CrsPlugin` — registers `crs_score()` and `crs_match(tag)` GRL built-ins.

use std::sync::Arc;
use crate::plugin::Plugin;
use crate::rules::crs::evaluator::CrsRuleset;
use crate::rules::grl::ast::Value;
use crate::rules::grl::registry::FunctionRegistry;

/// WAF plugin that wires `CrsRuleset` into the GRL rule engine.
///
/// # GRL functions registered
///
/// | Function | Returns |
/// |---|---|
/// | `crs_score()` | CRS inbound anomaly score for this request (`i64`) |
/// | `crs_match(tag)` | `true` if any rule tagged with `tag` fired (`bool`) |
///
/// # Example GRL rule
///
/// ```grl
/// rule "CrsBlock" salience 1000 {
///     when  crs_score() >= 5
///     then
///         Request.RiskScore = Request.RiskScore + 90;
///         block("crs");
/// }
/// ```
pub struct CrsPlugin {
    ruleset: Arc<CrsRuleset>,
}

impl CrsPlugin {
    pub fn new(ruleset: Arc<CrsRuleset>) -> Self {
        Self { ruleset }
    }
}

impl Plugin for CrsPlugin {
    fn name(&self) -> &'static str { "crs" }

    fn register(&self, registry: &mut FunctionRegistry) {
        let rs = Arc::clone(&self.ruleset);
        registry.register("crs_score", move |ctx, _args| {
            Value::Int(rs.evaluate(ctx).inbound_score)
        });

        let rs2 = Arc::clone(&self.ruleset);
        registry.register("crs_match", move |ctx, args| {
            let tag = args.first().map(|v| v.as_str()).unwrap_or_default();
            Value::Bool(rs2.evaluate(ctx).matched_tags.contains(tag.as_str()))
        });
    }
}
