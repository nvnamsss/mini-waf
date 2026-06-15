//! Optimized Rule Engine with pre-compiled regex caching

pub mod types;
pub mod loader;
pub mod condition;

pub use condition::RequestContext;
pub use types::{Rule, RuleSet};
use std::sync::Arc;

#[derive(Clone)]
pub struct RuleEvaluator {
    ruleset: RuleSet,
}

#[derive(Clone)]
pub struct MatchResult {
    pub rule_id: String,
    pub description: String,
}

impl RuleEvaluator {
    pub fn new(ruleset: RuleSet) -> Self {
        Self { ruleset }
    }

    /// Evaluate rules against a request context, returning the first matching rule
    pub fn evaluate(
        &self,
        ctx: &RequestContext<'_>,
        _skip_rules: &[String],
    ) -> Option<MatchResult> {
        for rule in &self.ruleset.rules {
            // Skip disabled rules
            if !rule.enabled {
                continue;
            }

            // Evaluate condition with pre-compiled regex cache
            if condition::ConditionEvaluator::eval(
                &rule.condition,
                ctx,
                &self.ruleset.compiled_regexes,
            ) {
                return Some(MatchResult {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                });
            }
        }

        None
    }

    /// Get reference to ruleset for debugging
    pub fn ruleset(&self) -> &RuleSet {
        &self.ruleset
    }
}
