//! Rule engine — loads YAML rule files, compiles conditions, evaluates in priority order.
//!
//! Rules are sorted by `priority` ascending (lower number = higher precedence).
//! First matching rule wins (unless action is `log`, which continues evaluation).
//! All condition matching is done without per-request allocation where possible.

pub mod condition;
pub mod loader;
pub mod types;

pub use types::{Action, RuleSet};

use condition::ConditionEvaluator;
use std::sync::Arc;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("Rule file parse error in '{file}': {source}")]
    ParseError {
        file:   String,
        source: serde_yaml::Error,
    },
    #[error("IO error reading rule file '{file}': {source}")]
    IoError {
        file:   String,
        source: std::io::Error,
    },
    #[error("Rule validation error in rule '{id}': {reason}")]
    ValidationError { id: String, reason: String },
    #[error("Duplicate rule ID '{0}'")]
    DuplicateId(String),
    #[error("Regex compile error in rule '{id}': {source}")]
    RegexError {
        id:     String,
        source: regex::Error,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Match result
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id:          String,
    pub description:      String,
    pub action:           Action,
    pub risk_score_delta: i8,
    pub source:           String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Request context for rule evaluation
// ─────────────────────────────────────────────────────────────────────────────

pub struct RequestContext<'a> {
    pub ip:           &'a str,
    pub path:         &'a str,
    pub method:       &'a str,
    pub headers:      &'a std::collections::HashMap<String, String>,
    pub payload:      &'a [u8],
    pub cookies:      &'a std::collections::HashMap<String, String>,
    pub tier:         waf_types::tier::Tier,
    pub session_id:   &'a str,
    pub device_fp:    &'a str,
    pub content_type: Option<&'a str>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule evaluator
// ─────────────────────────────────────────────────────────────────────────────

pub struct RuleEvaluator {
    ruleset: Arc<RuleSet>,
}

impl RuleEvaluator {
    pub fn new(ruleset: Arc<RuleSet>) -> Self {
        RuleEvaluator { ruleset }
    }

    /// Evaluate all rules against the request context.
    /// Returns the first non-log match, or `None` if no rule matched.
    pub fn evaluate<'a>(&self, ctx: &RequestContext<'a>, skip_rules: &[String]) -> Option<RuleMatch> {
        for rule in self.ruleset.rules_for_context(ctx) {
            if !rule.enabled {
                continue;
            }

            if skip_rules.contains(&rule.id) {
                continue;
            }

            if let Some(tier) = &rule.tier {
                let tier_lower = tier.to_lowercase();
                if tier_lower != "global" && tier_lower != format!("{:?}", ctx.tier).to_lowercase() {
                    continue;
                }
            }

            let evaluator = ConditionEvaluator::new(&rule.condition);
            if evaluator.evaluate(ctx) {
                let matched = RuleMatch {
                    rule_id:          rule.id.clone(),
                    description:      rule.description.clone(),
                    action:           rule.action.clone(),
                    risk_score_delta: rule.risk_score_delta,
                    source:           rule.source.clone(),
                };

                // `log` action: record but keep evaluating
                if rule.action == Action::Log {
                    tracing::debug!(rule_id = %rule.id, "Rule matched (log action — continuing)");
                    continue;
                }

                return Some(matched);
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple wildcard matching: * matches any sequence, ? matches one char
    let mut p_chars = pattern.chars().peekable();
    let mut t_chars = text.chars().peekable();

    let mut p_vec: Vec<char> = pattern.chars().collect();
    let mut t_vec: Vec<char> = text.chars().collect();
    let mut pi = 0;
    let mut ti = 0;

    while pi < p_vec.len() && ti < t_vec.len() {
        match p_vec[pi] {
            '*' => {
                if pi == p_vec.len() - 1 {
                    return true;
                }
                while ti < t_vec.len() {
                    if glob_match(&pattern[(pi + 1)..], &text[ti..]) {
                        return true;
                    }
                    ti += 1;
                }
                return false;
            }
            '?' => {
                pi += 1;
                ti += 1;
            }
            c if c == t_vec.get(ti).copied().unwrap_or('\0') => {
                pi += 1;
                ti += 1;
            }
            _ => return false,
        }
    }

    pi == p_vec.len() && ti == t_vec.len()
}

pub(crate) fn cidr_contains(cidr: &str, ip: &str) -> bool {
    // Parse CIDR and check if IP is within range
    let ip_addr: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    if let Some((net_str, prefix_str)) = cidr.split_once('/') {
        let prefix: u8 = prefix_str.parse().unwrap_or(0);
        let net: std::net::IpAddr = match net_str.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };

        match (net, ip_addr) {
            (std::net::IpAddr::V4(net4), std::net::IpAddr::V4(ip4)) => {
                if prefix == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - prefix.min(32));
                (u32::from(net4) & mask) == (u32::from(ip4) & mask)
            }
            (std::net::IpAddr::V6(net6), std::net::IpAddr::V6(ip6)) => {
                if prefix == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - prefix.min(128));
                (u128::from(net6) & mask) == (u128::from(ip6) & mask)
            }
            _ => false,
        }
    } else {
        // Exact IP match
        cidr.parse::<std::net::IpAddr>()
            .map(|a| a == ip_addr)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_rule_evaluator_skips_matched_rules() {
        let rule1 = types::Rule {
            id: "rule-1".to_string(),
            source: "system".to_string(),
            description: "First rule".to_string(),
            enabled: true,
            priority: 10,
            condition: types::ConditionNode::Leaf(types::ConditionLeaf {
                field: types::Field::Path,
                match_type: types::MatchType::Exact,
                value: "/api/data".to_string(),
                header_name: None,
                cookie_name: None,
                case_sensitive: false,
                negate: false,
            }),
            action: types::Action::RateLimit,
            risk_score_delta: 5,
            response: None,
            rate_limit: None,
            challenge: None,
            tier: None,
        };

        let rule2 = types::Rule {
            id: "rule-2".to_string(),
            source: "system".to_string(),
            description: "Second rule".to_string(),
            enabled: true,
            priority: 20,
            condition: types::ConditionNode::Leaf(types::ConditionLeaf {
                field: types::Field::Path,
                match_type: types::MatchType::Exact,
                value: "/api/data".to_string(),
                header_name: None,
                cookie_name: None,
                case_sensitive: false,
                negate: false,
            }),
            action: types::Action::Block,
            risk_score_delta: 10,
            response: None,
            rate_limit: None,
            challenge: None,
            tier: None,
        };

        let ruleset = Arc::new(types::RuleSet {
            rules: vec![rule1, rule2],
        });

        let evaluator = RuleEvaluator::new(ruleset);
        let headers = HashMap::new();
        let cookies = HashMap::new();
        let ctx = RequestContext {
            ip: "127.0.0.1",
            path: "/api/data",
            method: "GET",
            headers: &headers,
            payload: b"",
            cookies: &cookies,
            tier: waf_types::tier::Tier::CatchAll,
            session_id: "session",
            device_fp: "fp",
            content_type: None,
        };

        // When no skip_rules are passed, the first rule matches
        let m1 = evaluator.evaluate(&ctx, &[]);
        assert!(m1.is_some());
        assert_eq!(m1.unwrap().rule_id, "rule-1");

        // When skip_rules contains the first rule, it evaluates and matches the second rule
        let m2 = evaluator.evaluate(&ctx, &["rule-1".to_string()]);
        assert!(m2.is_some());
        assert_eq!(m2.unwrap().rule_id, "rule-2");

        // When both rules are in skip_rules, none matches
        let m3 = evaluator.evaluate(&ctx, &["rule-1".to_string(), "rule-2".to_string()]);
        assert!(m3.is_none());
    }
}
