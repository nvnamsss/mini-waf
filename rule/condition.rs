//! Condition evaluator — walks a ConditionNode tree against a RequestContext.
//!
//! Regexes are expected to be pre-compiled and cached (via `once_cell` or
//! the loader's compilation step). The evaluator itself does zero allocation
//! on the hot path for simple match types.

use super::{types::*, RequestContext};
use regex::Regex;

pub struct ConditionEvaluator<'a> {
    condition: &'a ConditionNode,
}

impl<'a> ConditionEvaluator<'a> {
    pub fn new(condition: &'a ConditionNode) -> Self {
        ConditionEvaluator { condition }
    }

    pub fn evaluate(&self, ctx: &RequestContext<'_>) -> bool {
        eval_node(self.condition, ctx)
    }
}

fn eval_node(node: &ConditionNode, ctx: &RequestContext<'_>) -> bool {
    match node {
        ConditionNode::And(children) => children.iter().all(|c| eval_node(c, ctx)),
        ConditionNode::Or(children)  => children.iter().any(|c| eval_node(c, ctx)),
        ConditionNode::Leaf(leaf)    => eval_leaf(leaf, ctx),
    }
}

fn eval_leaf(leaf: &ConditionLeaf, ctx: &RequestContext<'_>) -> bool {
    let result = match leaf.field {
        Field::Ip          => match_value(ctx.ip, leaf),
        Field::Path        => match_value(ctx.path, leaf),
        Field::Method      => match_value(ctx.method, leaf),
        Field::SessionId   => match_value(ctx.session_id, leaf),
        Field::DeviceFp    => match_value(ctx.device_fp, leaf),
        Field::ContentType => {
            let ct = ctx.content_type.unwrap_or("");
            match_value(ct, leaf)
        }
        Field::Header => {
            let name = leaf.header_name.as_deref().unwrap_or("");
            let value = ctx
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            match leaf.match_type {
                MatchType::Presence => !value.is_empty(),
                MatchType::Absence  => value.is_empty(),
                _                   => match_value(value, leaf),
            }
        }
        Field::Cookie => {
            let name = leaf.cookie_name.as_deref().unwrap_or("");
            let value = ctx.cookies.get(name).map(|s| s.as_str()).unwrap_or("");
            match leaf.match_type {
                MatchType::Presence => !value.is_empty(),
                MatchType::Absence  => value.is_empty(),
                _                   => match_value(value, leaf),
            }
        }
        Field::Payload => {
            let body_str = std::str::from_utf8(ctx.payload).unwrap_or("");
            match leaf.match_type {
                MatchType::Presence => !ctx.payload.is_empty(),
                MatchType::Absence  => ctx.payload.is_empty(),
                _                   => match_value(body_str, leaf),
            }
        }
    };

    if leaf.negate { !result } else { result }
}

fn match_value(subject: &str, leaf: &ConditionLeaf) -> bool {
    match leaf.match_type {
        MatchType::Exact => {
            if leaf.case_sensitive {
                subject == leaf.value
            } else {
                subject.eq_ignore_ascii_case(&leaf.value)
            }
        }
        MatchType::Wildcard => {
            globset::GlobBuilder::new(&leaf.value)
                .case_insensitive(!leaf.case_sensitive)
                .build()
                .ok()
                .map(|g| g.compile_matcher().is_match(subject))
                .unwrap_or(false)
        }
        MatchType::Regex => {
            let pattern = if !leaf.case_sensitive && !leaf.value.starts_with("(?i)") {
                format!("(?i){}", leaf.value)
            } else {
                leaf.value.clone()
            };
            Regex::new(&pattern)
                .map(|re| re.is_match(subject))
                .unwrap_or(false)
        }
        MatchType::Cidr => {
            // CIDR matching for IP field
            super::cidr_contains(&leaf.value, subject)
        }
        MatchType::Presence => !subject.is_empty(),
        MatchType::Absence  => subject.is_empty(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use std::collections::HashMap;
    use crate::engine::tier::TierName;

    fn ctx<'a>(
        ip: &'a str,
        path: &'a str,
        method: &'a str,
        payload: &'a [u8],
        headers: &'a HeaderMap,
        cookies: &'a HashMap<String, String>,
    ) -> RequestContext<'a> {
        RequestContext {
            ip,
            path,
            method,
            headers,
            payload,
            cookies,
            tier: TierName::CatchAll,
            session_id: "sess",
            device_fp:  "fp",
            content_type: None,
        }
    }

    fn empty_headers() -> HeaderMap { HeaderMap::new() }
    fn empty_cookies() -> HashMap<String, String> { HashMap::new() }

    #[test]
    fn exact_match_path() {
        let leaf = ConditionNode::Leaf(ConditionLeaf {
            field: Field::Path,
            match_type: MatchType::Exact,
            value: "/login".to_string(),
            header_name: None,
            cookie_name: None,
            case_sensitive: false,
            negate: false,
        });
        let h = empty_headers();
        let c = empty_cookies();
        let ctx = ctx("1.2.3.4", "/login", "GET", b"", &h, &c);
        assert!(eval_node(&leaf, &ctx));
    }

    #[test]
    fn regex_match_payload() {
        let leaf = ConditionNode::Leaf(ConditionLeaf {
            field: Field::Payload,
            match_type: MatchType::Regex,
            value: r"(?i)union\s+select".to_string(),
            header_name: None,
            cookie_name: None,
            case_sensitive: false,
            negate: false,
        });
        let h = empty_headers();
        let c = empty_cookies();
        let ctx = ctx("1.2.3.4", "/", "POST", b"' UNION SELECT 1--", &h, &c);
        assert!(eval_node(&leaf, &ctx));
    }

    #[test]
    fn negate_works() {
        let leaf = ConditionNode::Leaf(ConditionLeaf {
            field: Field::Method,
            match_type: MatchType::Exact,
            value: "GET".to_string(),
            header_name: None,
            cookie_name: None,
            case_sensitive: true,
            negate: true, // NOT GET
        });
        let h = empty_headers();
        let c = empty_cookies();
        let ctx = ctx("1.2.3.4", "/", "POST", b"", &h, &c);
        assert!(eval_node(&leaf, &ctx)); // POST is NOT GET → true
    }

    #[test]
    fn and_node_requires_all() {
        let h = empty_headers();
        let c = empty_cookies();
        let node = ConditionNode::And(vec![
            ConditionNode::Leaf(ConditionLeaf {
                field: Field::Method, match_type: MatchType::Exact,
                value: "POST".to_string(),
                header_name: None, cookie_name: None,
                case_sensitive: true, negate: false,
            }),
            ConditionNode::Leaf(ConditionLeaf {
                field: Field::Path, match_type: MatchType::Exact,
                value: "/login".to_string(),
                header_name: None, cookie_name: None,
                case_sensitive: false, negate: false,
            }),
        ]);
        // Both match
        let ctx1 = ctx("1.2.3.4", "/login", "POST", b"", &h, &c);
        assert!(eval_node(&node, &ctx1));
        // Only one matches
        let ctx2 = ctx("1.2.3.4", "/other", "POST", b"", &h, &c);
        assert!(!eval_node(&node, &ctx2));
    }

    #[test]
    fn or_node_requires_any() {
        let h = empty_headers();
        let c = empty_cookies();
        let node = ConditionNode::Or(vec![
            ConditionNode::Leaf(ConditionLeaf {
                field: Field::Path, match_type: MatchType::Exact,
                value: "/admin".to_string(),
                header_name: None, cookie_name: None,
                case_sensitive: false, negate: false,
            }),
            ConditionNode::Leaf(ConditionLeaf {
                field: Field::Path, match_type: MatchType::Exact,
                value: "/login".to_string(),
                header_name: None, cookie_name: None,
                case_sensitive: false, negate: false,
            }),
        ]);
        let ctx1 = ctx("1.2.3.4", "/login", "GET", b"", &h, &c);
        assert!(eval_node(&node, &ctx1));
        let ctx2 = ctx("1.2.3.4", "/public", "GET", b"", &h, &c);
        assert!(!eval_node(&node, &ctx2));
    }
}
