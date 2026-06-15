//! Condition evaluator — walks a ConditionNode tree against a RequestContext.
//!
//! Regexes are pre-compiled and cached in RuleSet.compiled_regexes.
//! The evaluator uses the cached compiled regex instead of recompiling at runtime.

use super::{types::*, RequestContext};
use std::collections::HashMap;
use std::sync::Arc;
use regex::Regex;

pub struct ConditionEvaluator<'a> {
    condition: &'a ConditionNode,
    compiled_regexes: &'a Arc<HashMap<String, Regex>>,
}

impl<'a> ConditionEvaluator<'a> {
    pub fn new(condition: &'a ConditionNode, compiled_regexes: &'a Arc<HashMap<String, Regex>>) -> Self {
        ConditionEvaluator { condition, compiled_regexes }
    }

    pub fn evaluate(&self, ctx: &RequestContext<'_>) -> bool {
        eval_node(self.condition, ctx, self.compiled_regexes)
    }
}

fn eval_node(node: &ConditionNode, ctx: &RequestContext<'_>, compiled_regexes: &Arc<HashMap<String, Regex>>) -> bool {
    match node {
        ConditionNode::And(children) => children.iter().all(|c| eval_node(c, ctx, compiled_regexes)),
        ConditionNode::Or(children)  => children.iter().any(|c| eval_node(c, ctx, compiled_regexes)),
        ConditionNode::Leaf(leaf)    => eval_leaf(leaf, ctx, compiled_regexes),
    }
}

fn eval_leaf(leaf: &ConditionLeaf, ctx: &RequestContext<'_>, compiled_regexes: &Arc<HashMap<String, Regex>>) -> bool {
    let result = match leaf.field {
        Field::Ip          => match_value(ctx.ip, leaf, compiled_regexes),
        Field::Path        => match_value(ctx.path, leaf, compiled_regexes),
        Field::Method      => match_value(ctx.method, leaf, compiled_regexes),
        Field::SessionId   => match_value(ctx.session_id, leaf, compiled_regexes),
        Field::DeviceFp    => match_value(ctx.device_fp, leaf, compiled_regexes),
        Field::ContentType => {
            let ct = ctx.content_type.unwrap_or("");
            match_value(ct, leaf, compiled_regexes)
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
                _                   => match_value(value, leaf, compiled_regexes),
            }
        }
        Field::Cookie => {
            let name = leaf.cookie_name.as_deref().unwrap_or("");
            let value = ctx.cookies.get(name).map(|s| s.as_str()).unwrap_or("");
            match leaf.match_type {
                MatchType::Presence => !value.is_empty(),
                MatchType::Absence  => value.is_empty(),
                _                   => match_value(value, leaf, compiled_regexes),
            }
        }
        Field::Payload => {
            let body_str = std::str::from_utf8(ctx.payload).unwrap_or("");
            match leaf.match_type {
                MatchType::Presence => !ctx.payload.is_empty(),
                MatchType::Absence  => ctx.payload.is_empty(),
                _                   => match_value(body_str, leaf, compiled_regexes),
            }
        }
    };

    if leaf.negate { !result } else { result }
}

fn match_value(subject: &str, leaf: &ConditionLeaf, compiled_regexes: &Arc<HashMap<String, Regex>>) -> bool {
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
            // Use pre-compiled regex from cache instead of recompiling
            if let Some(cache_key) = &leaf.compiled_regex_key {
                if let Some(re) = compiled_regexes.get(cache_key) {
                    return re.is_match(subject);
                }
            }
            // Fallback (shouldn't happen if loader worked correctly)
            false
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
    fn empty_regexes() -> Arc<HashMap<String, Regex>> { Arc::new(HashMap::new()) }

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
            compiled_regex_key: None,
        });
        let h = empty_headers();
        let c = empty_cookies();
        let ctx = ctx("1.2.3.4", "/login", "GET", b"", &h, &c);
        assert!(eval_node(&leaf, &ctx, &empty_regexes()));
    }

    #[test]
    fn regex_match_payload() {
        // Pre-compile the regex pattern
        let mut regexes = HashMap::new();
        let regex_key = "regex_0".to_string();
        regexes.insert(regex_key.clone(), Regex::new(r"(?i)union\s+select").unwrap());
        let compiled_regexes = Arc::new(regexes);

        let leaf = ConditionNode::Leaf(ConditionLeaf {
            field: Field::Payload,
            match_type: MatchType::Regex,
            value: r"(?i)union\s+select".to_string(),
            header_name: None,
            cookie_name: None,
            case_sensitive: false,
            negate: false,
            compiled_regex_key: Some(regex_key),
        });
        let h = empty_headers();
        let c = empty_cookies();
        let ctx = ctx("1.2.3.4", "/", "POST", b"' UNION SELECT 1--", &h, &c);
        assert!(eval_node(&leaf, &ctx, &compiled_regexes));
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
            compiled_regex_key: None,
        });
        let h = empty_headers();
        let c = empty_cookies();
        let ctx = ctx("1.2.3.4", "/", "POST", b"", &h, &c);
        assert!(eval_node(&leaf, &ctx, &empty_regexes())); // POST is NOT GET → true
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
                compiled_regex_key: None,
            }),
            ConditionNode::Leaf(ConditionLeaf {
                field: Field::Path, match_type: MatchType::Exact,
                value: "/login".to_string(),
                header_name: None, cookie_name: None,
                case_sensitive: false, negate: false,
                compiled_regex_key: None,
            }),
        ]);
        // Both match
        let ctx1 = ctx("1.2.3.4", "/login", "POST", b"", &h, &c);
        assert!(eval_node(&node, &ctx1, &empty_regexes()));
        // Only one matches
        let ctx2 = ctx("1.2.3.4", "/other", "POST", b"", &h, &c);
        assert!(!eval_node(&node, &ctx2, &empty_regexes()));
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
                compiled_regex_key: None,
            }),
            ConditionNode::Leaf(ConditionLeaf {
                field: Field::Path, match_type: MatchType::Exact,
                value: "/login".to_string(),
                header_name: None, cookie_name: None,
                case_sensitive: false, negate: false,
                compiled_regex_key: None,
            }),
        ]);
        let ctx1 = ctx("1.2.3.4", "/login", "GET", b"", &h, &c);
        assert!(eval_node(&node, &ctx1, &empty_regexes()));
        let ctx2 = ctx("1.2.3.4", "/public", "GET", b"", &h, &c);
        assert!(!eval_node(&node, &ctx2, &empty_regexes()));
    }
}
