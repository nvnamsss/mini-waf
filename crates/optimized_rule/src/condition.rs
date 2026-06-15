//! Condition evaluation using pre-compiled regex cache

use crate::types::*;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

pub struct ConditionEvaluator;

pub struct RequestContext<'a> {
    pub ip: &'a str,
    pub path: &'a str,
    pub method: &'a str,
    pub headers: &'a HashMap<String, String>,
    pub payload: &'a [u8],
    pub cookies: &'a HashMap<String, String>,
    pub tier: waf_types::tier::Tier,
    pub session_id: &'a str,
    pub device_fp: &'a str,
    pub content_type: Option<&'a str>,
}

impl ConditionEvaluator {
    pub fn eval(
        node: &ConditionNode,
        ctx: &RequestContext<'_>,
        compiled_regexes: &Arc<HashMap<String, Regex>>,
    ) -> bool {
        match node {
            ConditionNode::And(nodes) => nodes.iter().all(|n| Self::eval(n, ctx, compiled_regexes)),
            ConditionNode::Or(nodes) => nodes.iter().any(|n| Self::eval(n, ctx, compiled_regexes)),
            ConditionNode::Leaf(leaf) => Self::eval_leaf(leaf, ctx, compiled_regexes),
        }
    }

    fn eval_leaf(
        leaf: &ConditionLeaf,
        ctx: &RequestContext<'_>,
        compiled_regexes: &Arc<HashMap<String, Regex>>,
    ) -> bool {
        let matches = match leaf.field {
            Field::Ip => Self::match_value(&leaf.value, ctx.ip, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref()),
            Field::Path => Self::match_value(&leaf.value, ctx.path, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref()),
            Field::Method => Self::match_value(&leaf.value, ctx.method, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref()),
            Field::Header => {
                if let Some(ref header_name) = leaf.header_name {
                    if let Some(header_value) = ctx.headers.get(header_name) {
                        Self::match_value(&leaf.value, header_value, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref())
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Field::Payload => {
                let payload_str = String::from_utf8_lossy(ctx.payload);
                Self::match_value(&leaf.value, &payload_str, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref())
            }
            Field::Cookie => {
                if let Some(ref cookie_name) = leaf.cookie_name {
                    if let Some(cookie_value) = ctx.cookies.get(cookie_name) {
                        Self::match_value(&leaf.value, cookie_value, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref())
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Field::ContentType => {
                if let Some(ct) = ctx.content_type {
                    Self::match_value(&leaf.value, ct, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref())
                } else {
                    false
                }
            }
            Field::SessionId => Self::match_value(&leaf.value, ctx.session_id, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref()),
            Field::DeviceFp => Self::match_value(&leaf.value, ctx.device_fp, leaf.match_type, compiled_regexes, leaf.compiled_regex_key.as_ref()),
        };

        if leaf.negate { !matches } else { matches }
    }

    fn match_value(
        pattern: &str,
        value: &str,
        match_type: MatchType,
        compiled_regexes: &Arc<HashMap<String, Regex>>,
        regex_key: Option<&String>,
    ) -> bool {
        match match_type {
            MatchType::Exact => value == pattern,
            MatchType::Wildcard => Self::glob_match(pattern, value),
            MatchType::Regex => {
                if let Some(key) = regex_key {
                    if let Some(re) = compiled_regexes.get(key) {
                        re.is_match(value)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            MatchType::Cidr => Self::cidr_match(pattern, value),
            MatchType::Presence => !value.is_empty(),
            MatchType::Absence => value.is_empty(),
        }
    }

    fn glob_match(pattern: &str, text: &str) -> bool {
        // Simple glob matching: * matches any sequence of characters
        let parts: Vec<&str> = pattern.split('*').collect();
        
        if parts.is_empty() {
            return text.is_empty();
        }

        if !text.starts_with(parts[0]) {
            return false;
        }

        let mut remaining = &text[parts[0].len()..];

        for part in &parts[1..] {
            if let Some(pos) = remaining.find(part) {
                remaining = &remaining[pos + part.len()..];
            } else {
                return false;
            }
        }

        true
    }

    fn cidr_match(cidr: &str, ip: &str) -> bool {
        // Simple CIDR matching (IPv4 and IPv6)
        if let Ok(ip_addr) = IpAddr::from_str(ip) {
            if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
                return net.contains(&ip_addr);
            }
        }
        false
    }
}
