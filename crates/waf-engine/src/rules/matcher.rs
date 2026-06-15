use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::{context::RequestContext, rules::rule::Condition};

/// Evaluate a `Condition` against the current request context.
/// Returns `true` if the condition matches.
pub fn evaluate(condition: &Condition, ctx: &RequestContext) -> bool {
    match condition {
        Condition::IpExact { value } => ctx.client_ip == *value,
        Condition::IpInBlacklist | Condition::IpInWhitelist => false,

        Condition::PathExact { value } => ctx.path == *value,
        Condition::PathWildcard { pattern } => wildcard_match(pattern, &ctx.path),
        Condition::PathRegex { pattern } => regex_match(pattern, &ctx.path),

        Condition::HeaderExact { name, value } => {
            let lower = name.to_lowercase();
            ctx.headers.get(&lower).map(|v| v == value).unwrap_or(false)
        }
        Condition::HeaderRegex { name, pattern } => {
            let lower = name.to_lowercase();
            ctx.headers
                .get(&lower)
                .map(|v| regex_match(pattern, v))
                .unwrap_or(false)
        }

        Condition::PayloadRegex { pattern } => ctx
            .body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| regex_match(pattern, s))
            .unwrap_or(false),

        Condition::CookieExact { name, value } => check_cookie(&ctx.headers, name, value),

        Condition::RateLimitExceeded => false,

        Condition::SqliPattern => sqli_regex().is_match(&build_haystack(ctx)),
        Condition::XssPattern => xss_regex().is_match(&build_haystack(ctx)),
        Condition::PathTraversalPattern => pt_regex().is_match(&ctx.path.to_lowercase()),
        Condition::SsrfPattern => ssrf_regex().is_match(&build_haystack(ctx)),
        Condition::HeaderInjectionPattern => ctx.headers.values().any(|v| hi_regex().is_match(v)),

        Condition::And(conds) => conds.iter().all(|c| evaluate(c, ctx)),
        Condition::Or(conds) => conds.iter().any(|c| evaluate(c, ctx)),
        Condition::Not(cond) => !evaluate(cond, ctx),
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Glob-style wildcard match: `*` matches any sequence, `?` matches one char.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let mut re = String::with_capacity(pattern.len() * 2 + 4);
    re.push('^');
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                re.push('\\');
                re.push(ch);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    regex_match(&re, value)
}

fn regex_match(pattern: &str, value: &str) -> bool {
    Regex::new(pattern)
        .map(|re| re.is_match(value))
        .unwrap_or(false)
}

fn check_cookie(headers: &HashMap<String, String>, name: &str, value: &str) -> bool {
    if let Some(cookies) = headers.get("cookie") {
        for part in cookies.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k.trim() == name && v.trim() == value {
                    return true;
                }
            }
        }
    }
    false
}

fn build_haystack(ctx: &RequestContext) -> String {
    let mut parts = vec![ctx.path.clone()];
    if let Some(q) = &ctx.query {
        parts.push(q.clone());
    }
    for v in ctx.headers.values() {
        parts.push(v.clone());
    }
    if let Some(body) = &ctx.body {
        if let Ok(s) = std::str::from_utf8(body) {
            parts.push(s.to_string());
        }
    }
    parts.join(" ")
}

// ── detection regexes (compiled once per process) ─────────────────────────

fn sqli_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(\b(union\s+select|select\s+\S+\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from|drop\s+(table|database)|exec(ute)?\s*\(|cast\s*\(|convert\s*\(|declare\s+@)\b|'(\s*(or|and)\s+'?\d|--)|/\*.*\*/|;\s*(drop|select|insert|update|delete|create)\b)",
        )
        .expect("sqli regex")
    })
}

fn xss_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(<\s*script[\s>]|javascript\s*:|on\w+\s*=\s*['"\w]|<\s*(iframe|object|embed|svg|math)[\s/>]|expression\s*\(|vbscript\s*:)"#,
        )
        .expect("xss regex")
    })
}

fn pt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e|%c0%ae|%c1%9c)")
            .expect("path traversal regex")
    })
}

fn ssrf_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)https?://(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|::1)|file://|dict://|gopher://|sftp://",
        )
        .expect("ssrf regex")
    })
}

fn hi_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\r\n]").expect("header injection regex"))
}
