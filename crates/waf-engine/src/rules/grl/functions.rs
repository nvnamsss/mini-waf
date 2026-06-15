//! Built-in functions exposed inside GRL `when`/`then` expressions.
//!
//! All entries are pure (no I/O), single-fact-aware, and dispatched by name.

use std::sync::OnceLock;

use regex::Regex;

use crate::rules::grl::ast::Value;

/// Dispatch a named function call with already-evaluated arguments.
pub fn dispatch(name: &str, args: &[Value]) -> Value {
    match name {
        // ── string predicates ────────────────────────────────────────────
        "matches"      => fn_matches(args),
        "contains"     => fn_contains(args),
        "starts_with"  => fn_starts_with(args),
        "ends_with"    => fn_ends_with(args),
        "lower"        => Value::Str(arg_str(args, 0).to_lowercase()),
        "upper"        => Value::Str(arg_str(args, 0).to_uppercase()),
        "len"          => Value::Int(arg_str(args, 0).chars().count() as i64),

        // ── WAF detection predicates ─────────────────────────────────────
        "contains_sqli"        => Value::Bool(detect_sqli(&arg_str(args, 0))),
        "contains_xss"         => Value::Bool(detect_xss(&arg_str(args, 0))),
        "contains_path_traversal" => Value::Bool(detect_path_traversal(&arg_str(args, 0))),
        "contains_cmd_injection"  => Value::Bool(detect_cmd_injection(&arg_str(args, 0))),
        "contains_header_injection" => Value::Bool(detect_header_injection(&arg_str(args, 0))),

        // ── network / list helpers ───────────────────────────────────────
        // ip_in_blacklist / ip_in_whitelist are registered by BlacklistPlugin
        // via FunctionRegistry and never reach this dispatch table.

        _ => Value::Null,
    }
}

fn arg_str(args: &[Value], i: usize) -> String {
    args.get(i).map(|v| v.as_str()).unwrap_or_default()
}

fn fn_matches(args: &[Value]) -> Value {
    let hay = arg_str(args, 0);
    let pat = arg_str(args, 1);
    Value::Bool(Regex::new(&pat).map(|r| r.is_match(&hay)).unwrap_or(false))
}
fn fn_contains(args: &[Value]) -> Value {
    Value::Bool(arg_str(args, 0).contains(&arg_str(args, 1)))
}
fn fn_starts_with(args: &[Value]) -> Value {
    Value::Bool(arg_str(args, 0).starts_with(&arg_str(args, 1)))
}
fn fn_ends_with(args: &[Value]) -> Value {
    Value::Bool(arg_str(args, 0).ends_with(&arg_str(args, 1)))
}

// ─── Detection patterns ──────────────────────────────────────────────────────
//
// These are intentionally conservative regex-based detectors covering the
// payloads in `tests/fixtures/`. Phase 6 may swap them for the richer impls
// in `crate::detection::*`.

static SQLI_RE: OnceLock<Regex> = OnceLock::new();
static XSS_RE:  OnceLock<Regex> = OnceLock::new();
static PATH_TRAVERSAL_RE: OnceLock<Regex> = OnceLock::new();
static CMD_INJECTION_RE:  OnceLock<Regex> = OnceLock::new();
static HEADER_INJECTION_RE: OnceLock<Regex> = OnceLock::new();

fn re_sqli() -> &'static Regex {
    SQLI_RE.get_or_init(|| Regex::new(
        r"(?ix)
          (?:'\s*or\s*'?\d+'?\s*=\s*'?\d+)
        | (?:--\s)
        | (?:\bunion\b\s+\bselect\b)
        | (?:\bdrop\s+table\b)
        | (?:\bselect\b\s+\*\s+\bfrom\b)
        | (?:\bor\b\s+\d+\s*=\s*\d+)
        | (?:;\s*--)
        | (?:\bxp_cmdshell\b)
        | (?:\bsleep\s*\(\s*\d+\s*\))
        ").unwrap()
    )
}
fn re_xss() -> &'static Regex {
    XSS_RE.get_or_init(|| Regex::new(
        r"(?ix)
          <\s*script[^>]*>
        | javascript\s*:
        | on(?:error|load|click|mouseover)\s*=
        | <\s*img[^>]*\bonerror\b
        | <\s*svg[^>]*on\w+
        | document\.cookie
        ").unwrap()
    )
}
fn re_traversal() -> &'static Regex {
    PATH_TRAVERSAL_RE.get_or_init(|| Regex::new(
        r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)"
    ).unwrap())
}
fn re_cmd() -> &'static Regex {
    CMD_INJECTION_RE.get_or_init(|| Regex::new(
        r"(?ix)
          (?:[;&|`]\s*(?:cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b)
        | (?:\$\([^)]*\))
        | (?:`[^`]*`)
        ").unwrap()
    )
}
fn re_header() -> &'static Regex {
    HEADER_INJECTION_RE.get_or_init(|| Regex::new(r"(?:\r\n|\n\r|\r|\n)").unwrap())
}

pub fn detect_sqli(s: &str)             -> bool { re_sqli().is_match(s) }
pub fn detect_xss(s: &str)              -> bool { re_xss().is_match(s) }
pub fn detect_path_traversal(s: &str)   -> bool { re_traversal().is_match(s) }
pub fn detect_cmd_injection(s: &str)    -> bool { re_cmd().is_match(s) }
pub fn detect_header_injection(s: &str) -> bool { re_header().is_match(s) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_detects_classics() {
        assert!(detect_sqli("' OR '1'='1"));
        assert!(detect_sqli("1; DROP TABLE users--"));
        assert!(detect_sqli("UNION SELECT password FROM users"));
        assert!(!detect_sqli("hello world"));
    }

    #[test]
    fn xss_detects_classics() {
        assert!(detect_xss("<script>alert(1)</script>"));
        assert!(detect_xss("<img src=x onerror=alert(1)>"));
        assert!(detect_xss("javascript:alert(1)"));
        assert!(!detect_xss("normal text"));
    }

    #[test]
    fn traversal_detects() {
        assert!(detect_path_traversal("../../etc/passwd"));
        assert!(detect_path_traversal("%2e%2e%2fetc"));
        assert!(!detect_path_traversal("/api/v1/users"));
    }
}
