//! YAML → GRL converter.
//!
//! Walks raw `serde_yaml::Value` so we don't depend on the strict
//! `Rule`/`Condition` struct definitions matching the on-disk format.
//!
//! Mapping (YAML → GRL):
//!   priority: u32  →  salience = (1000 - priority)   ; lower YAML wins
//!   scope.tier     →  Request.Tier == "<tier>"       ; AND-merged into when
//!   scope.global   →  no extra guard
//!   condition.{...}→  GRL boolean expression (see `cond_to_grl`)
//!   action: block  →  block(<id>);
//!   action: challenge → challenge();
//!   action: rate_limit → rate_limit(60);
//!   action: allow  →  allow();
//!   action: log    →  log(<id>);
//!   risk_score_delta → Request.RiskScore = Request.RiskScore + N;

use serde_yaml::Value;

/// Convert a YAML document (a sequence of rule maps) to a GRL source string.
pub fn yaml_to_grl(doc: &Value) -> anyhow::Result<String> {
    let seq = doc.as_sequence()
        .ok_or_else(|| anyhow::anyhow!("yaml rules: top-level must be a sequence"))?;
    let mut out = String::new();
    for (i, item) in seq.iter().enumerate() {
        match rule_to_grl(item) {
            Ok(s)  => { out.push_str(&s); out.push('\n'); }
            Err(e) => tracing::warn!("yaml→grl: skipping rule {}: {}", i, e),
        }
    }
    Ok(out)
}

fn rule_to_grl(v: &Value) -> anyhow::Result<String> {
    let id = v.get("id").and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing id"))?;
    let priority = v.get("priority").and_then(|x| x.as_u64()).unwrap_or(500) as i64;
    let action   = v.get("action").and_then(|x| x.as_str()).unwrap_or("log");
    let delta    = v.get("risk_score_delta").and_then(|x| x.as_i64()).unwrap_or(0);
    let upstream = v.get("upstream_backend").and_then(|x| x.as_str());
    // Routing rules (those with an upstream_backend) must run after all
    // security/detection rules so that detection always wins. Cap their
    // salience to ≤ 150 regardless of their priority value.
    let salience = if upstream.is_some() {
        (1000 - priority).clamp(1, 150) as i32
    } else {
        (1000 - priority) as i32
    };

    let scope_guard = scope_to_grl(v.get("scope"));
    let cond_grl    = cond_to_grl(v.get("condition")
        .ok_or_else(|| anyhow::anyhow!("missing condition"))?)?;

    let when = match scope_guard {
        Some(s) => format!("({}) && ({})", s, cond_grl),
        None    => cond_grl,
    };

    let mut then = String::new();
    if delta != 0 {
        then.push_str(&format!(
            "    Request.RiskScore = Request.RiskScore + {};\n",
            delta
        ));
    }
    // Routing rules emit a virtual `route(...)` action so the proxy can read
    // it from the outcome (handled separately by the existing routing path).
    if let Some(backend) = upstream {
        then.push_str(&format!("    log(\"route:{}\");\n", backend));
    }
    let action_stmt = match action {
        "block"      => format!("    block({:?});\n",     id),
        "challenge"  => "    challenge(\"js\");\n".to_string(),
        "rate_limit" => "    rate_limit(60);\n".to_string(),
        "allow"      => "    allow();\n".to_string(),
        "log"        => format!("    log({:?});\n", id),
        other        => format!("    log(\"unknown_action:{}\");\n", other),
    };
    then.push_str(&action_stmt);

    Ok(format!(
        "rule {:?} salience {} {{\n    when {}\n    then\n{}}}\n",
        id, salience, when, then
    ))
}

fn scope_to_grl(scope: Option<&Value>) -> Option<String> {
    let scope = scope?;
    if let Some(s) = scope.as_str() {
        if s == "global" { return None; }
        return Some(format!("Request.Tier == {:?}", s));
    }
    let map = scope.as_mapping()?;
    let kind = map.get(Value::String("type".into())).and_then(|x| x.as_str())?;
    match kind {
        "global" => None,
        "tier" => {
            let tier = map.get(Value::String("tier".into())).and_then(|x| x.as_str())?;
            Some(format!("Request.Tier == {:?}", tier))
        }
        "route_pattern" => {
            let p = map.get(Value::String("pattern".into())).and_then(|x| x.as_str())?;
            Some(path_match_grl(p))
        }
        "ip" => {
            let ip = map.get(Value::String("ip".into())).and_then(|x| x.as_str())?;
            Some(format!("Request.ClientIp == {:?}", ip))
        }
        _ => None,
    }
}

fn cond_to_grl(c: &Value) -> anyhow::Result<String> {
    // Try new format first (field/match/value)
    if let Ok(grl) = new_cond_to_grl(c) {
        return Ok(grl);
    }
    
    // Fall back to legacy format (type-based)
    let map = c.as_mapping().ok_or_else(|| anyhow::anyhow!("condition must be a map"))?;
    let kind = map.get(Value::String("type".into())).and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("condition missing type and not field/match/value"))?;

    Ok(match kind {
        "ip_exact" => {
            let v = map.get(Value::String("value".into())).and_then(|x| x.as_str()).unwrap_or("");
            format!("Request.ClientIp == {:?}", v)
        }
        "ip_in_blacklist" => "ip_in_blacklist(Request.ClientIp)".into(),
        "ip_in_whitelist" => "ip_in_whitelist(Request.ClientIp)".into(),
        "path_exact" => {
            let v = map.get(Value::String("value".into())).and_then(|x| x.as_str()).unwrap_or("");
            format!("Request.Path == {:?}", v)
        }
        "path_wildcard" => {
            let p = map.get(Value::String("pattern".into())).and_then(|x| x.as_str()).unwrap_or("");
            path_match_grl(p)
        }
        "path_regex" => {
            let p = map.get(Value::String("pattern".into())).and_then(|x| x.as_str()).unwrap_or("");
            format!("matches(Request.Path, {:?})", p)
        }
        "header_exact" => {
            let n = map.get(Value::String("name".into())).and_then(|x| x.as_str()).unwrap_or("");
            let v = map.get(Value::String("value".into())).and_then(|x| x.as_str()).unwrap_or("");
            format!("Request.Headers[{:?}] == {:?}", n, v)
        }
        "header_regex" => {
            let n = map.get(Value::String("name".into())).and_then(|x| x.as_str()).unwrap_or("");
            let p = map.get(Value::String("pattern".into())).and_then(|x| x.as_str()).unwrap_or("");
            format!("matches(Request.Headers[{:?}], {:?})", n, p)
        }
        "payload_regex" => {
            let p = map.get(Value::String("pattern".into())).and_then(|x| x.as_str()).unwrap_or("");
            format!("(matches(Request.Body, {:?}) || matches(Request.Query, {:?}))", p, p)
        }
        "cookie_exact" => {
            // Cookie support not wired; approximate via Cookie header substring.
            let n = map.get(Value::String("name".into())).and_then(|x| x.as_str()).unwrap_or("");
            let v = map.get(Value::String("value".into())).and_then(|x| x.as_str()).unwrap_or("");
            let needle = format!("{}={}", n, v);
            format!("contains(Request.Headers[\"Cookie\"], {:?})", needle)
        }
        "rate_limit_exceeded"      => "false".into(), // wired in Phase 6
        "sqli_pattern"             => "(contains_sqli(Request.Query) || contains_sqli(Request.Body))".into(),
        "xss_pattern"              => "(contains_xss(Request.Query) || contains_xss(Request.Body))".into(),
        "path_traversal_pattern"   => "contains_path_traversal(Request.Path)".into(),
        "ssrf_pattern"             => "(contains(Request.Query, \"http://\") || contains(Request.Query, \"file://\") || contains(Request.Query, \"169.254.169.254\"))".into(),
        "header_injection_pattern" => "(contains_header_injection(Request.Path) || contains_header_injection(Request.Query))".into(),
        "and" => combine_conds(map.get(Value::String("conditions".into())), " && ")?,
        "or"  => combine_conds(map.get(Value::String("conditions".into())), " || ")?,
        "not" => {
            let inner = map.get(Value::String("condition".into()))
                .ok_or_else(|| anyhow::anyhow!("not: missing condition"))?;
            format!("!({})", cond_to_grl(inner)?)
        }
        other => format!("false /* unknown condition: {} */", other),
    })
}

/// Escape a string for use in GRL string literals.
/// Only escape quotes - GRL doesn't require backslash escaping for regex patterns.
fn grl_string_literal(s: &str) -> String {
    let mut result = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            _ => result.push(c),
        }
    }
    result.push('"');
    result
}

/// Convert new-format conditions (field/match/value) to GRL.
fn new_cond_to_grl(c: &Value) -> anyhow::Result<String> {
    let map = c.as_mapping().ok_or_else(|| anyhow::anyhow!("not a map"))?;
    
    // Check if this is an and/or node
    if let Some(conds_val) = map.get(Value::String("and".into())) {
        if let Some(seq) = conds_val.as_sequence() {
            let parts: Result<Vec<_>, _> = seq.iter().map(new_cond_to_grl).collect();
            return Ok(format!("({})", parts?.join(" && ")));
        }
    }
    
    if let Some(conds_val) = map.get(Value::String("or".into())) {
        if let Some(seq) = conds_val.as_sequence() {
            let parts: Result<Vec<_>, _> = seq.iter().map(new_cond_to_grl).collect();
            return Ok(format!("({})", parts?.join(" || ")));
        }
    }
    
    // Field/match/value format
    let field = map.get(Value::String("field".into())).and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing field"))?;
    let match_type = map.get(Value::String("match".into())).and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing match"))?;
    let value = map.get(Value::String("value".into())).and_then(|x| x.as_str()).unwrap_or("");
    
    Ok(match (field, match_type) {
        ("ip", "exact") => format!("Request.ClientIp == {}", grl_string_literal(value)),
        ("ip", "cidr") => {
            // For now, approximate CIDR as substring; ideally would call cidr_match(ip, cidr)
            format!("contains(Request.ClientIp, {})", grl_string_literal(value))
        }
        ("path", "exact") => format!("Request.Path == {}", grl_string_literal(value)),
        ("path", "wildcard") => path_match_grl(value),
        ("path", "regex") => format!("matches(Request.Path, {})", grl_string_literal(value)),
        ("method", "exact") => format!("Request.Method == {}", grl_string_literal(value)),
        ("method", "regex") => format!("matches(Request.Method, {})", grl_string_literal(value)),
        ("header", "exact") => {
            // value format: "Header-Name: expected-value"
            if let Some((name, val)) = value.split_once(':') {
                let val = val.trim();
                format!("Request.Headers[{}] == {}", grl_string_literal(name), grl_string_literal(val))
            } else {
                format!("has_header(Request, {})", grl_string_literal(value))
            }
        }
        ("header", "regex") => {
            if let Some((name, pattern)) = value.split_once(':') {
                format!("matches(Request.Headers[{}], {})", grl_string_literal(name.trim()), grl_string_literal(pattern.trim()))
            } else {
                format!("false /* invalid header regex: {} */", value)
            }
        }
        ("payload", "regex") => format!("matches(Request.Body, {})", grl_string_literal(value)),
        ("payload", "contains") => format!("contains(Request.Body, {})", grl_string_literal(value)),
        ("cookie", "exact") => {
            if let Some((name, val)) = value.split_once('=') {
                let needle = format!("{}={}", name.trim(), val.trim());
                format!("contains(Request.Headers[\"Cookie\"], {})", grl_string_literal(&needle))
            } else {
                format!("false /* invalid cookie: {} */", value)
            }
        }
        (f, m) => format!("false /* unknown field/match: {}/{} */", f, m),
    })
}

fn combine_conds(list: Option<&Value>, sep: &str) -> anyhow::Result<String> {
    let seq = list.and_then(|v| v.as_sequence())
        .ok_or_else(|| anyhow::anyhow!("expected list of conditions"))?;
    let parts: Result<Vec<_>, _> = seq.iter().map(cond_to_grl).collect();
    Ok(format!("({})", parts?.join(sep)))
}

/// Translate a glob pattern (`/api/*`, `/**`, exact) into a GRL boolean expr.
fn path_match_grl(p: &str) -> String {
    if p == "/**" || p == "**" {
        return "true".into();
    }
    if let Some(prefix) = p.strip_suffix("/*") {
        // /api/* matches /api/anything (exactly one more segment, no nested /)
        // Uses the `matches()` built-in with a regex so it round-trips through
        // the GRL parser correctly.
        let escaped = regex_escape(prefix);
        return format!("matches(Request.Path, \"^{}/[^/]+$\")", escaped);
    }
    if let Some(prefix) = p.strip_suffix("/**") {
        return format!("starts_with(Request.Path, {:?})", format!("{}/", prefix));
    }
    format!("Request.Path == {:?}", p)
}

/// Escape regex metacharacters that may appear in a path prefix.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        if ".+*?^${}()|[]\\".contains(ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::grl::parser::parse;

    #[test]
    fn converts_sqli_block_rule() {
        let yaml = r#"
- id: critical-sqli
  priority: 90
  scope:
    type: tier
    tier: critical
  condition:
    type: sqli_pattern
  action: block
  risk_score_delta: 80
"#;
        let doc: Value = serde_yaml::from_str(yaml).unwrap();
        let grl = yaml_to_grl(&doc).unwrap();
        // Must round-trip parse cleanly.
        let rules = parse(&grl).expect(&grl);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "critical-sqli");
        assert_eq!(rules[0].salience, 1000 - 90);
    }

    #[test]
    fn converts_path_wildcard_routing() {
        let yaml = r#"
- id: route-api
  priority: 60
  scope: global
  condition:
    type: path_wildcard
    pattern: /api/*
  action: allow
  upstream_backend: python
  risk_score_delta: 0
"#;
        let doc: Value = serde_yaml::from_str(yaml).unwrap();
        let grl = yaml_to_grl(&doc).unwrap();
        let rules = parse(&grl).expect(&grl);
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn handles_and_or_combinator() {
        let yaml = r#"
- id: combo
  priority: 100
  scope: global
  condition:
    type: and
    conditions:
      - type: path_exact
        value: /x
      - type: or
        conditions:
          - type: sqli_pattern
          - type: xss_pattern
  action: block
  risk_score_delta: 50
"#;
        let doc: Value = serde_yaml::from_str(yaml).unwrap();
        let grl = yaml_to_grl(&doc).unwrap();
        parse(&grl).expect(&grl);
    }
}
