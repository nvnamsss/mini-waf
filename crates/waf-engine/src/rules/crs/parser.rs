//! Parser for ModSecurity/CRS `.conf` rule files.
//!
//! Handles:
//! - `SecRule TARGETS "OPERATOR" "ACTIONS"` → `RuleItem::Rule`
//! - `SecMarker "NAME"` → `RuleItem::Marker`
//!
//! Rules with unsupported operators (invalid regex, `@validateByteRange`, etc.)
//! are silently dropped so they cannot prevent the WAF from starting.

use std::net::IpAddr;
use ipnet::IpNet;
use tracing::warn;
use crate::rules::crs::types::*;

// ─── public entry point ──────────────────────────────────────────────────────

/// Parse a CRS `.conf` file source into `RuleItem`s.
pub fn parse_conf(src: &str) -> Vec<RuleItem> {
    let lines = join_continuations(src);
    let mut items = Vec::new();
    // Track whether the most-recently-skipped rule had `chain` in its action
    // string.  When true, the immediately following rule (a chain member) must
    // also be skipped, otherwise the orphaned member would fire standalone.
    let mut skip_chain_members: u32 = 0;

    for line in &lines {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }

        if t.starts_with("SecRule") && t[7..].starts_with(|c: char| c.is_whitespace()) {
            let rest = t["SecRule".len()..].trim_start();
            if skip_chain_members > 0 {
                // This line is a chain member of a previously-skipped head.
                // Determine if it itself chains further (nested chain).
                let chains_further = has_chain_action(rest);
                skip_chain_members -= 1;
                if chains_further { skip_chain_members += 1; }
                continue;
            }
            match parse_secrule(rest) {
                Some(rule) => {
                    items.push(RuleItem::Rule(rule));
                }
                None => {
                    // Rule was skipped (unsupported operator etc.).
                    // If it had a `chain` action, its members must be skipped too.
                    if has_chain_action(rest) {
                        skip_chain_members = 1;
                    }
                }
            }
        } else if t.starts_with("SecMarker") {
            skip_chain_members = 0; // chain can't span a marker
            let name = t["SecMarker".len()..].trim().trim_matches('"').trim();
            if !name.is_empty() {
                items.push(RuleItem::Marker(name.to_owned()));
            }
        }
    }
    items
}

// ─── line joining ────────────────────────────────────────────────────────────

/// Quick heuristic: does this raw (joined) `SecRule` line have a `chain` action?
/// Used to detect chain heads that fail to parse, so we can skip their members.
fn has_chain_action(rest: &str) -> bool {
    // The actions string is the last double-quoted token.
    // A rough check: look for the word `chain` as a comma-separated token.
    if let Some(last_dq) = rest.rfind('"') {
        if let Some(open) = rest[..last_dq].rfind('"') {
            let actions = &rest[open + 1..last_dq];
            return actions.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("chain"));
        }
    }
    false
}

fn join_continuations(src: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in src.lines() {
        if line.ends_with('\\') {
            current.push_str(&line[..line.len() - 1]);
            current.push(' ');
        } else {
            current.push_str(line);
            let trimmed = current.trim().to_owned();
            if !trimmed.is_empty() {
                lines.push(trimmed);
            }
            current.clear();
        }
    }
    if !current.trim().is_empty() {
        lines.push(current.trim().to_owned());
    }
    lines
}

// ─── SecRule parsing ─────────────────────────────────────────────────────────

fn parse_secrule(rest: &str) -> Option<SecRule> {
    let (targets_str, rest) = split_token(rest)?;
    let rest = rest.trim_start();
    let (op_str, rest) = parse_dquoted(rest)?;
    let rest = rest.trim_start();
    let (actions_str, _) = parse_dquoted(rest)?;

    let (negate_op, operator) = parse_operator(op_str.trim())?;
    let targets = parse_targets(&targets_str);
    let (transforms, raw) = parse_actions(&actions_str);

    Some(SecRule {
        id: raw.id,
        phase: raw.phase,
        targets,
        operator,
        negate_op,
        transforms,
        actions: raw.into_crs_actions(),
        cache_slot: vec![], // filled by CrsRuleset::assign_cache_slots()
        needs_body: false,  // filled by CrsRuleset::assign_needs_body()
    })
}

// ─── tokeniser ───────────────────────────────────────────────────────────────

fn split_token(s: &str) -> Option<(String, &str)> {
    let end = s.find(char::is_whitespace)?;
    Some((s[..end].to_owned(), &s[end..]))
}

fn parse_dquoted(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if !s.starts_with('"') { return None; }
    let inner = &s[1..];
    let mut prev_bs = false;
    for (i, c) in inner.char_indices() {
        if c == '"' && !prev_bs {
            return Some((inner[..i].to_owned(), &inner[i + 1..]));
        }
        prev_bs = c == '\\' && !prev_bs;
    }
    None
}

// ─── targets ─────────────────────────────────────────────────────────────────

fn parse_targets(s: &str) -> Vec<CrsTarget> {
    s.split('|').filter_map(|tok| parse_one_target(tok.trim())).collect()
}

fn parse_one_target(tok: &str) -> Option<CrsTarget> {
    // &TX:VAR — count of variable
    if let Some(rest) = tok.strip_prefix("&TX:") {
        return Some(CrsTarget::TxCount(rest.to_owned()));
    }
    // &REQUEST_HEADERS:Name — 1 if header present, 0 if absent
    if let Some(rest) = tok.strip_prefix("&REQUEST_HEADERS:") {
        return Some(CrsTarget::RequestHeadersCount(rest.to_owned()));
    }
    // &ARGS — total argument count
    if tok == "&ARGS" {
        return Some(CrsTarget::ArgsCount);
    }
    // Any other &COLLECTION prefix — skip
    if tok.starts_with('&') { return None; }

    // COLLECTION:subkey
    if let Some(colon) = tok.find(':') {
        let col = &tok[..colon];
        let sub = &tok[colon + 1..];
        return match col {
            "REQUEST_HEADERS" => Some(CrsTarget::RequestHeaders(Some(sub.to_owned()))),
            "TX"              => Some(CrsTarget::Tx(sub.to_owned())),
            "XML"             => None, // no XML parser
            _                 => None,
        };
    }

    Some(match tok {
        "ARGS"                  => CrsTarget::Args,
        "ARGS_NAMES"            => CrsTarget::ArgsNames,
        "REQUEST_COOKIES"       => CrsTarget::RequestCookies,
        "REQUEST_COOKIES_NAMES" => CrsTarget::RequestCookiesNames,
        "REQUEST_HEADERS"       => CrsTarget::RequestHeaders(None),
        "REQUEST_URI"           => CrsTarget::RequestUri,
        "REQUEST_URI_RAW"       => CrsTarget::RequestUriRaw,
        "REQUEST_FILENAME"      => CrsTarget::RequestFilename,
        "REQUEST_BASENAME"      => CrsTarget::RequestBasename,
        "REQUEST_METHOD"        => CrsTarget::RequestMethod,
        "REQUEST_BODY"          => CrsTarget::RequestBody,
        "REQUEST_LINE"          => CrsTarget::RequestLine,
        "QUERY_STRING"          => CrsTarget::QueryString,
        "REMOTE_ADDR"           => CrsTarget::RemoteAddr,
        _                       => return None,
    })
}

// ─── operator ────────────────────────────────────────────────────────────────

fn parse_operator(s: &str) -> Option<(bool, CrsOperator)> {
    let (negate, s) = if s.starts_with('!') {
        (true, s[1..].trim_start())
    } else {
        (false, s)
    };
    if !s.starts_with('@') { return None; }
    let body = &s[1..];
    let (name, args) = body
        .find(char::is_whitespace)
        .map(|i| (&body[..i], body[i..].trim()))
        .unwrap_or((body, ""));

    let op = match name.to_lowercase().as_str() {
        "detectsqli"           => CrsOperator::DetectSQLi,
        "detectxss"            => CrsOperator::DetectXSS,
        "validateurlencoding"  => CrsOperator::ValidateUrlEncoding,
        "validateutf8encoding" => CrsOperator::ValidateUtf8Encoding,

        "rx" => {
            match regex::Regex::new(args) {
                Ok(re) => CrsOperator::Rx(re),
                Err(e) => {
                    warn!("crs: skipping rule with invalid regex: {}", e);
                    return None;
                }
            }
        }

        "pm" => {
            let phrases: Vec<&str> = args.split_whitespace().collect();
            // Build the Aho-Corasick automaton once at parse/load time.
            // ascii_case_insensitive avoids lowercasing inputs at match time.
            let ac = aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&phrases)
                .unwrap_or_else(|_| aho_corasick::AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(Vec::<&str>::new())
                    .unwrap());
            CrsOperator::Pm(ac)
        }
        "pmfromfile" => CrsOperator::PmFromFile(args.trim().to_owned()),

        "eq" => {
            if let Some(tx_var) = args.strip_prefix("%{tx.").and_then(|s| s.strip_suffix('}')) {
                CrsOperator::EqTxRef(tx_var.to_lowercase())
            } else {
                CrsOperator::Eq(args.parse().ok()?)
            }
        }
        "lt" => {            if let Some(tx_var) = args.strip_prefix("%{tx.").and_then(|s| s.strip_suffix('}')) {
                CrsOperator::LtTxRef(tx_var.to_lowercase())
            } else {
                CrsOperator::Lt(args.parse().ok()?)
            }
        }
        "le" => {
            if let Some(tx_var) = args.strip_prefix("%{tx.").and_then(|s| s.strip_suffix('}')) {
                CrsOperator::LeTxRef(tx_var.to_lowercase())
            } else {
                CrsOperator::Le(args.parse().ok()?)
            }
        }
        "gt" => {
            if let Some(tx_var) = args.strip_prefix("%{tx.").and_then(|s| s.strip_suffix('}')) {
                CrsOperator::GtTxRef(tx_var.to_lowercase())
            } else {
                CrsOperator::Gt(args.parse().ok()?)
            }
        }
        "ge" => {
            if let Some(tx_var) = args.strip_prefix("%{tx.").and_then(|s| s.strip_suffix('}')) {
                CrsOperator::GeTxRef(tx_var.to_lowercase())
            } else {
                CrsOperator::Ge(args.parse().ok()?)
            }
        }

        "contains"   => CrsOperator::Contains(args.to_lowercase()),
        "streq"      => CrsOperator::Streq(args.to_owned()),
        "beginswith" => CrsOperator::BeginsWith(args.to_owned()),
        "endswith"   => CrsOperator::EndsWith(args.to_owned()),
        "within"     => CrsOperator::Within(args.split_whitespace().map(str::to_owned).collect()),

        "ipmatch" => {
            let nets = args.split(',').filter_map(|p| parse_ipnet(p.trim())).collect();
            CrsOperator::IpMatch(nets)
        }

        other => {
            warn!("crs: skipping rule with unsupported operator @{}", other);
            return None;
        }
    };
    Some((negate, op))
}

fn parse_ipnet(s: &str) -> Option<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() { return Some(net); }
    if let Ok(addr) = s.parse::<IpAddr>() {
        let prefix = match addr { IpAddr::V4(_) => 32, IpAddr::V6(_) => 128 };
        return IpNet::new(addr, prefix).ok();
    }
    None
}

// ─── actions ─────────────────────────────────────────────────────────────────

struct RawActions {
    id: u32,
    phase: u8,
    skip_after: Option<String>,
    setvars: Vec<SetVarOp>,
    tags: Vec<String>,
    severity: Option<String>,
    is_nolog: bool,
    is_block: bool,
    is_chain: bool,
    is_capture: bool,
    is_multi_match: bool,
    transforms: Vec<CrsTransform>,
}

impl Default for RawActions {
    fn default() -> Self {
        Self {
            id: 0, phase: 2,
            skip_after: None, setvars: Vec::new(), tags: Vec::new(), severity: None,
            is_nolog: false, is_block: false, is_chain: false,
            is_capture: false, is_multi_match: false, transforms: Vec::new(),
        }
    }
}

impl RawActions {
    fn into_crs_actions(self) -> CrsActions {
        CrsActions {
            skip_after: self.skip_after,
            setvars: self.setvars,
            tags: self.tags,
            severity: self.severity,
            is_nolog: self.is_nolog,
            default_action: if self.is_block { DefaultAction::Block } else { DefaultAction::Pass },
            is_chain: self.is_chain,
            is_capture: self.is_capture,
            is_multi_match: self.is_multi_match,
        }
    }
}

/// Returns `(transforms, raw_actions)`.
fn parse_actions(s: &str) -> (Vec<CrsTransform>, RawActions) {
    let mut ra = RawActions::default();
    for token in split_actions(s) {
        let token = token.trim();
        if token.is_empty() { continue; }

        if let Some(colon) = token.find(':') {
            let key = &token[..colon];
            let val = unquote(&token[colon + 1..]);
            match key.to_lowercase().as_str() {
                "id"        => { ra.id    = val.parse().unwrap_or(0); }
                "phase"     => { ra.phase = val.parse().unwrap_or(2); }
                "tag"       => { ra.tags.push(val.to_owned()); }
                "severity"  => { ra.severity = Some(val.to_owned()); }
                "skipafter" => { ra.skip_after = Some(val.to_owned()); }
                "setvar"    => {
                    // setvar value may still have surrounding single quotes
                    let sv_str = token[colon + 1..].trim().trim_matches('\'');
                    if let Some(sv) = parse_setvar(sv_str) {
                        ra.setvars.push(sv);
                    }
                }
                "t" => match val.to_lowercase().as_str() {
                    "none" => ra.transforms.clear(),
                    name   => {
                        if let Some(tf) = parse_transform(name) {
                            ra.transforms.push(tf);
                        }
                    }
                },
                // Ignored: msg, logdata, ver, auditlog, status, ctl, maturity, accuracy, rev
                _ => {}
            }
        } else {
            match token.to_lowercase().as_str() {
                "block" | "deny"    => ra.is_block      = true,
                "pass"              => ra.is_block       = false,
                "chain"             => ra.is_chain       = true,
                "nolog"             => ra.is_nolog       = true,
                "capture"           => ra.is_capture     = true,
                "multimatch"        => ra.is_multi_match = true,
                "log" | "auditlog" | "noauditlog" => {}
                _ => {}
            }
        }
    }
    let transforms = ra.transforms.clone();
    (transforms, ra)
}

/// Split action string on commas, respecting single-quoted values.
fn split_actions(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_sq = false;
    for c in s.chars() {
        match c {
            '\'' => { in_sq = !in_sq; cur.push(c); }
            ',' if !in_sq => {
                tokens.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() { tokens.push(cur); }
    tokens
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('\'') && s.ends_with('\''))
            || (s.starts_with('"') && s.ends_with('"')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn parse_transform(name: &str) -> Option<CrsTransform> {
    Some(match name {
        "lowercase"           => CrsTransform::Lowercase,
        "urldecodeuni"        => CrsTransform::UrlDecodeUni,
        "removenulls"         => CrsTransform::RemoveNulls,
        "utf8tounicode"       => CrsTransform::Utf8ToUnicode,
        "compresswhitespace"  => CrsTransform::CompressWhitespace,
        "normalizepath"       | "normalizepathwin" => CrsTransform::NormalizePath,
        "htmlentitydecode"    => CrsTransform::HtmlEntityDecode,
        "jsdecode"            => CrsTransform::JsDecode,
        "cssdecode"           => CrsTransform::CssDecode,
        "base64decode"        => CrsTransform::Base64Decode,
        "trim"                => CrsTransform::Trim,
        "removewhitespace"    => CrsTransform::RemoveWhitespace,
        "replacecomments"     => CrsTransform::ReplaceComments,
        "length"              => CrsTransform::Length,
        "escapeseqdecode"     => CrsTransform::EscapeSeqDecode,
        _ => return None,
    })
}

/// Parse a raw `setvar` value (after stripping outer `setvar:` and single quotes).
///
/// Format: `tx.varname=+%{tx.other}` | `tx.varname=+5` | `tx.varname=5`
fn parse_setvar(s: &str) -> Option<SetVarOp> {
    let eq = s.find('=')?;
    let var_full = &s[..eq];
    let rhs_str  = &s[eq + 1..];

    let var = var_full.trim_start_matches("tx.").to_lowercase();
    if var.is_empty() { return None; }

    let (op, rhs_s) = if rhs_str.starts_with('+') {
        (VarOp::IncrBy, &rhs_str[1..])
    } else if rhs_str.starts_with('-') {
        (VarOp::DecrBy, &rhs_str[1..])
    } else {
        (VarOp::Assign, rhs_str)
    };

    let rhs = if let Some(inner) = rhs_s.strip_prefix("%{tx.")
                                         .and_then(|s| s.strip_suffix('}'))
    {
        SetVarRhs::TxRef(inner.to_lowercase())
    } else if let Ok(n) = rhs_s.parse::<i64>() {
        SetVarRhs::Int(n)
    } else {
        return None; // unknown rhs form; skip this setvar
    };

    Some(SetVarOp { var, op, rhs })
}

// ─── unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_continuation_lines() {
        let src = "SecRule ARGS \\\n    \"@rx foo\" \\\n    \"id:1,phase:2,pass\"";
        let lines = join_continuations(src);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("@rx foo"));
    }

    #[test]
    fn parse_simple_detect_sqli_rule() {
        let src = r#"SecRule ARGS "@detectSQLi" "id:9001,phase:2,block,tag:'attack-sqli',setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'""#;
        let items = parse_conf(src);
        assert_eq!(items.len(), 1);
        let rule = match &items[0] { RuleItem::Rule(r) => r, _ => panic!("expected rule") };
        assert_eq!(rule.id, 9001);
        assert_eq!(rule.phase, 2);
        assert!(!rule.actions.setvars.is_empty());
        assert!(rule.actions.tags.contains(&"attack-sqli".to_owned()));
    }

    #[test]
    fn parse_skip_after_rule() {
        let src = r#"SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:942011,phase:1,pass,nolog,tag:'OWASP_CRS',skipAfter:END-CRS""#;
        let items = parse_conf(src);
        let rule = match &items[0] { RuleItem::Rule(r) => r, _ => panic!() };
        assert_eq!(rule.actions.skip_after.as_deref(), Some("END-CRS"));
    }

    #[test]
    fn parse_marker() {
        let items = parse_conf(r#"SecMarker "END-REQUEST-942-APPLICATION-ATTACK-SQLI""#);
        match &items[0] {
            RuleItem::Marker(n) => assert_eq!(n, "END-REQUEST-942-APPLICATION-ATTACK-SQLI"),
            _ => panic!("expected marker"),
        }
    }

    #[test]
    fn setvar_tx_ref() {
        let sv = parse_setvar("tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}").unwrap();
        assert_eq!(sv.var, "inbound_anomaly_score_pl1");
        assert_eq!(sv.op, VarOp::IncrBy);
        assert!(matches!(sv.rhs, SetVarRhs::TxRef(ref r) if r == "critical_anomaly_score"));
    }
}
