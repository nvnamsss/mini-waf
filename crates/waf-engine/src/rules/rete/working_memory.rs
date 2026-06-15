//! Working memory — fact storage + path resolution + scratch state.
//!
//! Only one fact (`RequestContext`) is supported; sufficient for WAF use.
//! Mutable state (assignments via `Request.RiskScore = …`) lives in `scratch`.

use std::collections::HashMap;

use crate::context::RequestContext;
use crate::rules::grl::ast::{Path, PathSeg, Value};
use crate::rules::grl::registry::FunctionRegistry;

/// Mutable, per-request rule-engine state.
pub struct WorkingMemory<'a> {
    pub fact:     &'a RequestContext,
    /// Assignments overlay — read-back wins over `fact`.
    /// Keyed directly by `Path` (which derives `Eq + Hash`), avoiding the
    /// `format!("{}", path)` String allocation on every read/write.
    pub scratch:  HashMap<Path, Value>,
    /// Side-channel commands emitted by action functions.
    pub outcome:  Outcome,
    /// Function registry — context-aware functions callable from GRL.
    pub registry: &'a FunctionRegistry,
}

#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub block_reason:    Option<String>,
    pub allow:           bool,
    pub challenge:       Option<ChallengeReq>,
    pub rate_limit_secs: Option<u64>,
    pub log_messages:    Vec<String>,
    pub matched_rules:   Vec<String>,
    pub risk_delta:      i64,
}

#[derive(Debug, Clone, Copy)]
pub enum ChallengeReq { Js, Pow }

impl<'a> WorkingMemory<'a> {
    pub fn new(fact: &'a RequestContext, registry: &'a FunctionRegistry) -> Self {
        Self { fact, scratch: HashMap::new(), outcome: Outcome::default(), registry }
    }

    /// Resolve a `Path` to a `Value` — overlay wins over base fact.
    pub fn read_path(&self, path: &Path) -> Value {
        if let Some(v) = self.scratch.get(path) { return v.clone(); }
        resolve(path, self.fact)
    }

    pub fn write_path(&mut self, path: &Path, value: Value) {
        self.scratch.insert(path.clone(), value);
    }
}

/// Resolve a `Path` against the live `RequestContext`. Unknown paths → `Null`.
fn resolve(path: &Path, ctx: &RequestContext) -> Value {
    let mut iter = path.segments.iter();
    let head = match iter.next() {
        Some(PathSeg::Field(s)) => s.as_str(),
        _ => return Value::Null,
    };
    if head != "Request" { return Value::Null; }

    let field = match iter.next() {
        Some(PathSeg::Field(s)) => s.as_str(),
        _ => return Value::Null,
    };

    match field {
        "Method"    => Value::Str(ctx.method.clone()),
        "Path"      => Value::Str(url_decode(&ctx.path)),
        "RawPath"   => Value::Str(ctx.path.clone()),
        "Query"     => Value::Str(form_decode(&ctx.query.clone().unwrap_or_default())),
        "RawQuery"  => Value::Str(ctx.query.clone().unwrap_or_default()),
        "Body"      => Value::Str(
            ctx.body.as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
        ),
        "ClientIp"  => Value::Str(ctx.client_ip.clone()),
        "RequestId" => Value::Str(ctx.request_id.clone()),
        "SessionId" => Value::Str(ctx.session_id.clone().unwrap_or_default()),
        "DeviceFp"  => Value::Str(ctx.device_fp.clone().unwrap_or_default()),
        "Tier"      => Value::Str(format!("{:?}", ctx.tier).to_lowercase()),
        "RiskScore" => Value::Int(ctx.risk_score.value() as i64),
        "Xff"       => Value::Str(ctx.xff_header.clone().unwrap_or_default()),
        "Headers"   => match iter.next() {
            Some(PathSeg::Index(name)) => {
                let key = name.to_lowercase();
                let val = ctx.headers.iter()
                    .find(|(k, _)| k.to_lowercase() == key)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                Value::Str(val)
            }
            _ => Value::Null,
        },
        // Plugin-injected key-value extensions. GRL: `Request.Ext["geo.country"]`
        "Ext" => match iter.next() {
            Some(PathSeg::Index(key)) => Value::Str(
                ctx.extensions.get(key.as_str()).cloned().unwrap_or_default(),
            ),
            _ => Value::Null,
        },
        _ => Value::Null,
    }
}

/// Minimal percent-decoder. Replaces `%XX` triplets with their byte and
/// returns a UTF-8 lossy string. `+` is left as-is (forms can be detected
/// independently).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Like `url_decode` but also converts `+` to space (form-urlencoded queries).
fn form_decode(s: &str) -> String {
    url_decode(&s.replace('+', " "))
}
