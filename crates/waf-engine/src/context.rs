use std::collections::HashMap;

use waf_types::{risk::RiskScore, tier::Tier};

/// All data the WAF pipeline needs to evaluate a single HTTP request.
/// Built once per request by `waf-proxy` and threaded through every check.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// UUIDv4 assigned at ingress.
    pub request_id: String,
    /// Unix timestamp (ms) when the request arrived at the WAF.
    pub arrived_at_ms: i64,

    // ── routing ──────────────────────────────────────────────────────────
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Resolved tier based on path matching.
    pub tier: Tier,

    // ── network identity ─────────────────────────────────────────────────
    /// Canonical client IP after XFF chain validation.
    pub client_ip: String,
    /// Raw X-Forwarded-For header value, if present.
    pub xff_header: Option<String>,

    // ── request data ─────────────────────────────────────────────────────
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,

    // ── session / device ─────────────────────────────────────────────────
    pub session_id: Option<String>,
    /// Derived device fingerprint (JA3/JA4 + UA entropy + H2 settings).
    pub device_fp: Option<String>,

    // ── risk state (mutated by pipeline stages) ───────────────────────────
    pub risk_score: RiskScore,
    /// Rule ID that produced the first match, if any.
    pub matched_rule_id: Option<String>,

    // ── plugin extension bag ──────────────────────────────────────────────
    /// Arbitrary key-value data injected by [`Plugin::enrich`] before rules
    /// fire. Readable from GRL as `Request.Ext["key"]`.
    pub extensions: HashMap<String, String>,
}

impl RequestContext {
    // ── Plugin methods — callable from GRL via `FunctionRegistry` ──────────
    //
    // Pattern:
    //   1. Add a typed method here.
    //   2. Register a closure in `grl::registry::register_context_defaults`:
    //        registry.register("my_fn", |ctx, args| ctx.my_fn(args[0].as_str()));
    //   3. Use in GRL: `when my_fn(...) == true`

    /// Returns the number of request headers.
    /// GRL: `header_count() > 50`
    pub fn header_count(&self) -> i64 {
        self.headers.len() as i64
    }

    /// Returns `true` if the named header is present (case-insensitive).
    /// GRL: `has_header("x-api-key")`
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }

    /// Returns `true` if the request path has `prefix` as a leading component.
    /// GRL: `is_path_under("/admin")`
    pub fn is_path_under(&self, prefix: &str) -> bool {
        self.path.starts_with(prefix)
    }

    // ── Lifecycle ────────────────────────────────────────────────────────

    /// Construct a new context from raw proxy data.
    pub fn new(
        _request_id: String,
        _method: String,
        _path: String,
        _query: Option<String>,
        _client_ip: String,
        _headers: HashMap<String, String>,
        _body: Option<Vec<u8>>,
    ) -> Self {
        todo!("build RequestContext — resolve tier, extract session cookie, set timestamps")
    }
}
