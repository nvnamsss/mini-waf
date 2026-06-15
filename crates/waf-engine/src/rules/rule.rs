use serde::{Deserialize, Serialize};

use waf_types::tier::Tier;

/// A single rule loaded from a YAML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    /// Lower numbers take precedence.
    pub priority: u32,
    pub scope: RuleScope,
    pub condition: Condition,
    pub action: RuleAction,
    /// Positive = increase risk score; negative = decrease.
    pub risk_score_delta: i32,
    /// If set, routes matching requests to this named backend (key in `[backends]` config).
    #[serde(default)]
    pub upstream_backend: Option<String>,
}

/// Where the rule applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    Global,
    Tier(Tier),
    RoutePattern(String),
    Ip(String),
    Session(String),
    DeviceFingerprint(String),
}

/// Condition tree that must evaluate to `true` for the rule to fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    // ── leaf match conditions ─────────────────────────────────────────────
    IpExact { value: String },
    IpInBlacklist,
    IpInWhitelist,
    PathExact { value: String },
    PathWildcard { pattern: String },
    PathRegex { pattern: String },
    HeaderExact { name: String, value: String },
    HeaderRegex { name: String, pattern: String },
    PayloadRegex { pattern: String },
    CookieExact { name: String, value: String },
    RateLimitExceeded,
    SqliPattern,
    XssPattern,
    PathTraversalPattern,
    SsrfPattern,
    HeaderInjectionPattern,

    // ── logical combinators ───────────────────────────────────────────────
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
}

/// Action the WAF takes when the condition matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
    Challenge,
    RateLimit,
    Log,
}
