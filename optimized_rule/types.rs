//! Rule type definitions — mirrors the YAML schema in docs/rules-spec.md exactly.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use regex::Regex;

use super::RequestContext;

// ─────────────────────────────────────────────────────────────────────────────
// Top-level rule file
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<RuleRaw>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw rule (deserialized from YAML)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleRaw {
    pub id:               String,
    #[serde(default)]
    pub description:      String,
    #[serde(default = "default_true")]
    pub enabled:          bool,
    pub priority:         u32,
    pub condition:        ConditionNode,
    pub action:           Action,
    #[serde(default)]
    pub risk_score_delta: i8,
    pub response:         Option<ResponseConfig>,
    pub rate_limit:       Option<RateLimitRule>,
    pub challenge:        Option<ChallengeRule>,

    // Target tier (optional, defaults to Global)
    pub tier:          Option<String>,

    // Source field (system or custom)
    pub source:        Option<String>,
}

fn default_true() -> bool { true }

// ─────────────────────────────────────────────────────────────────────────────
// Compiled rule (regexes pre-compiled)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Rule {
    pub id:               String,
    pub source:           String,
    pub description:      String,
    pub enabled:          bool,
    pub priority:         u32,
    pub condition:        ConditionNode,
    pub action:           Action,
    pub risk_score_delta: i8,
    pub response:         Option<ResponseConfig>,
    pub rate_limit:       Option<RateLimitRule>,
    pub challenge:        Option<ChallengeRule>,
    pub tier:             Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sorted, deduplicated rule set
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RuleSet {
    /// Rules sorted by priority ascending.
    pub rules: Vec<Rule>,
    /// Shared compiled regex cache to avoid recompilation and deduplicate patterns
    pub compiled_regexes: Arc<HashMap<String, Regex>>,
}

impl RuleSet {
    /// Return an iterator over rules applicable to this request context.
    /// (All rules — scope filtering is done in the evaluator.)
    pub fn rules_for_context<'a>(
        &'a self,
        _ctx: &RequestContext<'_>,
    ) -> impl Iterator<Item = &'a Rule> {
        self.rules.iter()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scope
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Actions
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
    Challenge,
    RateLimit,
    Log,
}

// ─────────────────────────────────────────────────────────────────────────────
// Condition tree
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionNode {
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    /// Leaf condition
    #[serde(untagged)]
    Leaf(ConditionLeaf),
}


#[derive(Debug, Clone, Deserialize)]
pub struct ConditionLeaf {
    pub field:          Field,
    #[serde(rename = "match")]
    pub match_type:     MatchType,
    pub value:          String,
    pub header_name:    Option<String>,
    pub cookie_name:    Option<String>,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub negate:         bool,
    /// Pre-compiled regex pattern (not serialized, populated at load time)
    /// This is a reference to the shared cache in RuleSet
    #[serde(skip)]
    pub compiled_regex_key: Option<String>,
}

// Manual Serialize impl since we skip the regex key
impl Serialize for ConditionLeaf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ConditionLeaf", 7)?;
        state.serialize_field("field", &self.field)?;
        state.serialize_field("match", &self.match_type)?;
        state.serialize_field("value", &self.value)?;
        state.serialize_field("header_name", &self.header_name)?;
        state.serialize_field("cookie_name", &self.cookie_name)?;
        state.serialize_field("case_sensitive", &self.case_sensitive)?;
        state.serialize_field("negate", &self.negate)?;
        state.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Ip,
    #[serde(alias = "uri")]
    Path,
    Header,
    #[serde(alias = "body")]
    Payload,
    Cookie,
    Method,
    ContentType,
    SessionId,
    DeviceFp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    Exact,
    Wildcard,
    Regex,
    Cidr,
    Presence,
    Absence,
}

// ─────────────────────────────────────────────────────────────────────────────
// Ancillary rule configs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseConfig {
    #[serde(default = "default_403")]
    pub status:  u16,
    pub body:    Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

fn default_403() -> u16 { 403 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitRule {
    pub scope:          RateLimitScope,
    pub window_seconds: u64,
    pub max_requests:   u64,
    pub burst_tokens:   u64,
    pub on_breach:      crate::config::types::BreachAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitScope {
    PerIp,
    PerSession,
    PerApiKey,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeRule {
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    pub pow_difficulty: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeType {
    Js,
    Pow,
}
