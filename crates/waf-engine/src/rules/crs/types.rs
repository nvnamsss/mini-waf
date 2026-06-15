//! Core types for the CRS SecRule parser and evaluator.

use std::collections::HashSet;
use std::path::PathBuf;
use aho_corasick::AhoCorasick;
use regex::Regex;
use ipnet::IpNet;
use zentinel_modsec::ModSecurity;

/// A parsed `SecRule` directive.
#[derive(Debug)]
pub struct SecRule {
    pub id: u32,
    pub phase: u8,
    pub targets: Vec<CrsTarget>,
    pub operator: CrsOperator,
    /// True when the operator is negated (`!@rx ...`).
    pub negate_op: bool,
    pub transforms: Vec<CrsTransform>,
    pub actions: CrsActions,
    /// Per-target cache slot index, assigned at load time.
    /// `None` for TX targets (their values change as rules fire).
    pub cache_slot: Vec<Option<u16>>,
    /// True if any target in this rule requires the request body.
    /// When false, the rule is skipped entirely for bodyless requests.
    pub needs_body: bool,
}

/// CRS request variable targets we can extract from `RequestContext`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CrsTarget {
    Args,
    ArgsNames,
    RequestCookies,
    RequestCookiesNames,
    /// `None` = all headers (values); `Some(name)` = specific header.
    RequestHeaders(Option<String>),
    RequestUri,
    RequestUriRaw,
    RequestFilename,
    RequestBasename,
    RequestMethod,
    RequestBody,
    RequestLine,
    QueryString,
    RemoteAddr,
    /// `TX:VAR_NAME` — numeric value of a transaction variable.
    Tx(String),
    /// `&TX:VAR_NAME` — 1 if set/non-zero, 0 otherwise.
    TxCount(String),
    /// `&REQUEST_HEADERS:Name` — 1 if header present, 0 if absent.
    RequestHeadersCount(String),
    /// `&ARGS` — total number of request arguments (query + body).
    ArgsCount,
}

/// CRS operators (regex pre-compiled at load time).
#[derive(Debug)]
pub enum CrsOperator {
    Rx(Regex),
    /// Inline phrase list — compiled into an Aho-Corasick automaton at load time.
    Pm(AhoCorasick),
    /// External phrase file — key is filename; automaton looked up from `DataFiles`.
    PmFromFile(String),
    DetectSQLi,
    DetectXSS,
    Lt(i64),
    Le(i64),
    Gt(i64),
    Ge(i64),
    Eq(i64),
    /// Comparison against a TX variable (e.g. `@gt %{tx.arg_name_length}`).
    GtTxRef(String),
    GeTxRef(String),
    LtTxRef(String),
    LeTxRef(String),
    EqTxRef(String),
    Contains(String),
    Streq(String),
    Within(Vec<String>),
    BeginsWith(String),
    EndsWith(String),
    IpMatch(Vec<IpNet>),
    ValidateUrlEncoding,
    ValidateUtf8Encoding,
}

/// Value transformations applied before the operator is tested.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CrsTransform {
    Lowercase,
    UrlDecodeUni,
    RemoveNulls,
    Utf8ToUnicode,
    CompressWhitespace,
    NormalizePath,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    Base64Decode,
    Trim,
    RemoveWhitespace,
    ReplaceComments,
    /// Replace the value with its character length as a decimal string.
    Length,
    /// ModSecurity `escapeSeqDecode`: convert C-style escape sequences (\n, \r, \t, \xHH, \uHHHH).
    EscapeSeqDecode,
}

/// Parsed actions from a `SecRule` third-argument string.
#[derive(Debug, Default)]
pub struct CrsActions {
    pub skip_after: Option<String>,
    pub setvars: Vec<SetVarOp>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
    pub is_nolog: bool,
    pub default_action: DefaultAction,
    pub is_chain: bool,
    pub is_capture: bool,
    pub is_multi_match: bool,
}

/// What the rule does on a match (in anomaly-scoring mode, `Block` still just
/// increments the score; actual blocking is done by the GRL `crs_score()` rule).
#[derive(Debug, Clone, Default, PartialEq)]
pub enum DefaultAction {
    Block,
    #[default]
    Pass,
}

/// A single `setvar:'...'` operation.
#[derive(Debug, Clone)]
pub struct SetVarOp {
    /// Lowercase variable name (the `tx.` prefix is stripped during parsing).
    pub var: String,
    pub op: VarOp,
    pub rhs: SetVarRhs,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VarOp {
    Assign,
    IncrBy,
    DecrBy,
}

#[derive(Debug, Clone)]
pub enum SetVarRhs {
    Int(i64),
    /// Reference another TX variable by (lowercase) name.
    TxRef(String),
}

/// A chain of two or more rules that ALL must match before any actions fire.
/// Actions (`setvar`, `tag`) are collected from the head AND all members;
/// the `id:` and `phase:` always come from the head.
#[derive(Debug)]
pub struct ChainRule {
    /// Head rule: carries `id:`, `phase:`, control actions, and optional setvars/tags.
    pub head: SecRule,
    /// Continuation rules (no `id:`): must all match after the head.
    pub members: Vec<SecRule>,
}

/// One item produced by the parser: either a standalone rule, a chain, or a skip marker.
#[derive(Debug)]
pub enum RuleItem {
    Rule(SecRule),
    Chain(ChainRule),
    /// `SecMarker "NAME"` — jump target for `skipAfter` actions.
    Marker(String),
}

/// Phrase lists loaded from `.data` files (filename → phrases).
pub type DataFiles = std::collections::HashMap<String, Vec<String>>;

/// Aho-Corasick automata built from `.data` phrase lists (filename → automaton).
pub type DataAutomata = std::collections::HashMap<String, AhoCorasick>;

/// Result of running the CRS ruleset against one request.
#[derive(Debug, Default, Clone)]
pub struct CrsResult {
    /// Sum of `tx.inbound_anomaly_score_pl1..4`.
    pub inbound_score: i64,
    pub sql_injection_score: i64,
    pub xss_score: i64,
    pub lfi_score: i64,
    pub rce_score: i64,
    /// All `tag:` values from rules that fired.
    pub matched_tags: HashSet<String>,
    /// `id:` values of rules that fired.
    pub matched_rule_ids: Vec<u32>,
}

/// Runtime adapter state for the active CRS engine.
#[derive(Debug)]
pub struct CrsRuntime {
    pub modsec: ModSecurity,
    pub rule_tags: std::collections::HashMap<u32, Vec<String>>,
    pub source_dir: PathBuf,
}
