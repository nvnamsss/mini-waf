# Old Rule Engine API Guide (`/rule/`)

This document describes the **"old" rule engine** located in `/home/namnv/git/mini-waf/rule/` — a simple, linear rule evaluator that serves as the baseline for performance comparisons against the new RETE-based engine in `crates/rule/`.

---

## Directory Structure

```
rule/
├── mod.rs           # Main module: RuleEvaluator, RequestContext, RuleMatch
├── types.rs         # Type definitions: RuleSet, Rule, RuleRaw, ConditionNode, MatchType, Action
├── condition.rs     # Condition evaluator: eval_node(), eval_leaf(), match_value()
└── loader.rs        # RuleLoader: load_from_path(), load_from_consul(), compile(), validate_regexes()
```

---

## Public API

### Exported Types & Structs

#### **`RuleEvaluator`** ← Main entry point
```rust
pub struct RuleEvaluator {
    ruleset: arc_swap::ArcSwap<RuleSet>,  // Atomic swap for hot-reload
}
```

**Methods:**
- `new(ruleset: Arc<RuleSet>) -> Self` — Create evaluator with initial ruleset
- `evaluate(ctx: &RequestContext, skip_rules: &[String]) -> Option<RuleMatch>` — Evaluate all rules, return first non-log match
- `update_ruleset(new_ruleset: Arc<RuleSet>)` — Hot-reload rules atomically

#### **`RuleSet`** ← Compiled rule collection
```rust
pub struct RuleSet {
    pub rules: Vec<Rule>,  // Sorted by priority ascending (lower number = higher precedence)
}
```

**Methods:**
- `rules_for_context<'a>(&'a self, _ctx: &RequestContext<'_>) -> impl Iterator<Item = &'a Rule>` — Iterate rules applicable to context

#### **`Rule`** ← Individual compiled rule
```rust
pub struct Rule {
    pub id:               String,           // Unique ID
    pub source:           String,           // "system" or custom source
    pub description:      String,           // Human-readable description
    pub enabled:          bool,             // Whether rule is active
    pub priority:         u32,              // Lower = higher precedence
    pub condition:        ConditionNode,    // AND/OR/Leaf tree
    pub action:           Action,           // Allow|Block|Challenge|RateLimit|Log
    pub risk_score_delta: i8,              // [-100, 100] risk adjustment
    pub response:         Option<ResponseConfig>,
    pub rate_limit:       Option<RateLimitRule>,
    pub challenge:        Option<ChallengeRule>,
    pub tier:             Option<String>,   // Scope: "global" or tier name
}
```

#### **`RuleMatch`** ← Result of evaluation
```rust
pub struct RuleMatch {
    pub rule_id:          String,  // Matched rule ID
    pub description:      String,  // Rule description
    pub action:           Action,  // What to do (Block, Challenge, etc.)
    pub risk_score_delta: i8,      // Risk contribution
    pub source:           String,  // Origin of rule
}
```

#### **`RequestContext<'a>`** ← Input for evaluation
```rust
pub struct RequestContext<'a> {
    pub ip:           &'a str,
    pub path:         &'a str,
    pub method:       &'a str,
    pub headers:      &'a http::HeaderMap,
    pub payload:      &'a [u8],                              // Request body
    pub cookies:      &'a std::collections::HashMap<String, String>,
    pub tier:         TierName,                              // Request tier (Global, CatchAll, etc.)
    pub session_id:   &'a str,
    pub device_fp:    &'a str,
    pub content_type: Option<&'a str>,
}
```

#### **`Action`** ← Rule outcome
```rust
pub enum Action {
    Allow,        // Pass request through
    Block,        // Reject with 403
    Challenge,    // Issue PoW/JS challenge
    RateLimit,    // Apply rate limit
    Log,          // Record match but continue evaluation
}
```

#### **`ConditionNode`** ← Boolean tree
```rust
pub enum ConditionNode {
    And(Vec<ConditionNode>),    // All children must match
    Or(Vec<ConditionNode>),     // Any child must match
    Leaf(ConditionLeaf),        // Atomic condition
}
```

#### **`ConditionLeaf`** ← Atomic condition
```rust
pub struct ConditionLeaf {
    pub field:          Field,           // What to match (Ip, Path, Header, Payload, etc.)
    pub match_type:     MatchType,       // How to match (Exact, Wildcard, Regex, Cidr, Presence, Absence)
    pub value:          String,          // Pattern or literal value
    pub header_name:    Option<String>,  // For Header field
    pub cookie_name:    Option<String>,  // For Cookie field
    pub case_sensitive: bool,            // Case sensitivity flag
    pub negate:         bool,            // Logical NOT if true
}
```

#### **`Field`** ← Request field to match
```rust
pub enum Field {
    Ip,           // Client IP
    Path,         // Request path/URI
    Header,       // HTTP header (name in header_name)
    Payload,      // Request body
    Cookie,       // HTTP cookie (name in cookie_name)
    Method,       // HTTP method (GET, POST, etc.)
    ContentType,  // Content-Type header
    SessionId,    // Application session ID
    DeviceFp,     // Device fingerprint
}
```

#### **`MatchType`** ← Matching algorithm
```rust
pub enum MatchType {
    Exact,      // String equality (case-sensitive or case-insensitive)
    Wildcard,   // Glob pattern (*, ?)
    Regex,      // Regular expression (with (?i) for case-insensitivity)
    Cidr,       // IP CIDR block match (192.168.0.0/16)
    Presence,   // Field exists (non-empty)
    Absence,    // Field absent or empty
}
```

### Error Types

```rust
pub enum RuleError {
    ParseError { file: String, source: serde_yaml::Error },
    IoError { file: String, source: std::io::Error },
    ValidationError { id: String, reason: String },
    DuplicateId(String),
    RegexError { id: String, source: regex::Error },
}
```

---

## Usage Example

### 1. Load Rules

```rust
use rule::loader::RuleLoader;
use std::path::Path;

// Load from YAML files in a directory
let ruleset = RuleLoader::load_from_path("rules/")?;
```

**Supported files:**
- `global.yaml` — Rules that apply to all tiers
- `critical.yaml` — Highest priority rules
- `high.yaml` — High priority rules
- `medium.yaml` — Medium priority rules
- `catch-all.yaml` — Lowest priority catch-all rules

### 2. Create Evaluator

```rust
use rule::RuleEvaluator;
use std::sync::Arc;

let evaluator = RuleEvaluator::new(ruleset);
```

### 3. Build Request Context

```rust
use rule::RequestContext;
use std::collections::HashMap;
use http::HeaderMap;
use crate::engine::tier::TierName;

let mut headers = HeaderMap::new();
headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());

let mut cookies = HashMap::new();
cookies.insert("session".to_string(), "abc123".to_string());

let ctx = RequestContext {
    ip: "192.168.1.100",
    path: "/api/users",
    method: "POST",
    headers: &headers,
    payload: b"{ \"name\": \"Alice\" }",
    cookies: &cookies,
    tier: TierName::CatchAll,
    session_id: "sess_xyz",
    device_fp: "fp_abc",
    content_type: Some("application/json"),
};
```

### 4. Evaluate

```rust
// Evaluate all rules
let skip_rules = vec![];  // Can skip specific rule IDs
let result = evaluator.evaluate(&ctx, &skip_rules);

match result {
    Some(matched) => {
        println!("Matched rule: {} ({})", matched.rule_id, matched.description);
        println!("Action: {:?}", matched.action);
        println!("Risk: {}", matched.risk_score_delta);
    }
    None => {
        println!("No rules matched");
    }
}
```

---

## Evaluation Flow

### Priority-Based Linear Evaluation

```
1. Load RuleSet (rules sorted by priority ascending)
   └─ Rules with priority=10 checked before priority=100

2. For each rule (in order):
   a. Skip if disabled
   b. Check if rule tier matches request tier
   c. Skip if rule_id in skip_rules list
   d. Evaluate ConditionNode tree:
      - Walk AND/OR nodes recursively
      - Evaluate Leaf conditions
      - Return bool result
   e. If condition matches:
      - If action == Log: Record and CONTINUE to next rule
      - Otherwise: Return RuleMatch (FIRST non-log match wins)
   
3. Return None if no rule matched
```

### Condition Evaluation (`condition.rs`)

**And logic:**
```rust
fn eval_node(ConditionNode::And(children), ctx) -> bool {
    children.iter().all(|c| eval_node(c, ctx))
}
```

**Or logic:**
```rust
fn eval_node(ConditionNode::Or(children), ctx) -> bool {
    children.iter().any(|c| eval_node(c, ctx))
}
```

**Leaf evaluation (`eval_leaf`):**
1. Extract field value from context (IP, path, headers, etc.)
2. Apply match_type (exact, wildcard, regex, CIDR, presence, absence)
3. Apply case_sensitive flag
4. Apply negate flag (NOT)

**Match operations:**
- **Exact:** String equality
- **Wildcard:** `globset::Glob` with `*` and `?`
- **Regex:** `regex::Regex::new()` with optional `(?i)` for case-insensitivity
- **CIDR:** IP address range matching (IPv4 and IPv6)
- **Presence:** Field exists and non-empty
- **Absence:** Field absent or empty

---

## Hot-Reloading (Consul Integration)

### RuleWatcher

```rust
pub struct RuleWatcher {
    consul_addr: String,
    client: reqwest::Client,
}

impl RuleWatcher {
    pub fn new(consul_addr: &str) -> Self { /* ... */ }
    
    pub fn spawn_watcher(
        self: Arc<Self>,
        evaluator: Arc<RuleEvaluator>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Polls Consul for rule changes every 60 seconds
            // Calls evaluator.update_ruleset() atomically on change
            // Uses arc_swap for zero-downtime hot-reload
        })
    }
}
```

### Load from Consul

```rust
let ruleset = RuleLoader::load_from_consul(&client, "http://localhost:8500").await?;
```

Expects rules at: `waf/rules/` (recursively loaded, all .yaml files decoded from base64)

---

## Configuration Requirements

### YAML Rule Format

```yaml
rules:
  - id: "rule-001"
    description: "Block SQL injection attempts"
    enabled: true
    priority: 10
    action: block
    risk_score_delta: 50
    tier: "global"  # optional: defaults to global
    condition:
      and:
        - field: method
          match: exact
          value: "POST"
        - field: payload
          match: regex
          value: "(?i)union\\s+select"
    response:
      status: 403
      body: "Request blocked"
    rate_limit:
      scope: per-ip
      window_seconds: 60
      max_requests: 100
    challenge:
      type: "pow"
      pow_difficulty: 20
```

### Tier System

Rules can target specific tiers:
```rust
pub enum TierName {
    Global,     // All requests
    CatchAll,   // Default tier
    // ... other tiers
}
```

If rule has `tier: "catchall"`, it only evaluates for CatchAll requests.

---

## Key Differences from New Engine (`crates/rule/`)

| Feature | Old Engine | New Engine |
|---------|-----------|-----------|
| **Evaluation** | Linear O(r×c) | RETE graph with memoization |
| **Regexes** | Per-rule regex compilation | Pre-compiled + cached |
| **Matching** | Native regex/glob | Aho-Corasick automata + trie |
| **Hot-reload** | `arc_swap::ArcSwap` | Atomic reference swapping |
| **Performance** | ~10-100 µs per request | ~2-5 µs per request |
| **Condition trees** | Full AND/OR/Leaf trees | Same structure, optimized evaluation |
| **API** | Same (wrapper layer) | Same (compatible interface) |

---

## Testing

Unit tests in `rule/mod.rs` and `rule/condition.rs`:

```rust
#[test]
fn test_rule_evaluator_skips_matched_rules() {
    // Tests skip_rules functionality
}

#[test]
fn exact_match_path() {
    // Tests exact path matching
}

#[test]
fn regex_match_payload() {
    // Tests regex patterns
}

#[test]
fn negate_works() {
    // Tests logical NOT
}
```

---

## Summary

**Old Rule Engine** is a **simple, sequential evaluator**:
- Load YAML rules from files or Consul
- Compile into sorted RuleSet (by priority)
- Evaluate rules in priority order (first match wins)
- Support for hot-reloading via Consul watches
- Clean, immutable API with `RequestContext` + `RuleEvaluator`

**Use for:**
- Baseline performance comparisons
- Understanding rule evaluation semantics
- Simple rule scenarios without heavy optimization requirements

**Performance characteristics:**
- O(r × c) where r = rules, c = conditions per rule
- Typical latency: 10-100 µs per request
- Suitable for small-to-medium rule sets (<1000 rules)
