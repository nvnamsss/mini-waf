# Rule Engine — Architecture & Flow

mini-waf ships a custom **GRL rule engine** built on a RETE-style network.
It evaluates security rules against every inbound HTTP request and returns a typed decision (block / allow / challenge / rate-limit).

---

## High-Level Architecture

```
 config/rules/
 ├── *.grl          ←── hand-written GRL rules (detection.grl)
 ├── *.yaml         ←── YAML rules (auto-converted to GRL)
 └── crs/           ←── OWASP CRS .conf files (separate loader)

        │  at startup (AppState::init)
        ▼

 ┌─────────────────────────────────────────────────────────┐
 │                    Loader                               │
 │  load_grl_from_dir()                                    │
 │   .grl  → parse_grl()  → Vec<RuleAst>                  │
 │   .yaml → yaml_to_grl() → parse_grl() → Vec<RuleAst>  │
 └──────────────────────┬──────────────────────────────────┘
                        │ Vec<RuleAst>
                        ▼
 ┌──────────────────────────────────┐
 │         RETE Compilation         │
 │  Network::compile(rules)         │
 │  ┌──────────┐   ┌─────────────┐ │
 │  │ AlphaNode│   │  Terminal   │ │
 │  │ (expr)   │←──│ guard+acts  │ │
 │  └──────────┘   └─────────────┘ │
 └──────────────────────┬───────────┘
                        │ Network
                        ▼
 ┌──────────────────────────────────────────────────────────┐
 │                   Engine                                 │
 │  engine.install(BlacklistPlugin)                         │
 │  engine.install(CrsPlugin)       ← optional (crs_dir)   │
 │  engine.install(GeoPlugin)                               │
 │                                                          │
 │  FunctionRegistry                                        │
 │  ├── built-ins: contains_sqli, matches, starts_with, …  │
 │  ├── BlacklistPlugin: ip_in_blacklist()                  │
 │  ├── CrsPlugin:       crs_score()                        │
 │  └── GeoPlugin:       GetCountry(), geo_blocked()        │
 └──────────────────────────────────────────────────────────┘
```

---

## Per-Request Flow

```
Incoming HTTP request
        │
        ▼
 ┌─────────────────────┐
 │  RequestContext      │  method, path, query, body,
 │  (immutable fact)    │  headers, client_ip, …
 └────────┬────────────┘
          │
          ▼ engine.enrich(&mut ctx)
 ┌─────────────────────────────────────────┐
 │  Plugin Enrichment (in install order)   │
 │  GeoPlugin.enrich → ctx.extensions      │
 │    ["geo.country"] = "VN"               │
 └────────┬────────────────────────────────┘
          │
          ▼ engine.fire(&ctx)
 ┌──────────────────────────────────────────────────────┐
 │                RETE Firing Loop                      │
 │                                                      │
 │  for cycle in 0..MAX_CYCLES (16):                    │
 │    1. Evaluate all AlphaNodes against ctx+scratch    │
 │       alpha[0] = contains_sqli(Request.Query) → bool │
 │       alpha[1] = GetCountry() == "VN"         → bool │
 │       …                                              │
 │    2. Walk terminals in salience order (desc)        │
 │       for each Terminal not yet fired:               │
 │         if guard.eval(alphas) → fire!                │
 │           run then-statements:                       │
 │             Assign → write to scratch overlay        │
 │             Call   → block/allow/challenge/log →     │
 │                       write to Outcome               │
 │    3. If no new rules fired → quiesce, break         │
 └────────┬─────────────────────────────────────────────┘
          │ Outcome
          ▼
 ┌──────────────────────────────────────┐
 │  Decision                            │
 │  block_reason / allow / challenge /  │
 │  rate_limit_secs / matched_rules /   │
 │  risk_delta                          │
 └────────┬─────────────────────────────┘
          │
          ▼
 waf-proxy: respond 403 / forward / issue JS challenge
```

---

## Core Components

### 1. GRL Language (`crates/waf-engine/src/rules/grl/`)

Parsed by a **pest** grammar (`grl.pest`). A rule has three parts:

```grl
rule "BlockSqli" salience 900 {
    when  contains_sqli(Request.Query) || contains_sqli(Request.Body)
    then
        Request.RiskScore = Request.RiskScore + 80;
        block("sqli detected");
}
```

| Part | Purpose |
|------|---------|
| `salience` | Firing priority — higher fires first |
| `when` | Boolean guard over `Request.*` fields and registered functions |
| `then` | Statements: `Assign` (mutates scratch overlay) or `Call` (action function) |

**Built-in action functions**

| Function | Effect |
|----------|--------|
| `block("reason")` | Block request, emit 403 |
| `allow()` | Short-circuit, pass immediately |
| `challenge()` | Issue JS / PoW challenge |
| `rate_limit(secs)` | Apply sliding-window rate limit |
| `log("msg")` | Add message to audit log |

**Built-in predicate functions** (pure, no context):

`contains_sqli`, `contains_xss`, `contains_path_traversal`,
`contains_cmd_injection`, `contains_header_injection`,
`matches`, `contains`, `starts_with`, `ends_with`, `lower`, `upper`, `len`

---

### 2. RETE Network (`crates/waf-engine/src/rules/rete/`)

Compilation decomposes each `when` clause:

- **AlphaNode** — a single atomic condition expression (hash-consed; shared across rules)
- **Guard** — boolean DAG (`And` / `Or` / `Not` / `Alpha(id)`) over alpha indices
- **Terminal** — one per rule: `guard + salience + actions + rule_name`

At fire time: alpha truth-values are recomputed once per cycle, then all guards are evaluated cheaply as boolean DAG walks.

---

### 3. Working Memory (`working_memory.rs`)

Holds per-request mutable state:

| Field | Purpose |
|-------|---------|
| `fact` | Immutable `RequestContext` (the HTTP request) |
| `scratch` | Path→Value overlay for `Request.RiskScore` mutations |
| `registry` | Function registry (read-only reference) |
| `outcome` | Accumulates `block_reason`, `matched_rules`, `risk_delta`, … |

Path resolution: `scratch` overlay wins over live `fact` fields, so later rules see risk score mutations from earlier ones.

---

### 4. Plugin System (`crates/waf-engine/src/plugin.rs`)

A `Plugin` has two hooks:

```rust
trait Plugin {
    fn name(&self) -> &'static str;

    /// Called once at startup — registers GRL functions into the engine's
    /// FunctionRegistry so rules can call them.
    fn register(&self, registry: &mut FunctionRegistry);

    /// Called once per request before engine.fire() — pre-populates
    /// ctx.extensions so functions avoid redundant work during evaluation.
    fn enrich(&self, ctx: &mut RequestContext) {}
}
```

**Installed plugins (in order)**

| Plugin | Registered Functions | `enrich` side-effect |
|--------|---------------------|----------------------|
| `BlacklistPlugin` | `ip_in_blacklist()` | — |
| `CrsPlugin` | `crs_score()` | Computes CRS anomaly score, stores in `ctx.extensions` |
| `GeoPlugin` | `GetCountry()`, `GetCountry(ip)`, `geo_blocked()` | Resolves country → `ctx.extensions["geo.country"]` |

---

### 5. Rule Loading & Hot Reload (`crates/waf-engine/src/rules/loader.rs`, `watcher.rs`)

```
config/rules/*.grl   ─────────────────────────────────┐
config/rules/*.yaml  → yaml_to_grl() → parse_grl() → │ Vec<RuleAst>
                                                       │
                                              Network::compile()
                                                       │
                                         store.reload_engine(engine)
```

`watcher.rs` watches `config/rules/` with `notify`. On any file change it re-runs the full load → compile → install cycle **atomically** via an `ArcSwap<Engine>` inside `RuleStore`. In-flight requests see the old engine; the next request gets the new one.

---

## Writing a New Rule

### Option A — GRL (recommended for complex logic)

Add a `rule` block to `config/rules/detection.grl`:

```grl
rule "BlockBadBot" salience 700 {
    when matches(Request.Headers["User-Agent"], "(?i)badbot")
    then
        Request.RiskScore = Request.RiskScore + 60;
        block("bad bot");
}
```

The file is hot-reloaded; no restart needed.

### Option B — YAML (simple field-match rules)

Add an entry to any `config/rules/*.yaml` file:

```yaml
- id: block-bad-bot
  priority: 300                # lower = higher salience
  action: block
  risk_score_delta: 60
  condition:
    header_matches:
      name: User-Agent
      pattern: "(?i)badbot"
```

YAML rules are converted to GRL at load time via `yaml_to_grl()`.

### Option C — Plugin (requires Rust code)

For functions that need I/O or shared state (DB lookups, caches, external APIs):

1. Implement the `Plugin` trait.
2. Register a named function in `register()`.
3. Optionally pre-compute values in `enrich()` and store in `ctx.extensions`.
4. Install via `engine.install(MyPlugin::new(...))` in `AppState::init`.

```rust
// register
registry.register("is_tor_exit", move |ctx, _args| {
    Value::Bool(tor_list.contains(&ctx.client_ip))
});

// rule
rule "BlockTor" salience 850 {
    when is_tor_exit()
    then block("tor exit node");
}
```

---

## Request Fields Available in GRL

| GRL path | Type | Description |
|----------|------|-------------|
| `Request.Method` | `Str` | HTTP method (`GET`, `POST`, …) |
| `Request.Path` | `Str` | URL path |
| `Request.Query` | `Str` | Raw query string |
| `Request.Body` | `Str` | Request body (buffered) |
| `Request.Host` | `Str` | `Host` header value |
| `Request.ClientIp` | `Str` | Canonical client IP |
| `Request.RiskScore` | `Int` | Accumulator — mutate with `Assign` |
| `Request.Tier` | `Str` | Backend tier tag |
| `Request.Headers["X-Foo"]` | `Str` | Arbitrary header lookup |
| `Request.Ext["geo.country"]` | `Str` | Plugin-enriched extension fields |

---

## Performance Optimisations

Measured on Apple M4 Max (arm64), Rust 1.94.1 `--release`, 459 CRS rule items loaded.
See [benchmarks.md](benchmarks.md) for full numbers.

### RETE layer

| Technique | Where | Effect |
|---|---|---|
| **Alpha-node hash-consing** | `Network::compile` | Identical sub-expressions across rules compile to a single `AlphaNode`. Each unique condition is evaluated exactly once per cycle regardless of how many rules share it. |
| **Pre-compiled regex in alpha nodes** | `alpha.rs` / `CompiledAlpha` | `matches(field, "literal")` calls in GRL rules have their pattern compiled to a `Regex` at `Network::compile` time (stored as `Arc<Regex>`). At fire time it is a direct `re.is_match()` call — zero compile overhead per request. |
| **Salience-ordered terminal scan** | `Network::compile` | Terminals are sorted by salience descending once at compile time. The firing loop walks them in order and can stop early once an outcome is produced, skipping lower-priority rules entirely. |
| **Static `OnceLock<Regex>` for built-in detectors** | `grl/functions.rs` | `detect_sqli`, `detect_xss`, `detect_path_traversal`, `detect_header_injection` each hold a `static OnceLock<Regex>`. The pattern is compiled once on first call, never again. Benchmark: ~10–70 ns per call vs ~134 µs for an ad-hoc `matches()` with a complex pattern. |
| **Immutable `RequestContext` + scratch overlay** | `working_memory.rs` | The request is never cloned. A small `HashMap` scratch overlay records only mutations (`RiskScore` etc.). Alpha nodes read the original context directly — no copy per rule. |

### CRS evaluator layer

| Technique | Where | Effect |
|---|---|---|
| **Aho-Corasick automata for `@pm` / `@pmFromFile`** | `loader.rs` / `parser.rs` | Inline phrase lists and `.data` files are compiled to `AhoCorasick` automata at startup with `ascii_case_insensitive(true)`. One `ac.is_match(value)` call replaces an O(n×m) linear scan and eliminates the per-call `to_lowercase()` allocation. Benefit: −13% to −63% per-request cost depending on scenario. |
| **Body-skip for body-only rules** | `loader.rs` (`assign_needs_body`) | Rules whose every target is `REQUEST_BODY` are flagged `needs_body = true` at load time. When `ctx.body.is_none()` (GET requests) those rules are skipped with a single branch, cutting the active rule count significantly. Benefit: −56% on `sqli_body`, −63% on `xss_body` for bodyless requests. |
| **Per-request target value cache** | `loader.rs` (`assign_cache_slots`) / `evaluator.rs` | At load time every unique `(target, transform-chain)` pair is assigned a `u16` slot index. During evaluation the extracted+transformed string is computed once and stored in a `Vec<Option<Vec<String>>>`. Subsequent rules that share the same target/transform pair read the cached slot. TX variables are excluded (they mutate as rules fire). |
| **`skipAfter` / marker short-circuit** | `evaluator.rs` | When a rule fires with `skipAfter: MARKER` the evaluator advances the rule pointer past all items until the named `SecMarker`. This mirrors the CRS paranoia-level gate pattern — rules above the active PL are skipped in a single jump. Benefit: scanner UA scenario runs at near-clean speed (52 µs vs 91 µs clean) because REQUEST-913 fires early and skips the rest of the phase. |
| **Zero-copy transform chain** | `transform.rs` | `apply_transforms` returns `Cow::Borrowed(s)` when no transform is applied, avoiding any allocation. The first transform that actually changes the string upgrades to `Cow::Owned`; subsequent transforms operate in-place on the owned buffer. |
