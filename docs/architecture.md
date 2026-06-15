# Architecture

```mermaid
flowchart LR
    Client(["🌐 Internet / Client"])
    Proxy["**waf-proxy**\nReverse proxy\nCircuit breaker"]
    Engine["**waf-engine**\nRule engine · Detectors\nRisk scorer · Rate limit\nFingerprint · Cache"]
    Backend(["🖥️ Backend App"])
    API["**waf-api**\nREST + WebSocket\nHot config"]
    Dashboard["**dashboard**\nNode.js / TS\nLive feed · Charts"]
    Config[("📄 Config\nwaf.toml\nrules/*.yaml")]
    AuditLog[("📝 Audit Log\nNDJSON")]

    Client -->|HTTP request| Proxy
    Proxy -->|inspected request| Backend
    Backend -->|response| Proxy
    Proxy -->|filtered response| Client

    Proxy <-->|run pipeline| Engine
    Engine -->|write entry| AuditLog
    Engine <-->|load / hot-reload| Config

    API <-->|read/write state| Engine
    API -->|stream entries| Dashboard
    Dashboard -->|patch config & rules| API
```

## Nodes

| Node | Crate / Component | Role |
|------|-------------------|------|
| Internet / Client | — | Inbound HTTP traffic |
| **waf-proxy** | `crates/waf-proxy` | Accepts connections, forwards to backend, applies decisions; circuit breaker for upstream |
| **waf-engine** | `crates/waf-engine` | Rule matching, all detectors (SQLi, XSS, …), risk scoring, rate limiting, device fingerprinting, response filtering, cache |
| Backend App | — | Protected upstream; zero awareness of the WAF |
| **waf-api** | `crates/waf-api` | axum REST + WebSocket; exposes live feed and hot-config endpoints |
| **Dashboard** | `dashboard/` | Node.js / TypeScript UI — live request feed, attack charts, hot config panel |
| Config | `config/waf.toml` + `config/rules/*.yaml` | All runtime configuration; hot-reloaded by the engine via filesystem watcher |
| Audit Log | `logs/audit.jsonl` | Append-only NDJSON written by the engine after every request; SIEM-ingestible |

---

## Crate Dependency Graph

```
waf  (binary)
 ├── waf-proxy   ──► waf-engine ──► waf-types
 ├── waf-engine  ──► waf-types
 └── waf-api     ──► waf-engine
```

`waf-types` owns the shared primitives (`Decision`, `RiskScore`, `AuditEntry`, `Tier`).  
`waf-engine` owns all logic: rule loading, RETE compilation, pipeline execution, stores, plugins.  
`waf-proxy` and `waf-api` are thin servers that call into `waf-engine`.  
`waf` is the entry-point binary: loads config, initialises `AppState`, `tokio::try_join!`s both servers.

---

## Inbound Request Pipeline

```mermaid
sequenceDiagram
    participant C  as Client
    participant P  as waf-proxy<br/>handler.rs
    participant PL as waf-engine<br/>pipeline.rs
    participant E  as waf-engine<br/>engine.rs (RETE)
    participant U  as Upstream Backend

    C->>P: HTTP request (TCP)
    P->>P: extract method / path / query<br/>headers / body bytes
    P->>P: build RequestContext<br/>(tier, client_ip, risk_score=0)
    P->>PL: run_inbound(&mut ctx, &state)
    PL->>PL: plugins.enrich(&ctx)<br/>(e.g. BlacklistPlugin sets ctx.extensions)
    PL->>E: engine.fire(&ctx)

    loop up to 16 agenda cycles
        E->>E: evaluate all AlphaNodes → Vec<bool>
        E->>E: scan Terminals (salience desc)
        E->>E: first matching unfired Terminal:<br/>execute Stmt actions
        note over E: block / allow / challenge /<br/>rate_limit / log / assign
    end

    E-->>PL: Outcome
    PL->>PL: apply risk_delta to ctx.risk_score<br/>copy first matched_rule_id
    PL-->>P: Decision

    alt Decision::Allow
        P->>P: resolve_upstream() via routing rules
        P->>U: forward request (hyper)
        U-->>P: upstream response
        P-->>C: proxied response
    else Decision::Block
        P-->>C: 403 JSON
    else Decision::Challenge
        P-->>C: 403 JSON (challenge)
    else Decision::RateLimit
        P-->>C: 429 + Retry-After header
    end
```

---

## Rule Loading & RETE Compilation

```mermaid
flowchart TD
    A["AppState::init(config)"]

    subgraph load["Rule Loading  (loader.rs)"]
        B["scan config/rules/*.yaml + *.grl"]
        C1["YAML file\nyaml_to_grl() → GRL text"]
        C2["GRL file\n(used as-is)"]
        D["parse_grl() → Vec&lt;RuleAst&gt;"]
    end

    subgraph compile["RETE Compilation  (rete/mod.rs)"]
        E["Network::compile(rule_asts)"]
        F["walk each rule's when-expr\nleaf exprs → AlphaNode (hash-consed)\n&&/||/! → Guard combinators"]
        G["sort Terminals by salience desc\n= 1000 − priority"]
        H["Network { alphas, terminals }"]
    end

    subgraph engine["Engine Assembly  (engine.rs)"]
        I["Engine::new(network)"]
        J["install plugins\n(BlacklistPlugin + custom)"]
        K["Plugin::register(registry)\nadds GRL functions"]
        L["Arc&lt;Engine&gt; stored in RuleStore"]
    end

    subgraph hot["Hot-Reload  (watcher.rs)"]
        M["notify watcher\nwatches config/rules/"]
        N["FS change detected"]
        O["re-run load + compile"]
        P["store.reload_engine(new_engine)\n(atomic Arc swap)"]
    end

    A --> B
    B --> C1 & C2
    C1 & C2 --> D
    D --> E
    E --> F --> G --> H
    H --> I --> J --> K --> L

    M --> N --> O --> P
```

---

## RETE Engine Evaluation Detail

The engine (`waf-engine/src/rules/rete/engine.rs`) runs a **forward-chaining RETE loop** over the compiled network:

```mermaid
flowchart TD
    Start(["engine.fire(&ctx)"])
    WM["build WorkingMemory\n(fact=ctx, scratch={}, outcome=Allow)"]
    AlphaEval["evaluate every AlphaNode\n(call expr tree on WorkingMemory)\n→ alphas: Vec&lt;bool&gt;"]
    Scan["scan Terminals in salience order\n(highest priority first)"]
    Match{"Guard::eval(&alphas)\n&& !already_fired?"}
    Fire["mark terminal fired\nexecute Stmt actions:
    • block(rule_id)
    • allow()
    • challenge('js'|'captcha')
    • rate_limit(secs)
    • log(rule_id)
    • assign ctx.ext[key] = val
    • RiskScore += delta"]
    Continue{"action == block\nor quiescent?"}
    End(["return Outcome"])

    Start --> WM --> AlphaEval --> Scan --> Match
    Match -- yes --> Fire --> Continue
    Match -- no next terminal --> Continue
    Continue -- no --> AlphaEval
    Continue -- yes --> End
```

**AlphaNode evaluation** calls `WorkingMemory::resolve_path()` which maps GRL path segments to `RequestContext` fields:

| GRL path | `RequestContext` field |
|---|---|
| `Request.Method` | `ctx.method` |
| `Request.Path` | `ctx.path` (URL-decoded) |
| `Request.Body` | `ctx.body` (UTF-8 lossy) |
| `Request.ClientIp` | `ctx.client_ip` |
| `Request.Headers["name"]` | `ctx.headers` lookup |
| `Request.Ext["key"]` | `ctx.extensions` lookup |
| `Request.RiskScore` | `ctx.risk_score.0` |

**Built-in GRL functions** (`functions.rs`):

| Function | Purpose |
|---|---|
| `matches(s, pattern)` | regex match |
| `contains(s, sub)` | substring check |
| `starts_with` / `ends_with` | string predicates |
| `lower` / `upper` / `len` | string utils |
| `contains_sqli(s)` | SQLi regex detector |
| `contains_xss(s)` | XSS regex detector |
| `contains_path_traversal(s)` | path traversal detector |
| `contains_cmd_injection(s)` | command injection detector |
| `contains_header_injection(s)` | CRLF injection detector |

Plugin-registered functions (`BlacklistPlugin`):

| Function | Source |
|---|---|
| `ip_in_blacklist(ip)` | `IpListStore` (CIDR-aware) |
| `ip_in_whitelist(ip)` | `IpListStore` (CIDR-aware) |

---

## Rule YAML → GRL → RETE (Example)

Given `config/rules/critical.yaml`:
```yaml
- id: SQLI-001
  priority: 1
  scope: Global
  condition:
    SqliPattern:
      field: body
  action: Block
  risk_score_delta: 50
```

**Step 1 — `yaml_to_grl()` converts to GRL text:**
```
rule "SQLI-001" salience 999 {
    when
        contains_sqli(Request.Body)
    then
        Request.RiskScore = Request.RiskScore + 50;
        block("SQLI-001");
}
```

**Step 2 — `parse_grl()` produces a `RuleAst`** with:
- `when: Expr::Call { name: "contains_sqli", args: [Expr::Path("Request.Body")] }`
- `then: [Stmt::Assign(RiskScore, ...), Stmt::Call("block", ["SQLI-001"])]`

**Step 3 — `Network::compile()` produces:**
- One `AlphaNode` for `contains_sqli(Request.Body)` (hash-consed by canonical expr string)
- One `Terminal { salience: 999, guard: Guard::Alpha(id0), actions: [...] }`

**Step 4 — at request time**, `AlphaNode` calls `contains_sqli(ctx.body)` → `true` → `Guard::Alpha(id0)` → terminal fires → `block("SQLI-001")` → `Decision::Block`.

---

## Plugin System

```mermaid
classDiagram
    class Plugin {
        <<trait>>
        +register(registry: &mut FunctionRegistry)
        +enrich(ctx: &mut RequestContext)
    }
    class BlacklistPlugin {
        -store: Arc~IpListStore~
        +register() registers ip_in_blacklist, ip_in_whitelist
        +enrich()   sets ctx.extensions["blacklisted"|"whitelisted"]
    }
    class FunctionRegistry {
        -fns: HashMap~String, Fn~
        +call(name, ctx, args) Value
    }
    class Engine {
        -network: Network
        -registry: FunctionRegistry
        -plugins: Vec~Box~dyn Plugin~~
        +fire(ctx) Outcome
    }

    Plugin <|-- BlacklistPlugin
    Engine --> FunctionRegistry
    Engine --> Plugin
    BlacklistPlugin --> FunctionRegistry : registers into
```

New detectors can be added without touching the RETE core: implement `Plugin`, call `engine.install(plugin)` in `AppState::init`.
