//! engine-demo — standalone rule engine demo.
//!
//! Edit the DEMO CONFIG block in `main()` and re-run:
//!   cargo run -p waf-engine --bin engine-demo

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use waf_engine::{
    context::RequestContext,
    geo::GeoPlugin,
    lists::{blacklist_plugin::BlacklistPlugin, ip_list::IpListStore},
    rules::{
        crs::{CrsPlugin, CrsRuleset},
        loader::load_grl_from_dir,
        rete::{engine::Engine, working_memory::Outcome, Network},
    },
};
use waf_types::{risk::RiskScore, tier::Tier};

const BOLD:   &str = "\x1b[1m";
const RESET:  &str = "\x1b[0m";
const RED:    &str = "\x1b[31m";
const GREEN:  &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN:   &str = "\x1b[36m";
const DIM:    &str = "\x1b[2m";

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_target(false)
        .init();

    // ═══════════════════════════════════════════════════════════════════
    //  DEMO CONFIG — uncomment one scenario, then:
    //    cargo run -p waf-engine --bin engine-demo
    // ═══════════════════════════════════════════════════════════════════

    let rules_dir: PathBuf = "config/rules".into();
    let crs_dir:   Option<PathBuf> = Some("config/rules/crs".into());

    // ── Scenario 1: Clean request (PASS) ─────────────────────────────
    // let method    = "GET";
    // let path      = "/api/users";
    // let query:    Option<&str> = None;
    // let body:     Option<&str> = None;
    // let client_ip = "127.0.0.1";
    // let raw_headers: &[(&str, &str)] = &[];

    // ── Scenario DIAG: Clean GET /health with browser headers ────────
    let method    = "GET";
    let path      = "/health";
    let query:    Option<&str> = None;
    let body:     Option<&str> = None;
    let client_ip = "127.0.0.1";
    let raw_headers: &[(&str, &str)] = &[
        ("host", "127.0.0.1:8111"),
        ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("accept-language", "en-US,en;q=0.5"),
        ("connection", "keep-alive"),
    ];

    // ── Scenario 3: XSS in POST body ─────────────────────────────────
    // let method    = "POST";
    // let path      = "/comment";
    // let query:    Option<&str> = None;
    // let body:     Option<&str> = Some("<script>alert(document.cookie)</script>");
    // let client_ip = "127.0.0.1";
    // let raw_headers: &[(&str, &str)] = &[];

    // ── Scenario 4: Path traversal ───────────────────────────────────
    // let method    = "GET";
    // let path      = "/../../etc/passwd";
    // let query:    Option<&str> = None;
    // let body:     Option<&str> = None;
    // let client_ip = "127.0.0.1";
    // let raw_headers: &[(&str, &str)] = &[];

    // ── Scenario 5: SSRF via metadata endpoint ───────────────────────
    // let method    = "POST";
    // let path      = "/fetch";
    // let query:    Option<&str> = None;
    // let body:     Option<&str> = Some("url=http://169.254.169.254/latest/meta-data/");
    // let client_ip = "127.0.0.1";
    // let raw_headers: &[(&str, &str)] = &[];

    // ── Scenario 6: Geo block — Vietnam ──────────────────────────────
    // let method    = "GET";
    // let path      = "/api/checkout";
    // let query:    Option<&str> = None;
    // let body:     Option<&str> = None;
    // let client_ip = "127.0.0.1";
    // let raw_headers: &[(&str, &str)] = &[("CF-IPCountry", "VN")];

    // ── Scenario 7: Scanner user-agent ───────────────────────────────
    // let method    = "GET";
    // let path      = "/";
    // let query:    Option<&str> = None;
    // let body:     Option<&str> = None;
    // let client_ip = "127.0.0.1";
    // let raw_headers: &[(&str, &str)] = &[("User-Agent", "Nikto/2.1.6")];

    // ── Scenario 8: Canary / honeypot endpoint ───────────────────────
    // let method    = "GET";
    // let path      = "/admin-test";
    // let query:    Option<&str> = None;
    // let body:     Option<&str> = None;
    // let client_ip = "10.0.0.1";
    // let raw_headers: &[(&str, &str)] = &[];

    // ── Hot-reload simulation ─────────────────────────────────────────
    // When true: fires the engine twice — first with the loaded rule set,
    // then again after swapping in an empty network (zero rules).
    // Demonstrates the atomic rule-store swap done by the watcher thread.
    let hot_reload: bool = true;

    // ═══════════════════════════════════════════════════════════════════

    let mut headers: HashMap<String, String> = HashMap::new();
    for (name, value) in raw_headers {
        headers.insert(name.to_lowercase(), value.to_string());
    }

    let mut ctx = RequestContext {
        request_id:      uuid::Uuid::new_v4().to_string(),
        arrived_at_ms:   chrono::Utc::now().timestamp_millis(),
        method:          method.to_uppercase(),
        path:            path.to_string(),
        query:           query.map(|s| s.to_string()),
        tier:            Tier::CatchAll,
        client_ip:       client_ip.to_string(),
        xff_header:      headers.get("x-forwarded-for").cloned(),
        headers,
        body:            body.map(|b| b.as_bytes().to_vec()),
        session_id:      None,
        device_fp:       None,
        risk_score:      RiskScore(0),
        matched_rule_id: None,
        extensions:      HashMap::new(),
    };

    println!();
    println!("{BOLD}{CYAN}  mini-waf  ·  Rule Engine Demo{RESET}");
    println!("{DIM}  ─────────────────────────────────────────{RESET}");

    let grl_rules = load_grl_from_dir(&rules_dir)?;
    println!("  {DIM}rules dir   :{RESET}  {rules_dir:?}");
    println!("  {DIM}rules loaded:{RESET}  {}", grl_rules.len());

    let net = Network::compile(grl_rules);
    println!("  {DIM}alpha nodes :{RESET}  {}", net.alpha_count());
    println!("  {DIM}terminals   :{RESET}  {}", net.rule_count());

    let mut engine = Engine::new(net);
    engine.install(BlacklistPlugin::new(Arc::new(IpListStore::new())));

    if let Some(ref dir) = crs_dir {
        let data_dir = rules_dir.join("data");
        match CrsRuleset::load_from_dir(dir, &data_dir) {
            Ok(rs) => {
                println!("  {DIM}crs dir     :{RESET}  {dir:?}  {GREEN}✓ loaded{RESET}  ({} items)", rs.len());
                engine.install(CrsPlugin::new(Arc::new(rs)));
            }
            Err(e) => eprintln!(
                "  {YELLOW}warn:{RESET} could not load CRS ({e}) — crs_score() returns 0"
            ),
        }
    }

    engine.install(GeoPlugin::new(None, vec![], vec![]));
    println!("{DIM}  ─────────────────────────────────────────{RESET}");

    engine.enrich(&mut ctx);
    let outcomes: Vec<(&str, Outcome)> = if hot_reload {
        let o1 = engine.fire(&ctx);
        // Simulate the atomic network swap the watcher thread performs via
        // RuleStore::reload_engine — same engine, same plugins, only the
        // compiled RETE network is replaced (here with an empty one).
        engine.network = Network::default();
        let o2 = engine.fire(&ctx);
        vec![
            ("Pass 1 — full rule set  (before reload)", o1),
            ("Pass 2 — empty rule set (after  reload)", o2),
        ]
    } else {
        vec![("(single fire)", engine.fire(&ctx))]
    };

    println!();
    println!("{BOLD}  Request{RESET}");
    println!("    method  : {BOLD}{}{RESET}", ctx.method);
    println!("    path    : {}", ctx.path);
    if let Some(q) = &ctx.query {
        println!("    query   : {YELLOW}{q}{RESET}");
    }
    if let Some(b) = body {
        let preview = if b.len() > 80 { &b[..80] } else { b };
        println!("    body    : {YELLOW}{preview}{RESET}");
    }
    println!("    ip      : {}", ctx.client_ip);
    for (k, v) in &ctx.headers {
        println!("    header  : {k}: {v}");
    }
    if let Some(country) = ctx.extensions.get("geo.country") {
        if !country.is_empty() {
            println!("    country : {CYAN}{country}{RESET}");
        }
    }

    for (label, outcome) in &outcomes {
        if hot_reload {
            println!();
            println!("{DIM}  ─────────────────────────────────────────{RESET}");
            println!("{BOLD}{CYAN}  {label}{RESET}");
        }

        println!();
        if outcome.matched_rules.is_empty() {
            println!("{BOLD}  Matched rules{RESET}  {DIM}(none){RESET}");
        } else {
            println!("{BOLD}  Matched rules{RESET}");
            for rule in &outcome.matched_rules {
                println!("    {YELLOW}⚡ {rule}{RESET}");
            }
        }

        println!();
        println!("{BOLD}  Decision{RESET}");
        if let Some(ref reason) = outcome.block_reason {
            println!("    {BOLD}{RED}🚫  BLOCK{RESET}  ← {reason}");
        } else if outcome.allow {
            println!("    {BOLD}{GREEN}✅  ALLOW  (explicit){RESET}");
        } else if outcome.challenge.is_some() {
            println!("    {BOLD}{YELLOW}🔒  CHALLENGE{RESET}");
        } else if let Some(secs) = outcome.rate_limit_secs {
            println!("    {BOLD}{YELLOW}⏱   RATE LIMIT  ({secs}s){RESET}");
        } else {
            println!("    {BOLD}{GREEN}✅  PASS{RESET}");
        }
        println!("    risk delta  : {}{}{RESET}",
            if outcome.risk_delta > 0 { RED } else { GREEN },
            outcome.risk_delta,
        );

        if !outcome.log_messages.is_empty() {
            println!();
            println!("{BOLD}  Log messages{RESET}");
            for msg in &outcome.log_messages {
                println!("    {DIM}{msg}{RESET}");
            }
        }
    }

    println!();
    Ok(())
}
