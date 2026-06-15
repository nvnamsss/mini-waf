//! Criterion benchmarks for the RETE rule engine.
//!
//! Run with:
//!   cargo bench -p waf-engine
//!
//! Or a single group:
//!   cargo bench -p waf-engine -- compile
//!   cargo bench -p waf-engine -- fire

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use waf_engine::{
    context::RequestContext,
    geo::GeoPlugin,
    lists::{blacklist_plugin::BlacklistPlugin, ip_list::IpListStore},
    rules::{
        crs::{CrsPlugin, CrsRuleset},
        loader::load_grl_from_dir,
        rete::{engine::Engine, Network},
    },
};
use waf_types::{risk::RiskScore, tier::Tier};

// ── helpers ───────────────────────────────────────────────────────────────────

fn rules_dir() -> PathBuf {
    // Benchmarks run from the crate root; config/ is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/rules")
}

fn build_engine() -> Engine {
    let base = rules_dir();
    let rules = load_grl_from_dir(&base).expect("load rules");
    let net = Network::compile(rules);
    let mut engine = Engine::new(net);
    engine.install(BlacklistPlugin::new(Arc::new(IpListStore::new())));
    engine.install(GeoPlugin::new(None, vec![], vec![]));
    if let Ok(rs) = CrsRuleset::load_from_dir(&base.join("crs"), &base.join("data")) {
        engine.install(CrsPlugin::new(Arc::new(rs)));
    }
    engine
}

/// Same engine but with the `CrsBlock` rule stripped from the network,
/// so `crs_score()` is never looked up during evaluation.
fn build_engine_no_crs() -> Engine {
    let rules = load_grl_from_dir(&rules_dir())
        .expect("load rules")
        .into_iter()
        .filter(|r| r.name != "CrsBlock")
        .collect::<Vec<_>>();
    let net = Network::compile(rules);
    let mut engine = Engine::new(net);
    engine.install(BlacklistPlugin::new(Arc::new(IpListStore::new())));
    engine.install(GeoPlugin::new(None, vec![], vec![]));
    engine
}

fn make_ctx(method: &str, path: &str, query: Option<&str>, headers: &[(&str, &str)]) -> RequestContext {
    let mut hmap = HashMap::new();
    for (k, v) in headers {
        hmap.insert(k.to_lowercase(), v.to_string());
    }
    RequestContext {
        request_id:      "bench-req".to_string(),
        arrived_at_ms:   0,
        method:          method.to_string(),
        path:            path.to_string(),
        query:           query.map(|s| s.to_string()),
        tier:            Tier::CatchAll,
        client_ip:       "127.0.0.1".to_string(),
        xff_header:      None,
        headers:         hmap,
        body:            None,
        session_id:      None,
        device_fp:       None,
        risk_score:      RiskScore(0),
        matched_rule_id: None,
        extensions:      HashMap::new(),
    }
}

// ── bench: Network::compile (knowledge-base build) ────────────────────────────

fn bench_compile(c: &mut Criterion) {
    // Load GRL sources once; the benchmark times only the RETE compilation.
    let rules = load_grl_from_dir(&rules_dir()).expect("load rules");
    let rule_count = rules.len();

    let mut group = c.benchmark_group("compile");
    // Compilation is O(rules²) α-node dedup — keep sample count low so the
    // suite finishes quickly even when the rule set grows.
    group.sample_size(20).measurement_time(Duration::from_secs(10));

    group.bench_function(
        format!("{rule_count}_rules"),
        |b| {
            b.iter(|| black_box(Network::compile(rules.clone())))
        },
    );
    group.finish();
}

// ── bench: Engine::fire per request scenario ──────────────────────────────────

fn bench_fire(c: &mut Criterion) {
    let engine = build_engine();

    // Pre-enrich a clean context (geo/blacklist enrichment happens once per req).
    let mut clean = make_ctx("GET", "/api/users", None, &[]);
    engine.enrich(&mut clean);

    let mut sqli = make_ctx("GET", "/search", Some("q=1' OR 1=1--"), &[]);
    engine.enrich(&mut sqli);

    let mut xss = make_ctx("POST", "/comment", None, &[]);
    xss.body = Some(b"<script>alert(document.cookie)</script>".to_vec());
    engine.enrich(&mut xss);

    let mut traversal = make_ctx("GET", "/../../etc/passwd", None, &[]);
    engine.enrich(&mut traversal);

    let mut scanner = make_ctx("GET", "/", None, &[("user-agent", "Nikto/2.1.6")]);
    engine.enrich(&mut scanner);

    let mut geo_vn = make_ctx("GET", "/api/checkout", None, &[("cf-ipcountry", "VN")]);
    engine.enrich(&mut geo_vn);

    let scenarios: &[(&str, &RequestContext)] = &[
        ("clean",     &clean),
        ("sqli",      &sqli),
        ("xss",       &xss),
        ("traversal", &traversal),
        ("scanner",   &scanner),
        ("geo_vn",    &geo_vn),
    ];

    let mut group = c.benchmark_group("fire");
    for (name, ctx) in scenarios {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            ctx,
            |b, ctx| b.iter(|| black_box(engine.fire(ctx))),
        );
    }
    group.finish();
}

// ── bench: enrich (plugin pre-processing per request) ─────────────────────────

fn bench_enrich(c: &mut Criterion) {
    let engine = build_engine();

    let ctx_template = make_ctx("GET", "/api/users", None, &[("cf-ipcountry", "US")]);

    c.bench_function("enrich/with_geo_header", |b| {
        b.iter(|| {
            let mut ctx = ctx_template.clone();
            engine.enrich(&mut ctx);
            black_box(ctx)
        })
    });
}

// ── bench: full pipeline (enrich + fire) ──────────────────────────────────────

fn bench_full_pipeline(c: &mut Criterion) {
    let engine = build_engine();

    let mut group = c.benchmark_group("pipeline");

    // Clean request — best-case latency.
    group.bench_function("clean", |b| {
        b.iter(|| {
            let mut ctx = make_ctx("GET", "/api/users", None, &[]);
            engine.enrich(&mut ctx);
            black_box(engine.fire(&ctx))
        })
    });

    // Worst-case: SQLi that matches early (salience 900+) — BLOCK path.
    group.bench_function("sqli_block", |b| {
        b.iter(|| {
            let mut ctx = make_ctx("GET", "/search", Some("q=1' OR 1=1--"), &[]);
            engine.enrich(&mut ctx);
            black_box(engine.fire(&ctx))
        })
    });

    group.finish();
}

// ── bench: no-CRS variants for direct comparison ─────────────────────────────
//
// These mirror `bench_fire` and `bench_full_pipeline` but use an engine
// compiled without the `CrsBlock` rule, so `crs_score()` is never evaluated.
// Diff vs the CRS-present runs shows the overhead of having that single
// high-salience rule in the network.

fn bench_fire_no_crs(c: &mut Criterion) {
    let engine = build_engine_no_crs();

    let mut clean = make_ctx("GET", "/api/users", None, &[]);
    engine.enrich(&mut clean);
    let mut sqli = make_ctx("GET", "/search", Some("q=1' OR 1=1--"), &[]);
    engine.enrich(&mut sqli);
    let mut scanner = make_ctx("GET", "/", None, &[("user-agent", "Nikto/2.1.6")]);
    engine.enrich(&mut scanner);

    let scenarios: &[(&str, &RequestContext)] = &[
        ("clean",   &clean),
        ("sqli",    &sqli),
        ("scanner", &scanner),
    ];

    let mut group = c.benchmark_group("fire_no_crs");
    for (name, ctx) in scenarios {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            ctx,
            |b, ctx| b.iter(|| black_box(engine.fire(ctx))),
        );
    }
    group.finish();
}

fn bench_pipeline_no_crs(c: &mut Criterion) {
    let engine = build_engine_no_crs();

    let mut group = c.benchmark_group("pipeline_no_crs");

    group.bench_function("clean", |b| {
        b.iter(|| {
            let mut ctx = make_ctx("GET", "/api/users", None, &[]);
            engine.enrich(&mut ctx);
            black_box(engine.fire(&ctx))
        })
    });

    group.bench_function("sqli_block", |b| {
        b.iter(|| {
            let mut ctx = make_ctx("GET", "/search", Some("q=1' OR 1=1--"), &[]);
            engine.enrich(&mut ctx);
            black_box(engine.fire(&ctx))
        })
    });

    group.finish();
}

// ── bench: micro-level breakdown — isolate each subsystem ────────────────────
//
// Goal: attribute the ~744 µs clean-request cost across:
//   (a) Working-memory allocation (HashMap init)
//   (b) Individual detection-regex calls (sqli, xss, traversal, …)
//   (c) fn_matches() — compiles a Regex from a string arg on EVERY call
//   (d) Full alpha-evaluation phase (all unique condition nodes) without the terminal scan
//   (e) read_path() — field resolution + String allocation + form_decode
//
// Subtract wm_create from read_path/* to isolate pure path-resolution cost.
// Subtract alpha_eval from fire/clean to isolate the terminal-scan overhead.

fn bench_micro(c: &mut Criterion) {
    use waf_engine::rules::grl::{
        ast::{Path, PathSeg, Value},
        functions::{detect_header_injection, detect_path_traversal, detect_sqli, detect_xss},
        functions as grl_fns,
        registry::{register_context_defaults, FunctionRegistry},
    };
    use waf_engine::rules::rete::{engine::eval_alpha, working_memory::WorkingMemory};

    let engine = build_engine();
    let mut clean = make_ctx("GET", "/api/users", Some("page=1&sort=asc"), &[]);
    engine.enrich(&mut clean);

    eprintln!(
        "\n[bench_micro] network: {} alpha nodes, {} terminals",
        engine.network.alphas.len(),
        engine.network.terminals.len()
    );

    let mut g = c.benchmark_group("micro");

    // ── (a) Working-memory allocation cost (HashMap + Outcome init) ───────────
    g.bench_function("wm_create", |b| {
        b.iter(|| black_box(WorkingMemory::new(black_box(&clean), &engine.registry)))
    });

    // ── (b) Individual detection-regex calls on a clean string ────────────────
    //   Uses static OnceLock<Regex> — regex is compiled only once.
    g.bench_function("detect_sqli/clean", |b| {
        b.iter(|| black_box(detect_sqli(black_box("page=1&sort=asc"))))
    });
    g.bench_function("detect_sqli/attack", |b| {
        b.iter(|| black_box(detect_sqli(black_box("1' OR 1=1--"))))
    });
    g.bench_function("detect_xss/clean", |b| {
        b.iter(|| black_box(detect_xss(black_box("page=1&sort=asc"))))
    });
    g.bench_function("detect_traversal/clean", |b| {
        b.iter(|| black_box(detect_path_traversal(black_box("/api/users"))))
    });
    g.bench_function("detect_header_inj/clean", |b| {
        b.iter(|| black_box(detect_header_injection(black_box("page=1&sort=asc"))))
    });

    // ── (c) fn_matches — compiles a new Regex from a string arg every call ────
    //   Unlike the static OnceLock detectors this is O(pattern-compile) each time.
    //   Three variants show how compile cost scales with pattern complexity.
    let matches_complex = [
        Value::Str("Mozilla/5.0 (compatible; Googlebot/2.1)".into()),
        Value::Str(r"(?i)nikto|masscan|nmap|nessus|zgrab".into()),
    ];
    g.bench_function("dispatch/matches_complex_pattern", |b| {
        b.iter(|| black_box(grl_fns::dispatch("matches", black_box(&matches_complex))))
    });
    // Patterns actually emitted by path_wildcard rules (backends.yaml)
    let matches_path_wildcard = [
        Value::Str("/api/users".into()),
        Value::Str(r"^/api/[^/]+$".into()),
    ];
    g.bench_function("dispatch/matches_path_wildcard", |b| {
        b.iter(|| black_box(grl_fns::dispatch("matches", black_box(&matches_path_wildcard))))
    });
    // Pattern ".*" used by placeholder payload_regex rules (critical/high.yaml)
    let matches_trivial = [
        Value::Str("some body payload".into()),
        Value::Str(".*".into()),
    ];
    g.bench_function("dispatch/matches_trivial_dotstar", |b| {
        b.iter(|| black_box(grl_fns::dispatch("matches", black_box(&matches_trivial))))
    });
    let contains_args = [
        Value::Str("Mozilla/5.0 (compatible; Googlebot/2.1)".into()),
        Value::Str("nikto".into()),
    ];
    g.bench_function("dispatch/contains_no_compile", |b| {
        b.iter(|| black_box(grl_fns::dispatch("contains", black_box(&contains_args))))
    });

    // ── (d) Full alpha-evaluation phase — no terminal scan ────────────────────
    //   Difference between this and fire/clean ≈ terminal-scan overhead.
    let n_alphas = engine.network.alphas.len();
    g.bench_function(format!("alpha_eval/{n_alphas}_nodes_clean"), |b| {
        b.iter(|| {
            let wm = WorkingMemory::new(&clean, &engine.registry);
            let bools: Vec<bool> = engine.network.alphas.iter()
                .map(|a| eval_alpha(a, &wm))
                .collect();
            black_box(bools)
        })
    });

    // ── (e) read_path cost — field resolution + String alloc + form_decode ────
    //   WM is pre-built once; b.iter measures only the read_path call itself.
    let query_path = Path {
        segments: vec![
            PathSeg::Field("Request".into()),
            PathSeg::Field("Query".into()),
        ],
    };
    let path_path = Path {
        segments: vec![
            PathSeg::Field("Request".into()),
            PathSeg::Field("Path".into()),
        ],
    };
    let local_reg = {
        let mut r = FunctionRegistry::new();
        register_context_defaults(&mut r);
        r
    };
    g.bench_function("read_path/query_with_form_decode", |b| {
        let wm = WorkingMemory::new(&clean, &local_reg);
        b.iter(|| black_box(wm.read_path(black_box(&query_path))))
    });
    g.bench_function("read_path/path_with_url_decode", |b| {
        let wm = WorkingMemory::new(&clean, &local_reg);
        b.iter(|| black_box(wm.read_path(black_box(&path_path))))
    });

    g.finish();
}

// ── bench: CRS evaluator in isolation ────────────────────────────────────────
//
// Calls `CrsRuleset::evaluate(&ctx)` directly — no RETE engine, no GRL
// dispatch overhead.  Measures the raw cost of running all CRS phase-1/2
// rules against one request.

fn bench_crs(c: &mut Criterion) {
    let base = rules_dir();
    let ruleset = std::sync::Arc::new(
        CrsRuleset::load_from_dir(&base.join("crs"), &base.join("data"))
            .expect("load CRS ruleset"),
    );

    let mut clean = make_ctx("GET", "/api/users", Some("page=1&sort=asc"), &[
        ("accept", "application/json"),
        ("user-agent", "Mozilla/5.0 (compatible)"),
    ]);
    // CrsRuleset::evaluate doesn't call enrich; fill in client_ip explicitly.
    clean.client_ip = "203.0.113.1".to_string();

    let mut sqli_uri = make_ctx("GET", "/search", Some("q=1' OR 1=1--"), &[
        ("user-agent", "Mozilla/5.0"),
    ]);
    sqli_uri.client_ip = "203.0.113.2".to_string();

    let mut sqli_body = make_ctx("POST", "/login", None, &[
        ("content-type", "application/x-www-form-urlencoded"),
        ("user-agent", "Mozilla/5.0"),
    ]);
    sqli_body.body = Some(b"username=admin' OR '1'='1&password=x".to_vec());
    sqli_body.client_ip = "203.0.113.3".to_string();

    let mut xss_body = make_ctx("POST", "/comment", None, &[
        ("content-type", "application/x-www-form-urlencoded"),
        ("user-agent", "Mozilla/5.0"),
    ]);
    xss_body.body = Some(b"text=<script>alert(document.cookie)</script>".to_vec());
    xss_body.client_ip = "203.0.113.4".to_string();

    let mut traversal = make_ctx("GET", "/files", Some("path=../../etc/passwd"), &[
        ("user-agent", "Mozilla/5.0"),
    ]);
    traversal.client_ip = "203.0.113.5".to_string();

    let mut scanner = make_ctx("GET", "/", None, &[
        ("user-agent", "Nikto/2.1.6 (Evasions:None)"),
    ]);
    scanner.client_ip = "203.0.113.6".to_string();

    let mut rce = make_ctx("GET", "/ping", Some("host=127.0.0.1;cat%20/etc/passwd"), &[
        ("user-agent", "Mozilla/5.0"),
    ]);
    rce.client_ip = "203.0.113.7".to_string();

    let scenarios: &[(&str, &RequestContext)] = &[
        ("clean",         &clean),
        ("sqli_uri",      &sqli_uri),
        ("sqli_body",     &sqli_body),
        ("xss_body",      &xss_body),
        ("path_traversal",&traversal),
        ("scanner_ua",    &scanner),
        ("rce_cmd",       &rce),
    ];

    eprintln!(
        "\n[bench_crs] ruleset: {} rule items loaded",
        ruleset.len()
    );

    let mut group = c.benchmark_group("crs");
    group.measurement_time(Duration::from_secs(10));

    for (name, ctx) in scenarios {
        let rs = Arc::clone(&ruleset);
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            ctx,
            move |b, ctx| b.iter(|| black_box(rs.evaluate(black_box(ctx)))),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_compile, bench_fire, bench_enrich, bench_full_pipeline,
                          bench_fire_no_crs, bench_pipeline_no_crs, bench_micro,
                          bench_crs);
criterion_main!(benches);
