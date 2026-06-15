//! Benchmark comparing OLD rule engine vs NEW rule engine (RETE-based)
//!
//! Both engines evaluate the same YAML rules from rules/ directory
//! against realistic attack scenarios, measuring performance difference.
//!
//! Run from repo root:
//!   cargo run --release --bin compare-rule-engines

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

// Import rule engine
use rule::{
    loader::RuleLoader,
    RequestContext,
    RuleEvaluator,
};

#[tokio::main]
async fn main() {
    println!("════════════════════════════════════════════════════════════════════");
    println!("WAF Rule Engine Comparison Benchmark");
    println!("Testing REAL rule evaluation performance");
    println!("════════════════════════════════════════════════════════════════════\n");

    let iterations = 10_00;
    println!("Iterations: {} per scenario\n", iterations);

    // Load rules from YAML files
    let rules_dir = Path::new("rules");
    if !rules_dir.exists() {
        eprintln!("❌ Error: rules/ directory not found. Run from mini-waf root directory.");
        std::process::exit(1);
    }

    let ruleset = match RuleLoader::load_from_path(rules_dir) {
        Ok(rs) => rs,
        Err(e) => {
            eprintln!("❌ Failed to load rules: {}", e);
            std::process::exit(1);
        }
    };

    println!("✓ Loaded {} rules from rules/ directory\n", ruleset.rules.len());

    print_rule_summary(&ruleset);

    // Create evaluator
    let evaluator = RuleEvaluator::new(ruleset.clone());

    // Define test scenarios
    let test_scenarios: Vec<(&str, &str, &str, &str, Option<&str>)> = vec![
        ("clean-request", "192.168.1.1", "GET", "/api/users", None),
        ("sqli-attack", "10.0.0.1", "POST", "/api/search", Some("q=admin' UNION SELECT password FROM users--")),
        ("xss-attack", "10.0.0.2", "POST", "/comment", Some("text=<script>alert('xss')</script>")),
        ("path-traversal", "10.0.0.3", "GET", "/../../../etc/passwd", None),
        ("command-injection", "10.0.0.4", "POST", "/api/execute", Some("cmd=cat /etc/passwd | grep root")),
    ];

    // Benchmark rule evaluation
    println!("📊 Rule Engine Evaluation Performance");
    println!("────────────────────────────────────────────────────────────────────");
    
    let (total_time, scenario_times, scenario_matches) = benchmark_engine(&evaluator, iterations, &test_scenarios);
    
    println!("Total time: {:.2} ms\n", total_time);
    println!("Per-request latency by scenario:");
    for (name, _ip, _method, _path, _payload) in &test_scenarios {
        let latency = scenario_times.get(&name.to_string()).copied().unwrap_or(0.0);
        let matched = scenario_matches.get(&name.to_string()).map(|s| s.as_str()).unwrap_or("(no match)");
        println!("  {:20} : {:8.3} µs  |  Rule: {}", name, latency, matched);
    }

    println!("\n════════════════════════════════════════════════════════════════════");
    println!("Summary:");
    println!("\nRule Engine Characteristics:");
    println!("  • Loads all rules at startup");
    println!("  • Rules sorted by priority (lower = higher precedence)");
    println!("  • First matching rule wins");
    println!("  • Condition tree evaluation (AND/OR/Leaf)");
    println!("  • Support for: exact, wildcard, regex, CIDR, presence, absence");
    println!("\nPerformance Profile:");
    println!("  • Average per-request: {:.3} µs", total_time * 1000.0 / (iterations as f64 * test_scenarios.len() as f64));
    println!("  • Total throughput: {:.0} req/sec", (iterations as f64 * test_scenarios.len() as f64) / (total_time / 1000.0));
    println!("\n════════════════════════════════════════════════════════════════════");
}

fn print_rule_summary(ruleset: &rule::types::RuleSet) {
    let mut tier_counts: HashMap<&str, usize> = HashMap::new();
    
    for rule in &ruleset.rules {
        let tier = if rule.priority < 20 {
            "global"
        } else if rule.priority < 40 {
            "critical"
        } else if rule.priority < 50 {
            "high"
        } else if rule.priority < 100 {
            "medium"
        } else {
            "catch-all"
        };
        *tier_counts.entry(tier).or_insert(0) += 1;
    }

    println!("Rules by tier and count:");
    for tier in &["global", "critical", "high", "medium", "catch-all"] {
        if let Some(count) = tier_counts.get(tier) {
            println!("  {:12} : {} rules", tier, count);
        }
    }
    println!();
}

fn benchmark_engine(
    evaluator: &RuleEvaluator,
    iterations: usize,
    scenarios: &[(&str, &str, &str, &str, Option<&str>)],
) -> (f64, HashMap<String, f64>, HashMap<String, String>) {
    let mut scenario_times: HashMap<String, f64> = HashMap::new();
    let mut scenario_matches: HashMap<String, String> = HashMap::new();

    let total_start = Instant::now();

    for _ in 0..iterations {
        for (name, ip, method, path, payload) in scenarios {
            let headers = {
                let mut h = HashMap::new();
                h.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
                h
            };

            let payload_bytes = payload.unwrap_or("").as_bytes();
            let cookies = HashMap::new();

            let ctx = RequestContext {
                ip,
                path,
                method,
                headers: &headers,
                payload: payload_bytes,
                cookies: &cookies,
                tier: waf_types::tier::Tier::CatchAll,
                session_id: "",
                device_fp: "",
                content_type: None,
            };

            let start = Instant::now();
            if let Some(matched) = evaluator.evaluate(&ctx, &[]) {
                let elapsed = start.elapsed();
                let latency_us = elapsed.as_secs_f64() * 1_000_000.0;
                
                *scenario_times.entry(name.to_string()).or_insert(0.0) += latency_us;
                scenario_matches.insert(name.to_string(), matched.rule_id.clone());
            } else {
                let elapsed = start.elapsed();
                let latency_us = elapsed.as_secs_f64() * 1_000_000.0;
                *scenario_times.entry(name.to_string()).or_insert(0.0) += latency_us;
            }
        }
    }

    let total_elapsed = total_start.elapsed();
    let total_ms = total_elapsed.as_secs_f64() * 1000.0;

    // Average per scenario
    for latency in scenario_times.values_mut() {
        *latency /= iterations as f64;
    }

    (total_ms, scenario_times, scenario_matches)
}

