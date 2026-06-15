//! Benchmark comparing YAML rule engine vs RETE + GRL engine
//!
//! Tests both engines against the same YAML rules from rules/ directory
//! to compare evaluation performance and correctness.
//!
//! Run from repo root:
//!   cargo run --release --bin compare-engines-yaml-vs-rete

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

// Import YAML engine
use rule::{
    loader::RuleLoader as YamlRuleLoader,
    RequestContext as YamlRequestContext,
    RuleEvaluator,
};

// Import RETE engine
use waf_engine::rules::{
    grl::{converter::yaml_to_grl, parser::parse as parse_grl},
    rete::{engine::Engine as ReteEngine, Network},
};
use waf_engine::context::RequestContext as ReteRequestContext;
use waf_types::risk::RiskScore;

#[tokio::main]
async fn main() {
    println!("════════════════════════════════════════════════════════════════════");
    println!("WAF Rule Engine Comparison: YAML vs RETE+GRL");
    println!("Testing against REAL rules from rules/ directory");
    println!("════════════════════════════════════════════════════════════════════\n");

    let iterations = 10_000;
    println!("Iterations: {} per scenario\n", iterations);

    // Load rules from YAML files
    let rules_dir = Path::new("rules");
    if !rules_dir.exists() {
        eprintln!("❌ Error: rules/ directory not found. Run from mini-waf root directory.");
        std::process::exit(1);
    }

    // Load YAML engine rules
    let yaml_ruleset = match YamlRuleLoader::load_from_path(rules_dir) {
        Ok(rs) => rs,
        Err(e) => {
            eprintln!("❌ Failed to load YAML rules: {}", e);
            std::process::exit(1);
        }
    };

    println!("✓ Loaded {} YAML rules\n", yaml_ruleset.rules.len());

    print_rule_summary(&yaml_ruleset);

    // Create YAML evaluator
    let yaml_evaluator = RuleEvaluator::new(yaml_ruleset.clone());

    // Load and convert YAML rules to RETE/GRL
    let rete_engine = match load_rete_engine(rules_dir) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("❌ Failed to load RETE engine: {}", e);
            std::process::exit(1);
        }
    };

    // Define test scenarios
    let test_scenarios: Vec<(&str, &str, &str, &str, Option<&str>)> = vec![
        ("clean-request", "192.168.1.1", "GET", "/api/users", None),
        ("sqli-attack", "10.0.0.1", "POST", "/api/search", Some("q=admin' UNION SELECT password FROM users--")),
        ("xss-attack", "10.0.0.2", "POST", "/comment", Some("text=<script>alert('xss')</script>")),
        ("path-traversal", "10.0.0.3", "GET", "/../../../etc/passwd", None),
        ("command-injection", "10.0.0.4", "POST", "/api/execute", Some("cmd=cat /etc/passwd | grep root")),
    ];

    // Benchmark YAML engine
    println!("📊 Engine 1: YAML Rule Engine (linear + condition tree)");
    println!("────────────────────────────────────────────────────────────────────");
    
    let (yaml_time, yaml_scenarios, yaml_matches) = benchmark_yaml_engine(&yaml_evaluator, iterations, &test_scenarios);
    
    println!("Total time: {:.2} ms\n", yaml_time);
    println!("Per-request latency by scenario:");
    for (name, _ip, _method, _path, _payload) in &test_scenarios {
        let latency = yaml_scenarios.get(&name.to_string()).copied().unwrap_or(0.0);
        let matched = yaml_matches.get(&name.to_string()).map(|s| s.as_str()).unwrap_or("(no match)");
        println!("  {:20} : {:8.3} µs  |  Rule: {}", name, latency, matched);
    }

    println!("\n");

    // Benchmark RETE engine
    println!("📊 Engine 2: RETE + GRL Engine (network + fire cycles)");
    println!("────────────────────────────────────────────────────────────────────");
    
    let (rete_time, rete_scenarios, rete_matches) = benchmark_rete_engine(&rete_engine, iterations, &test_scenarios);
    
    println!("Total time: {:.2} ms\n", rete_time);
    println!("Per-request latency by scenario:");
    for (name, _ip, _method, _path, _payload) in &test_scenarios {
        let latency = rete_scenarios.get(&name.to_string()).copied().unwrap_or(0.0);
        let matched = rete_matches.get(&name.to_string()).map(|s| s.as_str()).unwrap_or("(no match)");
        println!("  {:20} : {:8.3} µs  |  Rule: {}", name, latency, matched);
    }

    println!("\n");

    // Performance comparison
    println!("════════════════════════════════════════════════════════════════════");
    println!("Performance Comparison:");
    println!();
    
    let yaml_avg = yaml_time * 1000.0 / (iterations as f64 * test_scenarios.len() as f64);
    let rete_avg = rete_time * 1000.0 / (iterations as f64 * test_scenarios.len() as f64);
    let ratio = if yaml_avg > 0.0 { rete_avg / yaml_avg } else { 1.0 };
    
    println!("YAML Engine:");
    println!("  • Total time:        {:.2} ms", yaml_time);
    println!("  • Average latency:   {:.3} µs", yaml_avg);
    println!("  • Throughput:        {:.0} req/sec", (iterations as f64 * test_scenarios.len() as f64) / (yaml_time / 1000.0));
    
    println!("\nRETE + GRL Engine:");
    println!("  • Total time:        {:.2} ms", rete_time);
    println!("  • Average latency:   {:.3} µs", rete_avg);
    println!("  • Throughput:        {:.0} req/sec", (iterations as f64 * test_scenarios.len() as f64) / (rete_time / 1000.0));
    
    println!("\nSpeedup Factor: {:.2}x", ratio);
    if ratio > 1.0 {
        println!("  ⚡ RETE is {:.1}% SLOWER than YAML", (ratio - 1.0) * 100.0);
    } else if ratio < 1.0 {
        println!("  ✨ RETE is {:.1}% FASTER than YAML", (1.0 - ratio) * 100.0);
    } else {
        println!("  ≈ Both engines have similar performance");
    }

    println!("\nEngine Characteristics:");
    println!("  YAML Engine:");
    println!("    • Linear rule iteration in priority order");
    println!("    • Tree-walking condition evaluation");
    println!("    • First match wins (early exit)");
    println!("    • Complexity: O(r × c × m) where m=match cost");
    
    println!("\n  RETE + GRL Engine:");
    println!("    • Pre-compiled network of alpha/terminal nodes");
    println!("    • Hash-consing for shared pattern evaluation");
    println!("    • Salience-ordered fire cycles (max 16)");
    println!("    • Extensible function registry");
    println!("    • Complexity: O(alphas × cycles)");

    println!("\n════════════════════════════════════════════════════════════════════");
    println!("Accuracy Comparison: Rule Matching Validation");
    println!("════════════════════════════════════════════════════════════════════\n");
    
    // Build salience map for proper rule priority sorting
    let salience_map = build_salience_map(&rete_engine);
    compare_rule_accuracy(&yaml_evaluator, &rete_engine, &test_scenarios, &salience_map);

    println!("\n════════════════════════════════════════════════════════════════════");
}

fn load_rete_engine(rules_dir: &Path) -> anyhow::Result<ReteEngine> {
    // Load and merge all YAML rule files
    let mut all_rules: Vec<serde_yaml::Value> = Vec::new();
    
    for entry in std::fs::read_dir(rules_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "yaml").unwrap_or(false) {
            let content = std::fs::read_to_string(&path)?;
            let doc: serde_yaml::Value = serde_yaml::from_str(&content)?;
            if let Some(rules_seq) = doc.get("rules").and_then(|v| v.as_sequence()) {
                for rule in rules_seq {
                    all_rules.push(rule.clone());
                }
            }
        }
    }

    println!("\n🔍 DEBUG: Loaded {} rules from YAML files", all_rules.len());
    if !all_rules.is_empty() {
        println!("First rule:\n{}\n", serde_yaml::to_string(&all_rules[0]).unwrap());
    }

    // Create a sequence of rules (yaml_to_grl expects a top-level sequence)
    let merged_doc = serde_yaml::Value::Sequence(all_rules);
    
    // Convert YAML to GRL
    let grl_source = yaml_to_grl(&merged_doc)?;
    
    // DEBUG: Print first 2000 chars of generated GRL
    println!("🔍 Generated GRL length: {} chars\n", grl_source.len());
    if grl_source.is_empty() {
        println!("⚠️ WARNING: Empty GRL generated!\n");
    } else {
        let preview = if grl_source.len() > 2000 {
            format!("{}...\n(truncated)", &grl_source[..2000])
        } else {
            grl_source.clone()
        };
        println!("Generated GRL (first 2000 chars):\n{}\n", preview);
    }
    
    // Parse GRL and compile network
    match parse_grl(&grl_source) {
        Ok(rule_asts) => {
            println!("✓ GRL parsed: {} rule ASTs\n", rule_asts.len());
            let network = Network::compile(rule_asts);
            Ok(ReteEngine::new(network))
        }
        Err(e) => {
            eprintln!("❌ Failed to parse GRL: {}\n", e);
            eprintln!("Full GRL source (first 5000 chars):\n{}\n", 
                if grl_source.len() > 5000 { 
                    format!("{}...", &grl_source[..5000]) 
                } else { 
                    grl_source.clone() 
                });
            Err(e)
        }
    }
}

/// Build a mapping of rule names to their salience values from the compiled network.
/// Higher salience = higher priority (fires first).
fn build_salience_map(engine: &ReteEngine) -> HashMap<String, i32> {
    let mut map = HashMap::new();
    for terminal in &engine.network.terminals {
        map.insert(terminal.rule_name.clone(), terminal.salience);
    }
    map
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

fn benchmark_yaml_engine(
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
                h.insert("Content-Type".to_string(), "application/json".to_string());
                h
            };

            let payload_bytes = payload.unwrap_or("").as_bytes();
            let cookies = HashMap::new();

            let ctx = YamlRequestContext {
                ip,
                path,
                method,
                headers: &headers,
                payload: payload_bytes,
                cookies: &cookies,
                tier: waf_types::tier::Tier::CatchAll,
                session_id: "",
                device_fp: "",
                content_type: Some("application/json"),
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

fn benchmark_rete_engine(
    engine: &ReteEngine,
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
                h.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
                h.insert("content-type".to_string(), "application/json".to_string());
                h
            };

            let body = payload.map(|p| p.as_bytes().to_vec());

            let mut ctx = ReteRequestContext {
                request_id: format!("bench-{}", name),
                arrived_at_ms: chrono::Utc::now().timestamp_millis(),
                method: method.to_string(),
                path: path.to_string(),
                query: None,
                tier: waf_types::tier::Tier::CatchAll,
                client_ip: ip.to_string(),
                xff_header: None,
                headers,
                body,
                session_id: None,
                device_fp: None,
                risk_score: RiskScore::ZERO,
                matched_rule_id: None,
                extensions: HashMap::new(),
            };

            let start = Instant::now();
            engine.enrich(&mut ctx);
            let outcome = engine.fire(&ctx);
            let elapsed = start.elapsed();
            let latency_us = elapsed.as_secs_f64() * 1_000_000.0;
            
            *scenario_times.entry(name.to_string()).or_insert(0.0) += latency_us;
            
            // Extract first matched rule
            if let Some(first_match) = outcome.matched_rules.first() {
                scenario_matches.insert(name.to_string(), first_match.clone());
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

fn compare_rule_accuracy(
    yaml_evaluator: &RuleEvaluator,
    rete_engine: &ReteEngine,
    scenarios: &[(&str, &str, &str, &str, Option<&str>)],
    salience_map: &HashMap<String, i32>,
) {
    println!("Testing each scenario with both engines...\n");

    let mut agreement_count = 0;
    let mut disagreement_count = 0;

    for (name, ip, method, path, payload) in scenarios {
        // Test YAML engine
        let yaml_headers = {
            let mut h = HashMap::new();
            h.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
            h.insert("Content-Type".to_string(), "application/json".to_string());
            h
        };
        let yaml_payload = payload.unwrap_or("").as_bytes();
        let yaml_cookies = HashMap::new();

        let yaml_ctx = YamlRequestContext {
            ip,
            path,
            method,
            headers: &yaml_headers,
            payload: yaml_payload,
            cookies: &yaml_cookies,
            tier: waf_types::tier::Tier::CatchAll,
            session_id: "",
            device_fp: "",
            content_type: Some("application/json"),
        };

        let yaml_result = yaml_evaluator.evaluate(&yaml_ctx, &[]);
        let yaml_matched = yaml_result.map(|m| m.rule_id.clone()).unwrap_or_default();

        // Test RETE engine
        let rete_headers = {
            let mut h = HashMap::new();
            h.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
            h.insert("content-type".to_string(), "application/json".to_string());
            h
        };

        let rete_body = payload.map(|p| p.as_bytes().to_vec());
        
        let mut rete_ctx = ReteRequestContext {
            request_id: format!("accuracy-{}", name),
            arrived_at_ms: chrono::Utc::now().timestamp_millis(),
            method: method.to_string(),
            path: path.to_string(),
            query: None,
            tier: waf_types::tier::Tier::CatchAll,
            client_ip: ip.to_string(),
            xff_header: None,
            headers: rete_headers,
            body: rete_body,
            session_id: None,
            device_fp: None,
            risk_score: RiskScore::ZERO,
            matched_rule_id: None,
            extensions: HashMap::new(),
        };

        rete_engine.enrich(&mut rete_ctx);
        let mut rete_outcome = rete_engine.fire(&rete_ctx);
        
        // Sort matched rules by salience (higher first) to match YAML engine behavior
        // which always returns the highest-priority rule when multiple match
        rete_outcome.matched_rules.sort_by(|a, b| {
            let salience_a = salience_map.get(a).copied().unwrap_or(0);
            let salience_b = salience_map.get(b).copied().unwrap_or(0);
            salience_b.cmp(&salience_a)  // Descending: higher salience first
        });
        
        // Debug: print sorted result if was more than one
        if rete_outcome.matched_rules.len() > 1 {
            println!("    [DEBUG] After sorting, using first: {}", rete_outcome.matched_rules.first().unwrap_or(&"".to_string()));
        }
        
        let rete_matched = rete_outcome
            .matched_rules
            .first()
            .cloned()
            .unwrap_or_default();

        // Compare results
        let agreement = yaml_matched == rete_matched;
        if agreement {
            agreement_count += 1;
        } else {
            disagreement_count += 1;
        }

        // Display comparison
        let status = if agreement { "✓ MATCH" } else { "✗ DIFFER" };
        println!("Scenario: {}", name);
        println!("  {}", status);
        println!("    YAML Engine:  {}", if yaml_matched.is_empty() { "(no match)".to_string() } else { yaml_matched });
        println!("    RETE Engine:  {}", if rete_matched.is_empty() { "(no match)".to_string() } else { rete_matched });
        
        // Show all matched rules from RETE (in case multiple rules matched)
        if !rete_outcome.matched_rules.is_empty() && rete_outcome.matched_rules.len() > 1 {
            println!("    RETE all matches: {:?}", rete_outcome.matched_rules);
        }
        
        // Show outcome details
        if let Some(reason) = &rete_outcome.block_reason {
            println!("    RETE action: BLOCK ({})", reason);
        }
        println!();
    }

    println!("\n════════════════════════════════════════════════════════════════════");
    println!("Accuracy Summary:");
    println!();
    let total = scenarios.len();
    let agreement_pct = if total > 0 { (agreement_count as f64 / total as f64) * 100.0 } else { 0.0 };
    
    println!("  • Agreement:   {} / {} ({:.1}%)", agreement_count, total, agreement_pct);
    println!("  • Disagreement: {} / {} ({:.1}%)", disagreement_count, total, (100.0 - agreement_pct));

    if agreement_pct < 100.0 {
        println!("\n⚠ Engines produce different results!");
        println!("  Possible causes:");
        println!("    1. YAML-to-GRL conversion may be incomplete");
        println!("    2. RequestContext field mapping differences");
        println!("    3. Function registry differences (regex matching, etc.)");
        println!("    4. Rule priority/salience ordering differences");
    } else {
        println!("\n✓ All engines agree on matched rules!");
    }
}
