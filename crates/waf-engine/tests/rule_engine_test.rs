/// Integration tests for the rule engine.
/// Run with: `cargo test -p waf-engine --test rule_engine_test`

use std::collections::HashMap;
use std::sync::Arc;

use waf_engine::context::RequestContext;
use waf_engine::lists::blacklist_plugin::BlacklistPlugin;
use waf_engine::lists::ip_list::IpListStore;
use waf_engine::rules::matcher::evaluate;
use waf_engine::rules::rete::Network;
use waf_engine::rules::rete::engine::Engine;
use waf_engine::rules::grl::parser::parse;
use waf_engine::rules::rule::{Condition, Rule, RuleAction, RuleScope};
use waf_engine::rules::store::RuleStore;
use waf_types::{risk::RiskScore, tier::Tier};

fn make_ctx(ip: &str, path: &str) -> RequestContext {
    RequestContext {
        request_id: "test-id".to_string(),
        arrived_at_ms: 0,
        method: "GET".to_string(),
        path: path.to_string(),
        query: None,
        tier: Tier::Medium,
        client_ip: ip.to_string(),
        xff_header: None,
        headers: HashMap::new(),
        body: None,
        session_id: None,
        device_fp: None,
        risk_score: RiskScore::ZERO,
        matched_rule_id: None,
        extensions: HashMap::new(),
    }
}

#[test]
fn test_rule_matches_exact_ip() {
    let cond = Condition::IpExact { value: "1.2.3.4".to_string() };
    assert!(evaluate(&cond, &make_ctx("1.2.3.4", "/")));
    assert!(!evaluate(&cond, &make_ctx("9.9.9.9", "/")));
}

#[test]
fn test_rule_matches_path_wildcard() {
    let cond = Condition::PathWildcard { pattern: "/api/*".to_string() };
    assert!(evaluate(&cond, &make_ctx("1.2.3.4", "/api/users")));
    assert!(evaluate(&cond, &make_ctx("1.2.3.4", "/api/")));
    assert!(!evaluate(&cond, &make_ctx("1.2.3.4", "/other/path")));
}

#[test]
fn test_rule_matches_path_regex() {
    let cond = Condition::PathRegex { pattern: r"^/admin/.*$".to_string() };
    assert!(evaluate(&cond, &make_ctx("1.2.3.4", "/admin/dashboard")));
    assert!(!evaluate(&cond, &make_ctx("1.2.3.4", "/public/about")));
}

#[test]
fn test_and_condition_requires_all() {
    let cond = Condition::And(vec![
        Condition::IpExact { value: "1.2.3.4".to_string() },
        Condition::PathExact { value: "/secret".to_string() },
    ]);
    assert!(evaluate(&cond, &make_ctx("1.2.3.4", "/secret")));
    assert!(!evaluate(&cond, &make_ctx("1.2.3.4", "/other")));
    assert!(!evaluate(&cond, &make_ctx("9.9.9.9", "/secret")));
    assert!(!evaluate(&cond, &make_ctx("9.9.9.9", "/other")));
}

#[test]
fn test_or_condition_requires_one() {
    let cond = Condition::Or(vec![
        Condition::IpExact { value: "1.2.3.4".to_string() },
        Condition::PathExact { value: "/public".to_string() },
    ]);
    assert!(evaluate(&cond, &make_ctx("9.9.9.9", "/public")));
    assert!(evaluate(&cond, &make_ctx("1.2.3.4", "/other")));
    assert!(evaluate(&cond, &make_ctx("1.2.3.4", "/public")));
    assert!(!evaluate(&cond, &make_ctx("9.9.9.9", "/other")));
}

#[test]
fn test_not_condition_inverts() {
    let cond = Condition::Not(Box::new(Condition::IpExact { value: "1.2.3.4".to_string() }));
    assert!(!evaluate(&cond, &make_ctx("1.2.3.4", "/")));
    assert!(evaluate(&cond, &make_ctx("9.9.9.9", "/")));
}

#[test]
fn test_rule_priority_ordering() {
    let mut rules = vec![
        Rule {
            id: "low-priority".to_string(),
            priority: 100,
            scope: RuleScope::Global,
            condition: Condition::PathExact { value: "/".to_string() },
            action: RuleAction::Log,
            risk_score_delta: 0,
            upstream_backend: None,
        },
        Rule {
            id: "high-priority".to_string(),
            priority: 1,
            scope: RuleScope::Global,
            condition: Condition::PathExact { value: "/".to_string() },
            action: RuleAction::Block,
            risk_score_delta: 50,
            upstream_backend: None,
        },
    ];
    rules.sort_by_key(|r| r.priority);
    assert_eq!(rules[0].id, "high-priority");
    assert_eq!(rules[1].id, "low-priority");
}

#[test]
fn test_hot_reload_replaces_rules() {
    let initial = vec![Rule {
        id: "old-rule".to_string(),
        priority: 1,
        scope: RuleScope::Global,
        condition: Condition::PathExact { value: "/old".to_string() },
        action: RuleAction::Block,
        risk_score_delta: 0,
        upstream_backend: None,
    }];
    let store = RuleStore::new(initial);
    assert_eq!(store.snapshot()[0].id, "old-rule");

    store.reload(vec![Rule {
        id: "new-rule".to_string(),
        priority: 1,
        scope: RuleScope::Global,
        condition: Condition::PathExact { value: "/new".to_string() },
        action: RuleAction::Allow,
        risk_score_delta: 0,
        upstream_backend: None,
    }]);

    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].id, "new-rule");
}

// ── BlacklistPlugin tests ─────────────────────────────────────────────────────

#[test]
fn test_blacklist_plugin_blocks_listed_ip() {
    let store = Arc::new(IpListStore::new());
    store.add_to_blacklist("10.0.0.1");

    let src = r#"
        rule "BlockBlacklisted" salience 100 {
            when ip_in_blacklist(Request.ClientIp)
            then block("blacklisted");
        }
    "#;
    let mut engine = Engine::new(Network::compile(parse(src).unwrap()));
    engine.install(BlacklistPlugin::new(Arc::clone(&store)));

    let mut ctx = make_ctx("10.0.0.1", "/");
    engine.enrich(&mut ctx);
    let outcome = engine.fire(&ctx);

    assert!(outcome.block_reason.is_some(), "blacklisted IP should be blocked");
    assert_eq!(ctx.extensions.get("blacklisted").map(|s| s.as_str()), Some("true"));
}

#[test]
fn test_blacklist_plugin_allows_clean_ip() {
    let store = Arc::new(IpListStore::new());
    store.add_to_blacklist("10.0.0.1");

    let src = r#"
        rule "BlockBlacklisted" salience 100 {
            when ip_in_blacklist(Request.ClientIp)
            then block("blacklisted");
        }
    "#;
    let mut engine = Engine::new(Network::compile(parse(src).unwrap()));
    engine.install(BlacklistPlugin::new(Arc::clone(&store)));

    let mut ctx = make_ctx("9.9.9.9", "/");
    engine.enrich(&mut ctx);
    let outcome = engine.fire(&ctx);

    assert!(outcome.block_reason.is_none(), "clean IP should not be blocked");
    assert_eq!(ctx.extensions.get("blacklisted").map(|s| s.as_str()), Some("false"));
}

#[test]
fn test_blacklist_plugin_cidr_match() {
    let store = Arc::new(IpListStore::new());
    store.add_to_blacklist("192.168.1.0/24");

    let src = r#"
        rule "BlockCidr" salience 100 {
            when ip_in_blacklist(Request.ClientIp)
            then block("cidr-blacklisted");
        }
    "#;
    let mut engine = Engine::new(Network::compile(parse(src).unwrap()));
    engine.install(BlacklistPlugin::new(Arc::clone(&store)));

    let mut ctx_in  = make_ctx("192.168.1.42", "/");
    let mut ctx_out = make_ctx("192.168.2.1",  "/");
    engine.enrich(&mut ctx_in);
    engine.enrich(&mut ctx_out);

    assert!(engine.fire(&ctx_in).block_reason.is_some(),  "IP inside CIDR should be blocked");
    assert!(engine.fire(&ctx_out).block_reason.is_none(), "IP outside CIDR should pass");
}

#[test]
fn test_whitelist_overrides_blacklist() {
    let store = Arc::new(IpListStore::new());
    store.add_to_blacklist("10.0.0.0/8");
    store.add_to_whitelist("10.0.0.5");  // carve-out

    assert!(!store.is_blacklisted("10.0.0.5"), "whitelisted IP should not appear blacklisted");
    assert!(store.is_blacklisted("10.0.0.6"),  "non-whitelisted IP in range should be blacklisted");
}
