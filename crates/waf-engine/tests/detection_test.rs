/// Integration tests for OWASP attack detection.
/// Run with: `cargo test -p waf-engine --test detection_test`

use std::collections::HashMap;

use waf_engine::rules::grl::functions::detect_path_traversal;
use waf_engine::rules::rule::Condition;
use waf_engine::rules::matcher::evaluate;
use waf_engine::context::RequestContext;
use waf_types::{risk::RiskScore, tier::Tier};

fn make_ctx(path: &str, query: Option<&str>, body: Option<&[u8]>, headers: HashMap<String, String>) -> RequestContext {
    RequestContext {
        request_id: "test".to_string(),
        arrived_at_ms: 0,
        method: "GET".to_string(),
        path: path.to_string(),
        query: query.map(|s| s.to_string()),
        tier: Tier::CatchAll,
        client_ip: "1.2.3.4".to_string(),
        xff_header: None,
        headers,
        body: body.map(|b| b.to_vec()),
        session_id: None,
        device_fp: None,
        risk_score: RiskScore::ZERO,
        matched_rule_id: None,
        extensions: HashMap::new(),
    }
}

#[test]
fn test_sqli_detected_in_query_param() {
    let ctx = make_ctx("/search", Some("id=1' OR '1'='1"), None, HashMap::new());
    assert!(evaluate(&Condition::SqliPattern, &ctx));
}

#[test]
fn test_sqli_detected_in_json_body() {
    let body = b"{ \"q\": \"UNION SELECT password FROM users\" }";
    let ctx = make_ctx("/api/search", None, Some(body), HashMap::new());
    assert!(evaluate(&Condition::SqliPattern, &ctx));
}

#[test]
fn test_xss_detected_in_query_string() {
    let ctx = make_ctx("/search", Some("q=<script>alert(1)</script>"), None, HashMap::new());
    assert!(evaluate(&Condition::XssPattern, &ctx));
}

#[test]
fn test_path_traversal_detected() {
    // Path traversal in the path itself.
    assert!(detect_path_traversal("/../../../etc/passwd"));
    assert!(detect_path_traversal("../../etc/shadow"));
}

#[test]
fn test_path_traversal_encoded_detected() {
    // Percent-encoded variant; path is decoded by working_memory before eval.
    assert!(detect_path_traversal("%2e%2e%2fetc/passwd"));
    assert!(detect_path_traversal("%2e%2e/config"));
    // Ensure the Condition also fires through matcher (raw path with sequences).
    let ctx = make_ctx("/%2e%2e%2fetc/passwd", None, None, HashMap::new());
    assert!(evaluate(&Condition::PathTraversalPattern, &ctx));
}

#[test]
fn test_ssrf_detected_to_internal_ip() {
    let body = b"url=http://169.254.169.254/latest/meta-data/";
    let ctx = make_ctx("/proxy", None, Some(body), HashMap::new());
    assert!(evaluate(&Condition::SsrfPattern, &ctx));
}

#[test]
fn test_header_injection_crlf_detected() {
    let mut headers = HashMap::new();
    headers.insert("x-custom".to_string(), "value\r\nX-Injected: evil".to_string());
    let ctx = make_ctx("/", None, None, headers);
    assert!(evaluate(&Condition::HeaderInjectionPattern, &ctx));
}

#[test]
fn test_benign_request_not_flagged() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let ctx = make_ctx("/api/users", Some("page=1&limit=10"), Some(b"{\"name\":\"alice\"}"), headers);
    assert!(!evaluate(&Condition::SqliPattern, &ctx));
    assert!(!evaluate(&Condition::XssPattern, &ctx));
    assert!(!evaluate(&Condition::PathTraversalPattern, &ctx));
    assert!(!evaluate(&Condition::SsrfPattern, &ctx));
    assert!(!evaluate(&Condition::HeaderInjectionPattern, &ctx));
}

