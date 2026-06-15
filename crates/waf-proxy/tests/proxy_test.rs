/// Integration tests for proxy request lifecycle.
/// Run with: `cargo test -p waf-proxy --test proxy_test`

#[tokio::test]
async fn test_allowed_request_passes_through() {
    todo!("start test WAF instance; send benign GET /; assert 200 from upstream")
}

#[tokio::test]
async fn test_blocked_ip_returns_403() {
    todo!("add IP to blacklist; send request from that IP; assert 403")
}

#[tokio::test]
async fn test_upstream_down_returns_503() {
    todo!("configure unreachable upstream; send request; assert 503")
}

#[tokio::test]
async fn test_circuit_breaker_opens_after_threshold() {
    todo!("trip upstream failure threshold; verify circuit opens; verify fast 503")
}

#[tokio::test]
async fn test_critical_tier_fail_close() {
    todo!("simulate WAF internal panic on CRITICAL route; verify request is denied")
}
