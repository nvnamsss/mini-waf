/// Integration tests for rate limiting behaviour.
/// Run with: `cargo test -p waf-engine --test rate_limit_test`

#[test]
fn test_sliding_window_allows_within_limit() {
    todo!("send N requests within window; assert all allowed")
}

#[test]
fn test_sliding_window_blocks_over_limit() {
    todo!("send N+1 requests within window; assert last one is rejected")
}

#[test]
fn test_sliding_window_resets_after_window_expires() {
    todo!("fill window; advance time past window_ms; send one more; assert allowed")
}

#[test]
fn test_token_bucket_allows_burst() {
    todo!("consume up to capacity tokens; assert all succeed")
}

#[test]
fn test_token_bucket_rejects_over_capacity() {
    todo!("exhaust bucket; assert next consume returns false")
}

#[test]
fn test_per_session_limit_independent_of_ip_limit() {
    todo!("different sessions from same IP; verify each session has own counter")
}
