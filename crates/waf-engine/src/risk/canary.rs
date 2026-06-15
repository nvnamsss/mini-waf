/// Paths that are honeypot/canary endpoints.
/// Any request that hits one of these immediately sets the risk score to MAX.
#[allow(dead_code)]
const CANARY_PATHS: &[&str] = &["/admin-test", "/api-debug", "/.env", "/phpmyadmin"];

/// Returns `true` if `path` is a known canary endpoint.
pub fn is_canary(_path: &str) -> bool {
    todo!("check path against CANARY_PATHS list (also support config-defined canaries)")
}
