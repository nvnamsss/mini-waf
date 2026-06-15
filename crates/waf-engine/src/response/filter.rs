use waf_types::decision::Decision;

/// Inspect an outbound response body and block or rewrite it if it contains
/// sensitive internal information.
///
/// Blocks on: stack traces, internal IP addresses, API keys, verbose 5xx
/// bodies exceeding the configurable size limit.
pub fn filter_body(
    _status: u16,
    _body: &[u8],
    _max_error_body_bytes: usize,
) -> Result<(), Decision> {
    todo!("regex-scan body for stack traces, internal IPs, secret-like strings; return Block if found")
}

/// Remove response headers that could leak internal information.
/// Strips: `X-Debug`, `X-Internal-*`, `Server` (if configured).
pub fn filter_headers(_headers: &mut std::collections::HashMap<String, String>) {
    todo!("iterate headers, remove those matching the sensitive header patterns")
}
