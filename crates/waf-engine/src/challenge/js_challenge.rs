/// Generate the HTML/JS snippet that the browser must execute to pass the
/// JS challenge.  The snippet computes a result from `nonce` and POSTs it back.
pub fn issue_challenge(_nonce: &str) -> String {
    todo!("return HTML page with embedded JS that solves the challenge and redirects")
}

/// Verify the browser-submitted JS challenge response.
pub fn verify_response(_nonce: &str, _response: &str) -> bool {
    todo!("validate that response is the correct answer for the given nonce")
}
