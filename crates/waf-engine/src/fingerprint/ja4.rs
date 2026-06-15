/// Compute a JA4 fingerprint from TLS ClientHello fields.
///
/// JA4 is a newer, tag-based alternative to JA3 with improved collision resistance.
pub fn compute(_tls_client_hello_bytes: &[u8]) -> Option<String> {
    todo!("parse TLS ClientHello, build JA4 tag string per spec")
}
