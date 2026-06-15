/// Compute a JA3 fingerprint hash from TLS ClientHello fields.
///
/// JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
pub fn compute(_tls_client_hello_bytes: &[u8]) -> Option<String> {
    todo!("parse TLS ClientHello, extract fields, format JA3 string, return MD5 hex")
}
