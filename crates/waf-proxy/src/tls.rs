/// TLS termination support (bonus feature).
///
/// Handles TLS handshake, exposes JA3/JA4 fingerprints extracted from the
/// ClientHello, and optionally enforces mTLS client certificate validation.

/// Configuration for TLS termination.
pub struct TlsConfig {
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
    /// If set, require and validate client certificates (mTLS).
    pub client_ca_path: Option<std::path::PathBuf>,
    /// Allowed cipher suites (TLS 1.3 names).
    pub cipher_suites: Vec<String>,
}

/// Accept a TLS connection, return the decrypted stream plus the extracted
/// TLS fingerprint components.
pub async fn accept_tls(
    _tcp_stream: tokio::net::TcpStream,
    _config: &TlsConfig,
) -> anyhow::Result<TlsSession> {
    todo!("perform TLS handshake via rustls/tokio-rustls; capture ClientHello for JA3/JA4")
}

pub struct TlsSession {
    pub stream: tokio::net::TcpStream,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub sni: Option<String>,
}
