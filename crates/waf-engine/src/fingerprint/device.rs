/// Inputs used to derive a stable device fingerprint.
pub struct DeviceComponents<'a> {
    pub ja3: Option<&'a str>,
    pub ja4: Option<&'a str>,
    pub user_agent: &'a str,
    pub accept_encoding: Option<&'a str>,
    /// HTTP/2 SETTINGS frame values, if available.
    pub h2_settings: Option<&'a str>,
}

/// Derive a stable device fingerprint ID from the available components.
/// Returns a hex string that persists as long as the device characteristics
/// remain the same, even across IP rotations.
pub fn derive_device_id(_components: &DeviceComponents<'_>) -> String {
    todo!("hash non-null components together with a stable algorithm (SHA-256 truncated)")
}
