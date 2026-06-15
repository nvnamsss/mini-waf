/// Classifications for a source IP's ASN type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsnClass {
    Residential,
    Datacenter,
    Tor,
    VPN,
    Unknown,
}

/// Look up the ASN for `ip` and classify it.
pub fn classify(_ip: &str) -> AsnClass {
    todo!("look up ASN in loaded MaxMind/ASN database; map ASN to AsnClass")
}

/// Returns `true` if the source IP belongs to a datacenter or Tor exit node.
pub fn is_suspicious(class: AsnClass) -> bool {
    matches!(class, AsnClass::Datacenter | AsnClass::Tor)
}
