use std::{
    collections::HashSet,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, RwLock},
};

use ipnet::IpNet;

/// A hybrid IP set: `HashSet<IpAddr>` for exact hosts (O(1)), `Vec<IpNet>`
/// for CIDR ranges (O(n_cidrs)).  For a typical blacklist of 100k random IPs
/// the hot path is a single hash-table lookup.
#[derive(Default)]
struct IpSet {
    exact: HashSet<IpAddr>,
    cidrs: Vec<IpNet>,
}

impl IpSet {
    fn insert(&mut self, entry: &str) {
        let net = if let Ok(n) = IpNet::from_str(entry) {
            n
        } else if let Ok(addr) = IpAddr::from_str(entry) {
            // Bare IP → /32 or /128
            IpNet::from(addr)
        } else {
            tracing::warn!("ip_list: skipping unrecognised entry {:?}", entry);
            return;
        };

        // Host routes (/32 IPv4, /128 IPv6) go into the O(1) HashSet.
        let max_prefix = match net.addr() {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if net.prefix_len() == max_prefix {
            self.exact.insert(net.addr());
        } else {
            self.cidrs.push(net);
        }
    }

    fn contains(&self, addr: &IpAddr) -> bool {
        self.exact.contains(addr) || self.cidrs.iter().any(|net| net.contains(addr))
    }
}

/// Thread-safe, cheaply clonable IP blacklist + whitelist.
///
/// Supports exact IPs and CIDR ranges in both lists. An entry that matches
/// the whitelist is always allowed regardless of the blacklist.
#[derive(Clone)]
pub struct IpListStore {
    blacklist: Arc<RwLock<IpSet>>,
    whitelist: Arc<RwLock<IpSet>>,
}

impl IpListStore {
    pub fn new() -> Self {
        IpListStore {
            blacklist: Arc::new(RwLock::new(IpSet::default())),
            whitelist: Arc::new(RwLock::new(IpSet::default())),
        }
    }

    // ── programmatic mutation ─────────────────────────────────────────────

    /// Add a single IP or CIDR range to the blacklist.
    pub fn add_to_blacklist(&self, entry: &str) {
        self.blacklist.write().unwrap().insert(entry);
    }

    /// Add a single IP or CIDR range to the whitelist.
    pub fn add_to_whitelist(&self, entry: &str) {
        self.whitelist.write().unwrap().insert(entry);
    }

    // ── file loading ──────────────────────────────────────────────────────

    /// Load entries from a newline-delimited file into the blacklist.
    ///
    /// Lines starting with `#` and blank lines are ignored.
    pub fn load_blacklist_from_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut set = self.blacklist.write().unwrap();
        for line in content.lines() {
            let entry = line.trim();
            if entry.is_empty() || entry.starts_with('#') { continue; }
            set.insert(entry);
        }
        Ok(())
    }

    /// Load entries from a newline-delimited file into the whitelist.
    ///
    /// Lines starting with `#` and blank lines are ignored.
    pub fn load_whitelist_from_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut set = self.whitelist.write().unwrap();
        for line in content.lines() {
            let entry = line.trim();
            if entry.is_empty() || entry.starts_with('#') { continue; }
            set.insert(entry);
        }
        Ok(())
    }

    // ── lookup ────────────────────────────────────────────────────────────

    /// Returns `true` if `ip` matches any whitelist entry.
    pub fn is_whitelisted(&self, ip: &str) -> bool {
        let Ok(addr) = IpAddr::from_str(ip) else { return false };
        self.whitelist.read().unwrap().contains(&addr)
    }

    /// Returns `true` if `ip` matches any blacklist entry AND is not
    /// overridden by the whitelist.
    pub fn is_blacklisted(&self, ip: &str) -> bool {
        let Ok(addr) = IpAddr::from_str(ip) else { return false };
        if self.whitelist.read().unwrap().contains(&addr) { return false; }
        self.blacklist.read().unwrap().contains(&addr)
    }
}
