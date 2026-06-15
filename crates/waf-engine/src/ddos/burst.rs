use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Per-IP burst detector.  Tracks request arrival times in a short window and
/// auto-blocks IPs that exceed the configured burst threshold.
#[derive(Clone)]
#[allow(dead_code)]
pub struct BurstDetector(Arc<RwLock<HashMap<String, Vec<i64>>>>);

impl BurstDetector {
    pub fn new() -> Self {
        todo!("initialise empty arrival-time map")
    }

    /// Record a new request from `ip`.  Returns `true` if the IP is currently
    /// burst-blocked and the request should be denied.
    pub fn check(&self, _ip: &str, _window_ms: u64, _threshold: u32) -> bool {
        todo!("append timestamp, evict old entries, check count against threshold")
    }
}
