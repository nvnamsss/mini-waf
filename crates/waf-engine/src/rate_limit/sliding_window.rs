use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Per-key sliding-window counters for rate limiting.
///
/// Key can be an IP address string or a session-ID string.
#[derive(Clone)]
#[allow(dead_code)]
pub struct SlidingWindowStore(Arc<RwLock<HashMap<String, WindowState>>>);

#[allow(dead_code)]
struct WindowState {
    /// Request timestamps (ms) within the current window.
    timestamps: Vec<i64>,
    window_ms: u64,
    max_requests: u32,
}

impl SlidingWindowStore {
    pub fn new() -> Self {
        SlidingWindowStore(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Returns `true` if the key is within its allowed rate; `false` if exceeded.
    pub fn check_and_record(&self, _key: &str, _window_ms: u64, _max: u32) -> bool {
        todo!("slide window to now, evict old timestamps, count, record if allowed")
    }
}
