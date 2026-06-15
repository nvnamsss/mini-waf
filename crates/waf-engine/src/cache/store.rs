use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use waf_types::tier::Tier;

/// A simple LRU + TTL response cache.
/// CRITICAL tier is never cached; MEDIUM tier uses aggressive caching.
#[derive(Clone)]
#[allow(dead_code)]
pub struct CacheStore(Arc<RwLock<HashMap<String, CacheEntry>>>);

#[allow(dead_code)]
struct CacheEntry {
    body: Vec<u8>,
    status: u16,
    headers: HashMap<String, String>,
    expires_at_ms: i64,
}

impl CacheStore {
    pub fn new() -> Self {
        CacheStore(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Returns a cached response if one exists and has not expired.
    pub fn get(&self, _key: &str) -> Option<(u16, HashMap<String, String>, Vec<u8>)> {
        todo!("look up entry, check expiry, return clone of cached response")
    }

    /// Store a response for `key` with a TTL based on the route tier.
    pub fn put(&self, _key: &str, _status: u16, _headers: HashMap<String, String>, _body: Vec<u8>, _tier: Tier) {
        todo!("reject CRITICAL tier; compute TTL from tier config; insert entry")
    }

    /// Build a canonical cache key from method + path + relevant headers.
    pub fn make_key(_method: &str, _path: &str) -> String {
        todo!("hash method + path into a stable cache key")
    }
}
