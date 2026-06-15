use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// Token-bucket state per key, used for burst control on top of sliding windows.
#[derive(Clone)]
#[allow(dead_code)]
pub struct TokenBucketStore(Arc<RwLock<HashMap<String, BucketState>>>);

#[allow(dead_code)]
struct BucketState {
    tokens: f64,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill_ms: i64,
}

impl TokenBucketStore {
    pub fn new() -> Self {
        todo!("initialise empty bucket map")
    }

    /// Consume one token for `key`. Returns `true` if a token was available.
    pub fn consume(&self, _key: &str, _capacity: f64, _refill_rate: f64) -> bool {
        todo!("refill bucket based on elapsed time, then attempt to consume one token")
    }
}
