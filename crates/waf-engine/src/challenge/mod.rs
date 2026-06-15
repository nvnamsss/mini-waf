pub mod js_challenge;
pub mod pow;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// In-flight challenge state keyed by session/IP.
#[derive(Clone)]
#[allow(dead_code)]
pub struct ChallengeStore(Arc<RwLock<HashMap<String, ChallengeRecord>>>);

pub struct ChallengeRecord {
    pub challenge_type: waf_types::decision::ChallengeKind,
    pub nonce: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

impl ChallengeStore {
    pub fn new() -> Self {
        ChallengeStore(Arc::new(RwLock::new(HashMap::new())))
    }

    pub fn issue(&self, _key: &str, _kind: waf_types::decision::ChallengeKind) -> ChallengeRecord {
        todo!("generate nonce, store record with TTL, return it")
    }

    pub fn verify(&self, _key: &str, _response: &str) -> bool {
        todo!("look up record, validate response against nonce, remove on success")
    }
}
