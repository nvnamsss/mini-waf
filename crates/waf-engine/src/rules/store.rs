use std::sync::{Arc, RwLock};

use crate::rules::rete::engine::Engine;
use crate::rules::rete::Network;
use crate::rules::rule::Rule;

/// Thread-safe, hot-swappable rule list + compiled RETE engine.
/// The watcher background task calls `reload()` whenever rule files change.
#[derive(Clone)]
pub struct RuleStore {
    rules:  Arc<RwLock<Vec<Rule>>>,
    engine: Arc<RwLock<Arc<Engine>>>,
}

impl RuleStore {
    pub fn new(initial: Vec<Rule>) -> Self {
        Self {
            rules:  Arc::new(RwLock::new(initial)),
            engine: Arc::new(RwLock::new(Arc::new(Engine::new(Network::default())))),
        }
    }

    /// Replace the YAML rule list (legacy routing path).
    pub fn reload(&self, rules: Vec<Rule>) {
        *self.rules.write().unwrap() = rules;
    }

    /// Replace the compiled RETE engine atomically.
    pub fn reload_engine(&self, engine: Engine) {
        *self.engine.write().unwrap() = Arc::new(engine);
    }

    /// Return a snapshot of the current rules for pipeline evaluation.
    pub fn snapshot(&self) -> Vec<Rule> {
        self.rules.read().unwrap().clone()
    }

    /// Return a cheap-to-clone reference to the current compiled engine.
    pub fn engine(&self) -> Arc<Engine> {
        self.engine.read().unwrap().clone()
    }
}
