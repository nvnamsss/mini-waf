use std::sync::{
    atomic::AtomicU32,
    Arc,
};

/// Circuit-breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,   // normal — requests flow through
    Open,     // tripped — requests fail fast with 503
    HalfOpen, // probe — one request allowed through to test recovery
}

/// Forward an HTTP request to the upstream backend, running it through the
/// circuit breaker.  Returns 503 if the circuit is open or the upstream
/// fails to respond within the deadline.
pub async fn forward(
    _request: hyper::Request<hyper::body::Incoming>,
    _upstream_url: &str,
    _circuit: &CircuitBreaker,
) -> anyhow::Result<hyper::Response<hyper::body::Incoming>> {
    todo!("send request via hyper client; on timeout/error record failure; on success record success")
}

/// Thread-safe circuit breaker shared across all request handler tasks.
#[allow(dead_code)]
pub struct CircuitBreaker {
    state: Arc<std::sync::RwLock<CircuitState>>,
    consecutive_failures: Arc<AtomicU32>,
    failure_threshold: u32,
    recovery_secs: u64,
    last_tripped_at: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_secs: u64) -> Self {
        CircuitBreaker {
            state: Arc::new(std::sync::RwLock::new(CircuitState::Closed)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            failure_threshold,
            recovery_secs,
            last_tripped_at: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn state(&self) -> CircuitState {
        todo!("read current state")
    }

    pub fn record_success(&self) {
        todo!("reset failure counter, close circuit if half-open")
    }

    pub fn record_failure(&self) {
        todo!("increment counter; trip to Open if threshold exceeded")
    }
}
