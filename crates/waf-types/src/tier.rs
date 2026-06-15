use serde::{Deserialize, Serialize};

/// Protection tier assigned to a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Critical,
    High,
    Medium,
    CatchAll,
}

/// What the WAF does when it encounters an internal error on a given tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Deny all traffic — used for CRITICAL routes.
    Close,
    /// Pass traffic through — used for MEDIUM / CATCH-ALL.
    Open,
}

impl Tier {
    /// Return the configured fail-mode for this tier.
    /// The actual mapping is driven by config; this is the safe default.
    pub fn default_fail_mode(&self) -> FailMode {
        todo!("return fail mode based on tier — load from config in production")
    }

    /// Classify an HTTP path into the appropriate tier.
    pub fn from_path(_path: &str) -> Tier {
        todo!("match path against tier route patterns from config")
    }
}
