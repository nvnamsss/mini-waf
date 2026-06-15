use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use waf_types::tier::{FailMode, Tier};

/// Top-level WAF configuration loaded from `config/waf.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub dashboard_api: DashboardApiConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    pub tiers: HashMap<String, TierConfig>,
    pub risk: RiskConfig,
    pub rate_limit: RateLimitConfig,
    pub cache: CacheConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub geo: GeoConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    /// Default upstream used when no routing rule matches.
    pub upstream: String,
    /// Named backend upstreams referenced by routing rules (`upstream_backend` field).
    #[serde(default)]
    pub backends: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardApiConfig {
    pub bind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Directory containing `*.yaml` rule files.
    pub dir: String,
    /// Optional directory containing OWASP CRS `.conf` rule files.
    /// When set, `crs_score()` and `crs_match()` GRL functions are available.
    #[serde(default)]
    pub crs_dir: Option<String>,
    /// Optional path to a newline-delimited file of IPs/CIDRs to block.
    /// Loaded once at startup into the in-memory blacklist.
    #[serde(default)]
    pub blacklist_file: Option<String>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        RulesConfig { dir: "config/rules".to_string(), crs_dir: None, blacklist_file: None }
    }
}

/// Per-tier policy, loaded from config so fail_mode is never hardcoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfig {
    pub tier: Tier,
    pub routes: Vec<String>,
    pub fail_mode: FailMode,
    pub max_rps_per_ip: Option<u32>,
    pub max_rps_per_session: Option<u32>,
    pub cache_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    pub allow_threshold: u32,
    pub challenge_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub default_rps_per_ip: u32,
    pub default_rps_per_session: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub ttl_medium_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive upstream failures before opening the circuit.
    pub failure_threshold: u32,
    /// Seconds before the circuit half-opens for a probe request.
    pub recovery_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub log_path: String,
}

/// Geo-blocking configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoConfig {
    /// Optional path to a MaxMind `GeoLite2-Country.mmdb` file.
    /// When absent the plugin operates in header-only mode.
    #[serde(default)]
    pub db_path: Option<String>,
    /// Extra request header names (beyond `CF-IPCountry`, `X-Country`, etc.)
    /// to check for a pre-resolved country code.
    #[serde(default)]
    pub country_headers: Vec<String>,
    /// ISO 3166-1 alpha-2 country codes to block.
    /// An empty list disables geo-blocking while still enriching
    /// `Request.Ext["geo.country"]` for use in custom GRL rules.
    #[serde(default)]
    pub blocked_countries: Vec<String>,
}

impl Config {
    /// Load and parse `waf.toml` from the given path.
    pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {:?}: {}", path, e))?;
        let config: Self = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("invalid waf.toml: {}", e))?;
        Ok(config)
    }
}
