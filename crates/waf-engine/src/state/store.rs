use std::sync::Arc;

use crate::{
    audit::logger::AuditLogger,
    cache::store::CacheStore,
    challenge::ChallengeStore,
    config::schema::Config,
    geo::GeoPlugin,
    lists::{blacklist_plugin::BlacklistPlugin, ip_list::IpListStore},
    rate_limit::sliding_window::SlidingWindowStore,
    risk::scorer::RiskStore,
    rules::{crs::{CrsPlugin, CrsRuleset}, loader, store::RuleStore},
};

/// Shared, cheaply clonable application state threaded through every request.
/// All fields are wrapped in `Arc` so the proxy can hold a reference without
/// borrowing issues across async await points.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub rules: Arc<RuleStore>,
    pub risk: Arc<RiskStore>,
    pub rate_limits: Arc<SlidingWindowStore>,
    pub cache: Arc<CacheStore>,
    pub ip_lists: Arc<IpListStore>,
    pub challenges: Arc<ChallengeStore>,
    pub audit: Arc<AuditLogger>,
}

impl AppState {
    /// Initialise all sub-stores from a loaded `Config`.
    pub fn init(config: Config) -> anyhow::Result<Self> {
        let audit_path = std::path::PathBuf::from(&config.audit.log_path);
        let audit = AuditLogger::new(audit_path)
            .map_err(|e| anyhow::anyhow!("audit log: {}", e))?;

        let rules_dir = std::path::PathBuf::from(&config.rules.dir);
        let initial_rules = if rules_dir.exists() {
            loader::load_from_dir(&rules_dir).unwrap_or_else(|e| {
                tracing::warn!("failed to load rules from {:?}: {}", rules_dir, e);
                vec![]
            })
        } else {
            tracing::warn!("rules dir {:?} not found, starting with empty rule set", rules_dir);
            vec![]
        };

        // Compile RETE engine from YAML (auto-converted) + .grl files.
        let store = crate::rules::store::RuleStore::new(initial_rules);
        let grl_rules = loader::load_grl_from_dir(&rules_dir).unwrap_or_else(|e| {
            tracing::warn!("failed to compile rule engine from {:?}: {}", rules_dir, e);
            vec![]
        });
        let net = crate::rules::rete::Network::compile(grl_rules);
        tracing::info!(
            "rule engine compiled: {} alpha nodes, {} terminals",
            net.alpha_count(), net.rule_count()
        );
        let ip_lists = Arc::new(IpListStore::new());

        // Load blacklist from file if configured.
        if let Some(ref path_str) = config.rules.blacklist_file {
            let path = std::path::Path::new(path_str);
            match ip_lists.load_blacklist_from_file(path) {
                Ok(()) => tracing::info!("ip_lists: blacklist loaded from {:?}", path),
                Err(e) => tracing::warn!("ip_lists: failed to load blacklist from {:?}: {}", path, e),
            }
        }

        let mut engine = crate::rules::rete::engine::Engine::new(net);
        engine.install(BlacklistPlugin::new(Arc::clone(&ip_lists)));

        // Install the OWASP CRS plugin when crs_dir is configured.
        if let Some(crs_conf_dir) = config.rules.crs_dir.as_deref() {
            let data_dir = rules_dir.join("data");
            match CrsRuleset::load_from_dir(std::path::Path::new(crs_conf_dir), &data_dir) {
                Ok(ruleset) => {
                    engine.install(CrsPlugin::new(Arc::new(ruleset)));
                    tracing::info!("crs: plugin loaded from {:?}", crs_conf_dir);
                }
                Err(e) => tracing::warn!("crs: failed to load ruleset: {}", e),
            }
        }

        // Install the geo-blocking plugin.
        {
            let geo_cfg = &config.geo;
            let plugin = GeoPlugin::new(
                geo_cfg.db_path.as_deref(),
                geo_cfg.country_headers.clone(),
                geo_cfg.blocked_countries.clone(),
            );
            engine.install(plugin);
            tracing::info!(
                blocked_countries = ?config.geo.blocked_countries,
                db_configured = config.geo.db_path.is_some(),
                "geo: plugin installed",
            );
        }

        store.reload_engine(engine);

        Ok(AppState {
            config: Arc::new(config),
            rules: Arc::new(store),
            risk: Arc::new(RiskStore::new()),
            rate_limits: Arc::new(SlidingWindowStore::new()),
            cache: Arc::new(CacheStore::new()),
            ip_lists,
            challenges: Arc::new(ChallengeStore::new()),
            audit: Arc::new(audit),
        })
    }
}
