use std::{path::PathBuf, sync::Arc, time::Duration};

use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind};
use tokio::sync::mpsc;

use crate::rules::{
    loader::{load_from_dir, load_grl_from_dir},
    rete::{engine::Engine, Network},
    store::RuleStore,
};

/// Spawn a background task that watches `rules_dir` for filesystem changes
/// and triggers a hot-reload on the provided `RuleStore`.
pub async fn start_watcher(rules_dir: PathBuf, store: Arc<RuleStore>) -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel::<notify::Result<notify::Event>>(32);

    let mut watcher = RecommendedWatcher::new(
        move |res| { let _ = tx.blocking_send(res); },
        notify::Config::default().with_poll_interval(Duration::from_secs(2)),
    )?;

    watcher.watch(&rules_dir, RecursiveMode::NonRecursive)?;

    tokio::spawn(async move {
        // Keep watcher alive for the lifetime of the task.
        let _watcher = watcher;

        while let Some(event) = rx.recv().await {
            let event = match event {
                Ok(e) => e,
                Err(e) => { tracing::warn!("watcher error: {}", e); continue; }
            };

            let is_rules_change = matches!(
                event.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
            ) && event.paths.iter().any(|p| {
                matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml" | "grl"))
            });

            if !is_rules_change { continue; }

            tracing::info!("rules change detected, reloading");

            // Reload YAML rules (legacy routing path).
            match load_from_dir(&rules_dir) {
                Ok(rules) => store.reload(rules),
                Err(e)    => tracing::error!("failed to reload yaml rules: {}", e),
            }

            // Reload and recompile GRL rules into a new RETE engine.
            match load_grl_from_dir(&rules_dir) {
                Ok(asts) => {
                    let network = Network::compile(asts);
                    store.reload_engine(Engine::new(network));
                    tracing::info!("rete engine reloaded");
                }
                Err(e) => tracing::error!("failed to reload grl rules: {}", e),
            }
        }
    });

    Ok(())
}
