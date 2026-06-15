use axum::{
    Router,
    routing::{delete, get, post},
};
use waf_engine::state::store::AppState;

use crate::routes::{config, feed, metrics, rules};

/// Build and launch the axum-based dashboard API server.
pub async fn serve(bind_addr: &str, state: AppState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/rules", get(rules::list_rules).post(rules::upsert_rule))
        .route("/api/rules/:id", delete(rules::delete_rule))
        .route("/api/metrics", get(metrics::get_metrics))
        .route("/api/config", post(config::update_config))
        .route("/ws/feed", get(feed::live_feed))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("dashboard API listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
