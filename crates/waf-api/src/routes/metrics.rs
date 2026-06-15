use axum::{extract::State, Json};
use serde::Serialize;

use waf_engine::state::store::AppState;

/// GET /api/metrics — return a snapshot of current attack statistics.
pub async fn get_metrics(_state: State<AppState>) -> Json<MetricsSnapshot> {
    Json(MetricsSnapshot {
        total_requests: 0,
        blocked: 0,
        challenged: 0,
        rate_limited: 0,
        by_attack_type: std::collections::HashMap::new(),
        top_ips: vec![],
        route_heatmap: std::collections::HashMap::new(),
    })
}

#[derive(Serialize)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub blocked: u64,
    pub challenged: u64,
    pub rate_limited: u64,
    pub by_attack_type: std::collections::HashMap<String, u64>,
    pub top_ips: Vec<IpCount>,
    pub route_heatmap: std::collections::HashMap<String, u64>,
}

#[derive(Serialize)]
pub struct IpCount {
    pub ip: String,
    pub requests: u64,
}
