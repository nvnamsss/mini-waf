use axum::{extract::State, http::StatusCode};
use serde::Deserialize;

use waf_engine::state::store::AppState;

/// POST /api/config — update runtime thresholds and feature toggles
/// without restarting the WAF.
pub async fn update_config(
    _state: State<AppState>,
    body: axum::body::Bytes,
) -> StatusCode {
    if serde_json::from_slice::<ConfigPatch>(&body).is_err() {
        return StatusCode::UNPROCESSABLE_ENTITY;
    }
    // TODO: apply patch to live config
    StatusCode::OK
}

/// Partial config update — all fields are optional so callers can send only
/// what they want to change.
#[derive(Debug, Deserialize)]
pub struct ConfigPatch {
    pub allow_threshold: Option<u32>,
    pub challenge_threshold: Option<u32>,
    pub default_rps_per_ip: Option<u32>,
    pub default_rps_per_session: Option<u32>,
}
