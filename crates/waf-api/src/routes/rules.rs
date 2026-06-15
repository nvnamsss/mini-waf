use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use waf_engine::state::store::AppState;

/// GET /api/rules — return the current hot-loaded rule list.
pub async fn list_rules(_state: State<AppState>) -> Response {
    (StatusCode::OK, [("content-type", "application/json")], "[]").into_response()
}

/// POST /api/rules — add or replace a rule without restarting.
pub async fn upsert_rule(
    _state: State<AppState>,
    _body: axum::body::Bytes,
) -> StatusCode {
    // TODO: validate and hot-load rule
    StatusCode::OK
}

/// DELETE /api/rules/:id — remove a rule by its ID.
pub async fn delete_rule(
    _state: State<AppState>,
    axum::extract::Path(_id): axum::extract::Path<String>,
) -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Response body for rule mutation endpoints.
#[derive(Serialize, Deserialize)]
pub struct RuleResponse {
    pub ok: bool,
    pub message: String,
}
