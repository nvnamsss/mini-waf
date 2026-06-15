use axum::{
    extract::{State, WebSocketUpgrade},
    response::IntoResponse,
};

use waf_engine::state::store::AppState;

/// WS /ws/feed — upgrade to WebSocket and stream live `AuditEntry` events
/// to the dashboard as newline-delimited JSON.
pub async fn live_feed(
    ws: WebSocketUpgrade,
    _state: State<AppState>,
) -> impl IntoResponse {
    // TODO: subscribe to audit broadcast; forward entries as WS text frames
    ws.on_upgrade(|mut socket| async move {
        // keep connection open until client disconnects
        while socket.recv().await.is_some() {}
    })
}
