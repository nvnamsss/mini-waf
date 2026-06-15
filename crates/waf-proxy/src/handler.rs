use std::collections::HashMap;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use waf_engine::{
    context::RequestContext,
    pipeline,
    state::store::AppState,
};
use waf_types::{decision::Decision, risk::RiskScore, tier::Tier};

/// Process a single inbound HTTP request end-to-end:
///
/// 1. Build `RequestContext` from raw request data.
/// 2. Run `pipeline::run_inbound` → get `Decision`.
/// 3. If `Decision::Allow`:
///    a. Forward to upstream via hyper client.
///    b. Return upstream response to client.
/// 4. If `Decision::Block` / `Decision::Challenge` / `Decision::RateLimit`:
///    return the appropriate HTTP error response.
pub async fn handle_request(
    raw_request: Request<Incoming>,
    state: AppState,
    http_client: Client<HttpConnector, Full<Bytes>>,
) -> Response<Full<Bytes>> {
    let method = raw_request.method().to_string();
    let path = raw_request.uri().path().to_string();
    let query = raw_request.uri().query().map(|q| q.to_string());

    let headers: HashMap<String, String> = raw_request
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let xff = headers.get("x-forwarded-for").cloned();

    let (parts, body) = raw_request.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return json_error(400, "failed to read request body"),
    };

    let mut ctx = RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        arrived_at_ms: chrono::Utc::now().timestamp_millis(),
        method,
        path: path.clone(),
        query: query.clone(),
        tier: Tier::CatchAll,
        client_ip: "0.0.0.0".to_string(),
        xff_header: xff,
        headers,
        body: if body_bytes.is_empty() { None } else { Some(body_bytes.to_vec()) },
        session_id: None,
        device_fp: None,
        risk_score: RiskScore::ZERO,
        matched_rule_id: None,
        extensions: HashMap::new(),
    };

    match pipeline::run_inbound(&mut ctx, &state).await {
        Decision::Allow => {
            let upstream = resolve_upstream(&ctx.path, &state);
            let rebuilt = Request::from_parts(parts, Full::new(body_bytes));
            match forward(rebuilt, &upstream, &path, query.as_deref(), &http_client).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!("upstream error: {}", e);
                    json_error(502, "upstream unavailable")
                }
            }
        }
        Decision::Block { reason } => json_error(403, &format!("blocked: {}", reason)),
        Decision::Challenge(_) => json_error(403, "challenge required"),
        Decision::RateLimit { retry_after_secs } => Response::builder()
            .status(429)
            .header("Retry-After", retry_after_secs.to_string())
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"error":"rate limit exceeded"}"#)))
            .unwrap(),
    }
}

/// Select the upstream URL for the given path.
/// Walks rules sorted by priority; returns the URL for the first rule that
/// has `upstream_backend` set and whose condition matches the path.
/// Falls back to `config.server.upstream` if no routing rule matches.
fn resolve_upstream(path: &str, state: &AppState) -> String {
    for rule in state.rules.snapshot() {
        let Some(backend_name) = &rule.upstream_backend else { continue };
        if path_condition_matches(&rule.condition, path) {
            if let Some(url) = state.config.server.backends.get(backend_name) {
                tracing::debug!(path, backend = %backend_name, "routing rule matched");
                return url.clone();
            }
        }
    }
    state.config.server.upstream.clone()
}

fn path_condition_matches(condition: &waf_engine::rules::rule::Condition, path: &str) -> bool {
    use waf_engine::rules::rule::Condition;
    match condition {
        Condition::PathExact { value } => value == path,
        Condition::PathWildcard { pattern } => wildcard_matches(pattern, path),
        Condition::And(conditions) => conditions.iter().all(|c| path_condition_matches(c, path)),
        Condition::Or(conditions) => conditions.iter().any(|c| path_condition_matches(c, path)),
        _ => false,
    }
}

/// Glob-style path matching: `/**` = everything, `/prefix/*` = prefix match.
fn wildcard_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/**" || pattern == "/*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{}/", prefix));
    }
    pattern == path
}

async fn forward(
    req: Request<Full<Bytes>>,
    upstream_base: &str,
    path: &str,
    query: Option<&str>,
    client: &Client<HttpConnector, Full<Bytes>>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let upstream_uri: hyper::Uri = upstream_base.parse()?;
    let host = upstream_uri.host().unwrap_or("127.0.0.1").to_string();
    let port = upstream_uri.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let target_uri: hyper::Uri = match query {
        Some(q) => format!("{}{}?{}", upstream_base, path, q).parse()?,
        None    => format!("{}{}", upstream_base, path).parse()?,
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri;
    // Strip hop-by-hop headers — these must not be forwarded by a proxy.
    // Forwarding "Connection: keep-alive" or "Connection: close" confuses the
    // pool and causes stale-connection "SendRequest" errors under load.
    parts.headers.remove(hyper::header::CONNECTION);
    parts.headers.remove("keep-alive");
    parts.headers.remove(hyper::header::TRANSFER_ENCODING);
    parts.headers.remove(hyper::header::UPGRADE);
    parts.headers.insert(
        hyper::header::HOST,
        hyper::header::HeaderValue::from_str(&addr)?,
    );

    let upstream_resp = client.request(Request::from_parts(parts, body)).await?;
    let (resp_parts, resp_body) = upstream_resp.into_parts();
    let resp_bytes = resp_body.collect().await?.to_bytes();

    Ok(Response::from_parts(resp_parts, Full::new(resp_bytes)))
}

fn json_error(status: u16, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({"error": msg}).to_string();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}
