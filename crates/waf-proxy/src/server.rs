use std::time::Duration;

use http_body_util::Full;
use bytes::Bytes;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use waf_engine::state::store::AppState;

use crate::handler::handle_request;

/// Bind the HTTP listener and start accepting connections.
/// Every accepted connection is handled by `handler::handle_request`.
pub async fn serve(bind_addr: &str, state: AppState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!("proxy listening on {}", bind_addr);

    // Single shared HTTP client with connection pooling — reused across all requests
    // so we never exhaust ephemeral ports under high concurrency.
    // http1_only: all backends are plain HTTP/1.1; no upgrade negotiation.
    // pool_idle_timeout: evict idle connections before the backend closes them,
    //   which prevents "client error (SendRequest)" on stale pool entries.
    let http_client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(20))
            .build(HttpConnector::new());

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();
        let client = http_client.clone();
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                let client = client.clone();
                async move {
                    let resp = handle_request(req, state, client).await;
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });

            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                tracing::debug!("connection error from {}: {}", peer_addr, err);
            }
        });
    }
}
