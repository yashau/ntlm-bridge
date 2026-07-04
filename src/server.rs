use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use axum::routing::get;
use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{info, Level};

use crate::config::Config;
use crate::error::BridgeError;
use crate::proxy::ProxyClient;

#[derive(Clone)]
pub struct AppState {
    pub proxy: Arc<ProxyClient>,
    pub config: Arc<Config>,
}

pub fn router(state: AppState) -> Router {
    let body_limit = state.config.server.max_body_bytes;
    let timeout = Duration::from_secs(state.config.server.request_timeout_secs);

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .fallback(proxy)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            timeout,
        ))
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

pub async fn serve<F>(state: AppState, shutdown: F) -> anyhow::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let bind = state.config.server.bind;
    let app = router(state);
    info!(%bind, "listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// Foreground shutdown future. Waits for Ctrl-C on Windows, or
/// SIGTERM/SIGINT on Unix. Intended for console use; the Windows service
/// path uses its own SCM-driven oneshot instead.
pub async fn ctrl_c_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    info!("shutdown signal received");
}

async fn proxy(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<axum::body::Body>, BridgeError> {
    state
        .proxy
        .forward(&state.config, method, uri, headers, body)
        .await
}

pub fn init_logging(level: &str) -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .init();
    Ok(())
}

impl AppState {
    pub fn from_config(cfg: Config) -> anyhow::Result<Self> {
        cfg.validate()?;
        let proxy = Arc::new(ProxyClient::new(cfg.upstream.clone()));
        Ok(Self {
            proxy,
            config: Arc::new(cfg),
        })
    }
}
