//! The hosted Origin Cloud MCP server: the tools of
//! [origincloudhq/mcp](https://github.com/origincloudhq/mcp) over MCP's
//! Streamable HTTP transport, as an OAuth resource server.
//!
//! - A request without a bearer token issued for this server is answered
//!   `401` with a `WWW-Authenticate` challenge naming the protected resource
//!   metadata (RFC 9728), which names the authorization server.
//! - A tool call reaches the API with a token exchanged for the caller's
//!   (RFC 8693), never with the caller's own; see [`exchange`].
//! - The connection's toolsets and read-only mode come from the URL's query;
//!   see [`options`].
//!
//! The server keeps no MCP sessions: each request is served on its own, so
//! that any replica can answer any request. A caller's SDK client is kept
//! across requests ([`clients`]), so that reads see the caller's writes.

mod auth;
mod clients;
pub mod config;
mod exchange;
mod metrics;
pub mod options;
mod session;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use http::{header, HeaderName, HeaderValue, Method, StatusCode};
use origincloud_mcp::Defaults;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

use crate::auth::{Authenticator, Caller, Issuer, Refusal};
use crate::clients::{Api, Registry};
use crate::config::Config;
use crate::exchange::Exchanger;
use crate::session::Session;

/// How often the issuer's configuration is asked for until it answers.
const DISCOVERY_RETRY: Duration = Duration::from_secs(5);

/// The server: its routes and what they share.
#[derive(Clone)]
pub struct Server {
    state: Arc<Shared>,
}

struct Shared {
    config: Config,
    issuer: Arc<Issuer>,
    authenticator: Authenticator,
    registry: Arc<Registry>,
    transport: StreamableHttpServerConfig,
    cancel: CancellationToken,
    stopping: AtomicBool,
}

impl Server {
    /// A server as `config` says. Nothing is asked of the issuer yet.
    pub fn new(config: Config) -> anyhow::Result<Self> {
        config.validate()?;
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "origincloud-mcp-server/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;
        let issuer = Arc::new(Issuer::new(config.issuer_id(), http.clone()));
        let authenticator = Authenticator::new(Arc::clone(&issuer), config.accepted_audience());
        let exchanger = Arc::new(Exchanger::new(
            http.clone(),
            Arc::clone(&issuer),
            config.exchange_client_id.clone(),
            config.exchange_client_secret.clone(),
            config.api_audience.clone(),
        ));
        let registry = Arc::new(Registry::new(
            Api {
                region: config.api_region.clone(),
                endpoint: config.api_endpoint.clone(),
            },
            exchanger,
            http,
        ));
        let cancel = CancellationToken::new();
        let transport = StreamableHttpServerConfig::default()
            .with_allowed_hosts(config.hosts())
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_cancellation_token(cancel.clone());
        Ok(Self {
            state: Arc::new(Shared {
                config,
                issuer,
                authenticator,
                registry,
                transport,
                cancel,
                stopping: AtomicBool::new(false),
            }),
        })
    }

    /// The MCP endpoint and the protected resource metadata.
    pub fn router(&self) -> Router {
        let config = &self.state.config;
        let mut router = Router::new()
            .route(&config.endpoint_path(), any(mcp))
            .route(&config.metadata_path(), get(metadata));
        // Clients that don't follow the challenge look for the metadata at
        // the root as well.
        if config.metadata_path() != "/.well-known/oauth-protected-resource" {
            router = router.route("/.well-known/oauth-protected-resource", get(metadata));
        }
        let request_id = HeaderName::from_static("x-request-id");
        router
            .with_state(Arc::clone(&self.state))
            .layer(axum::middleware::from_fn(metrics::requests))
            // Browser-based clients: the token is a header, never a cookie,
            // so any origin may send one.
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods([Method::GET, Method::POST, Method::DELETE])
                    .allow_headers([
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                        header::ACCEPT,
                        HeaderName::from_static("mcp-protocol-version"),
                        HeaderName::from_static("mcp-session-id"),
                        HeaderName::from_static("last-event-id"),
                    ])
                    .expose_headers([
                        header::WWW_AUTHENTICATE,
                        HeaderName::from_static("mcp-session-id"),
                    ]),
            )
            .layer(PropagateRequestIdLayer::new(request_id.clone()))
            .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
    }

    /// `/metrics`, `/healthz` and `/readyz`, for the metrics port.
    pub fn metrics_router(&self) -> Router {
        Router::new()
            .route("/metrics", get(|| async { metrics::render() }))
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz", get(ready))
            .with_state(Arc::clone(&self.state))
    }

    /// Whether the server is ready for requests: it has read the issuer's
    /// configuration, and isn't stopping.
    pub fn is_ready(&self) -> bool {
        self.state.issuer.discovered() && !self.state.stopping.load(Ordering::Relaxed)
    }

    /// Reads the issuer's configuration and keys, asking again until it
    /// answers, so that the first request doesn't wait for them.
    pub fn discover_in_background(&self) {
        let issuer = Arc::clone(&self.state.issuer);
        tokio::spawn(async move {
            loop {
                match issuer.keys_for(None).await {
                    Ok(_) => {
                        tracing::info!(
                            issuer = issuer.id(),
                            "read the issuer's configuration and keys"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "the issuer's configuration or keys couldn't be read; asking again");
                        tokio::time::sleep(DISCOVERY_RETRY).await;
                    }
                }
            }
        });
    }

    /// Serves on `listener` and `metrics` until `shutdown` completes, then
    /// reports unready for the configured time, stops accepting, and lets
    /// the requests in flight finish for the drain time.
    pub async fn run(
        self,
        listener: TcpListener,
        metrics: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> anyhow::Result<()> {
        self.discover_in_background();
        let state = Arc::clone(&self.state);
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        tokio::spawn(async move {
            shutdown.await;
            tracing::info!("stopping: reporting unready");
            state.stopping.store(true, Ordering::Relaxed);
            tokio::time::sleep(state.config.unready_on_stop()).await;
            tracing::info!("stopping: no new connections");
            stop.cancel();
        });
        let metrics_server = axum::serve(metrics, self.metrics_router())
            .with_graceful_shutdown(stopped.clone().cancelled_owned());
        let metrics_task = tokio::spawn(async move { metrics_server.await });
        let main = axum::serve(listener, self.router())
            .with_graceful_shutdown(stopped.clone().cancelled_owned());
        let drain = self.state.config.drain();
        let served = tokio::spawn(async move { main.await });
        stopped.cancelled().await;
        match tokio::time::timeout(drain, served).await {
            Ok(result) => result??,
            Err(_) => tracing::warn!(
                seconds = drain.as_secs(),
                "requests still in flight after the drain; stopping all the same"
            ),
        }
        self.state.cancel.cancel();
        metrics_task.abort();
        Ok(())
    }
}

/// The MCP endpoint: the connection's options from the query, the caller
/// from the bearer token, then the request served by a session of its own.
async fn mcp(State(state): State<Arc<Shared>>, mut request: Request) -> Response {
    let defaults = Defaults {
        region: state.config.api_region.clone(),
        ..Defaults::default()
    };
    let options =
        match options::parse(request.uri().query(), defaults) {
            Ok(options) => options,
            Err(error) => return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_request", "error_description": error.to_string() })),
            )
                .into_response(),
        };
    let caller = match state.authenticator.authenticate(request.headers()).await {
        Ok(caller) => caller,
        Err(refusal) => return refuse(&state, refusal),
    };
    let logged = metrics::Logged {
        subject: caller.subject.clone(),
        client: caller.client.clone(),
    };
    request.extensions_mut().insert::<Caller>(caller);
    let registry = Arc::clone(&state.registry);
    let service = StreamableHttpService::new(
        move || Session::new(Arc::clone(&registry), options.clone()).map_err(std::io::Error::other),
        Arc::new(NeverSessionManager::default()),
        state.transport.clone(),
    );
    let mut response = service.handle(request).await.map(Body::new);
    response.extensions_mut().insert(logged);
    response
}

/// The answer to a request whose token was refused.
fn refuse(state: &Shared, refusal: Refusal) -> Response {
    metrics::refusal(refusal.reason());
    let config = &state.config;
    match refusal {
        Refusal::Unavailable(error) => {
            tracing::error!(%error, "a token couldn't be checked");
            let mut response = (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "temporarily_unavailable", "error_description": "the authorization server can't be reached" })),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            response
        }
        refusal => {
            if let Refusal::Invalid(reason) = &refusal {
                tracing::info!(reason, "refused a token");
            }
            let challenge = auth::challenge(&config.metadata_url(), &config.scopes, &refusal);
            let error = match refusal {
                Refusal::Invalid(_) => "invalid_token",
                _ => "unauthorized",
            };
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": error, "error_description": refusal.to_string() })),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
            response
        }
    }
}

/// The protected resource metadata (RFC 9728, section 2).
async fn metadata(State(state): State<Arc<Shared>>) -> Response {
    let config = &state.config;
    let mut document = json!({
        "resource": config.canonical_resource(),
        "authorization_servers": [config.issuer_id()],
        "bearer_methods_supported": ["header"],
        "resource_name": "Origin Cloud",
    });
    let scopes: Vec<&String> = config.scopes.iter().filter(|s| !s.is_empty()).collect();
    if !scopes.is_empty() {
        document["scopes_supported"] = json!(scopes);
    }
    let mut response = Json(document).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
}

async fn ready(State(state): State<Arc<Shared>>) -> Response {
    if state.issuer.discovered() && !state.stopping.load(Ordering::Relaxed) {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
}
