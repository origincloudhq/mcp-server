//! The server's Prometheus metrics, served at `/metrics` on the metrics
//! port.
//!
//! - `origincloud_http_requests_total{method,route,status_class}`,
//!   `origincloud_http_request_duration_seconds{method,route}` and
//!   `origincloud_http_requests_in_flight`: the requests, as Origin Cloud's
//!   other API hosts count them. `route` is the route template, `unmatched`
//!   for a path no route has.
//! - `origincloud_mcp_tool_calls_total{tool,outcome}`: tool calls by tool,
//!   `other` for a tool the connection doesn't expose, and outcome: `ok`,
//!   `error` (the tool's error, such as the API's refusal) or
//!   `protocol_error`.
//! - `origincloud_mcp_token_exchanges_total{outcome}`: `exchanged`,
//!   `cached` (a token exchanged before was used) or `failed`.
//! - `origincloud_mcp_auth_refusals_total{reason}`: requests refused for
//!   their token: `missing`, `invalid` or `unavailable` (the issuer's keys
//!   couldn't be read).
//! - `origincloud_build_info{artifact,version}`: 1.

use std::sync::OnceLock;
use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use http::{Method, StatusCode};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
    in_flight: IntGauge,
    tool_calls: IntCounterVec,
    exchanges: IntCounterVec,
    refusals: IntCounterVec,
}

fn metrics() -> &'static Metrics {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        let registry = Registry::new();
        let counter = |name: &str, help: &str, labels: &[&str]| {
            let c = IntCounterVec::new(Opts::new(name, help), labels).expect("well-formed");
            registry.register(Box::new(c.clone())).expect("registered once");
            c
        };
        let requests = counter(
            "origincloud_http_requests_total",
            "Answered HTTP requests, by method, route template and status class.",
            &["method", "route", "status_class"],
        );
        let tool_calls = counter(
            "origincloud_mcp_tool_calls_total",
            "MCP tool calls, by tool and outcome.",
            &["tool", "outcome"],
        );
        let exchanges = counter(
            "origincloud_mcp_token_exchanges_total",
            "Access tokens for the API, by whether they were exchanged, taken from the cache, or failed.",
            &["outcome"],
        );
        let refusals = counter(
            "origincloud_mcp_auth_refusals_total",
            "Requests refused for their bearer token, by reason.",
            &["reason"],
        );
        let duration = HistogramVec::new(
            HistogramOpts::new(
                "origincloud_http_request_duration_seconds",
                "Time from receiving an HTTP request to producing its response head.",
            )
            .buckets(DURATION_BUCKETS.to_vec()),
            &["method", "route"],
        )
        .expect("well-formed");
        registry
            .register(Box::new(duration.clone()))
            .expect("registered once");
        let in_flight = IntGauge::new(
            "origincloud_http_requests_in_flight",
            "HTTP requests currently being handled.",
        )
        .expect("well-formed");
        registry
            .register(Box::new(in_flight.clone()))
            .expect("registered once");
        let build = IntGaugeVec::new(
            Opts::new("origincloud_build_info", "The running build."),
            &["artifact", "version"],
        )
        .expect("well-formed");
        build
            .with_label_values(&["mcp-server", env!("CARGO_PKG_VERSION")])
            .set(1);
        registry
            .register(Box::new(build))
            .expect("registered once");
        Metrics {
            registry,
            requests,
            duration,
            in_flight,
            tool_calls,
            exchanges,
            refusals,
        }
    })
}

/// The metrics in Prometheus' text format.
pub fn render() -> String {
    let mut out = Vec::new();
    TextEncoder::new()
        .encode(&metrics().registry.gather(), &mut out)
        .expect("text encoding doesn't fail");
    String::from_utf8(out).expect("the text format is UTF-8")
}

pub fn tool_call(tool: &str, outcome: &str) {
    metrics()
        .tool_calls
        .with_label_values(&[tool, outcome])
        .inc();
}

pub fn exchange(outcome: &str) {
    metrics().exchanges.with_label_values(&[outcome]).inc();
}

pub fn refusal(reason: &str) {
    metrics().refusals.with_label_values(&[reason]).inc();
}

/// Who a request was from, which the MCP endpoint puts on its response for
/// the request's log line.
#[derive(Clone)]
pub struct Logged {
    pub subject: String,
    pub client: Option<String>,
}

/// Counts and times a request, and logs it. Applied with
/// `axum::middleware::from_fn` through `Router::layer`, after routing, so
/// that the route template is known.
pub async fn requests(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let method = method_label(request.method());
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let m = metrics();
    m.in_flight.inc();
    let _in_flight = InFlight;
    let started = Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed();
    m.duration
        .with_label_values(&[method, &route])
        .observe(elapsed.as_secs_f64());
    m.requests
        .with_label_values(&[method, &route, status_class(response.status())])
        .inc();
    let caller = response.extensions().get::<Logged>();
    tracing::info!(
        method,
        route,
        status = response.status().as_u16(),
        duration_ms = elapsed.as_millis() as u64,
        request_id,
        subject = caller.map(|c| c.subject.as_str()).unwrap_or_default(),
        client = caller.and_then(|c| c.client.as_deref()).unwrap_or_default(),
        "request"
    );
    response
}

struct InFlight;

impl Drop for InFlight {
    fn drop(&mut self) {
        metrics().in_flight.dec();
    }
}

fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        _ => "5xx",
    }
}
