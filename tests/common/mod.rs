//! What the end-to-end tests share: a fake authorization server that signs
//! tokens and exchanges them, a fake API that records what it receives,
//! the server between them on a local port, and MCP clients of it.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::Parser;
use fake_server::{FakeServer, Received, Response};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use origincloud_mcp_server::config::Config;
use origincloud_mcp_server::Server;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use rmcp::service::RunningService;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;

/// The exchange client's credentials the server is configured with.
pub const CLIENT_ID: &str = "mcp-server-test";
pub const CLIENT_SECRET: &str = "exchange-secret";
/// The audience the fake API's tokens are exchanged for.
pub const API_AUDIENCE: &str = "account";

/// The fake authorization server: an OpenID configuration, its key set and
/// a token endpoint that exchanges any token of its own for
/// `exchanged-{sub}-{n}`, recording each exchange.
pub struct Issuer {
    server: FakeServer,
    id: Arc<OnceLock<String>>,
    key: EncodingKey,
    /// A key of the same id that isn't in the key set.
    impostor: EncodingKey,
    pub exchanges: Arc<Mutex<Vec<Received>>>,
    /// Makes the token endpoint refuse every exchange.
    pub refuse: Arc<AtomicBool>,
}

fn key_pair() -> (EncodingKey, Value) {
    let key = SigningKey::random(&mut rand_core::OsRng);
    let pem = key.to_pkcs8_pem(LineEnding::LF).expect("a PEM");
    let point = key.verifying_key().to_encoded_point(false);
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": "key-1",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("y")),
    });
    (
        EncodingKey::from_ec_pem(pem.as_bytes()).expect("an EC key"),
        jwk,
    )
}

/// The claims of a JWT, read without checking it.
pub fn claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a JWT");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64")).expect("JSON")
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl Issuer {
    pub async fn start() -> Self {
        let (key, jwk) = key_pair();
        let (impostor, _) = key_pair();
        let id: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let refuse = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let (seen, issuer, refusing) =
            (Arc::clone(&exchanges), Arc::clone(&id), Arc::clone(&refuse));
        let server = FakeServer::start(move |r: Received| {
            let issuer = issuer.get().cloned().unwrap_or_default();
            let response = match (r.method.as_str(), r.path.as_str()) {
                ("GET", "/realms/test/.well-known/openid-configuration") => Response::json(
                    json!({
                        "issuer": issuer,
                        "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
                        "token_endpoint": format!("{issuer}/protocol/openid-connect/token"),
                    })
                    .to_string(),
                ),
                ("GET", "/realms/test/protocol/openid-connect/certs") => {
                    Response::json(json!({ "keys": [jwk] }).to_string())
                }
                ("POST", "/realms/test/protocol/openid-connect/token") => {
                    let answer = exchange(&r, &count, refusing.load(Ordering::SeqCst));
                    seen.lock().unwrap().push(r.clone());
                    answer
                }
                _ => Response::json("{}").with_status(404),
            };
            async move { response }
        })
        .await;
        id.set(format!("{}/realms/test", server.url())).unwrap();
        Self {
            server,
            id,
            key,
            impostor,
            exchanges,
            refuse,
        }
    }

    /// The issuer identifier.
    pub fn id(&self) -> String {
        self.id.get().unwrap().clone()
    }

    /// A token of `claims`, completed with the issuer and a lifetime
    /// unless they name their own.
    pub fn token(&self, claims: Value) -> String {
        self.sign(&self.key, claims)
    }

    /// A token of exactly `claims`, without the defaults.
    pub fn token_without_defaults(&self, claims: Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("key-1".to_owned());
        jsonwebtoken::encode(&header, &claims, &self.key).expect("a token")
    }

    /// The same, signed with a key the issuer doesn't publish.
    pub fn forged(&self, claims: Value) -> String {
        self.sign(&self.impostor, claims)
    }

    fn sign(&self, key: &EncodingKey, mut claims: Value) -> String {
        let defaults =
            json!({ "iss": self.id(), "iat": now(), "exp": now() + 300, "azp": "origincloud-mcp" });
        for (k, v) in defaults.as_object().unwrap() {
            if claims.get(k).is_none() {
                claims[k] = v.clone();
            }
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("key-1".to_owned());
        jsonwebtoken::encode(&header, &claims, key).expect("a token")
    }

    pub fn exchanges(&self) -> Vec<Received> {
        self.exchanges.lock().unwrap().clone()
    }
}

/// The token endpoint: checks the client's credentials and the grant, and
/// answers with a token naming the subject token's `sub`.
fn exchange(r: &Received, count: &AtomicUsize, refuse: bool) -> Response {
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if r.header("authorization") != Some(basic.as_str()) {
        return Response::json(json!({ "error": "invalid_client" }).to_string()).with_status(401);
    }
    let form: Vec<(String, String)> = url::form_urlencoded::parse(&r.body).into_owned().collect();
    let get = |k: &str| {
        form.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    if refuse
        || get("grant_type").as_deref() != Some("urn:ietf:params:oauth:grant-type:token-exchange")
    {
        return Response::json(
            json!({ "error": "access_denied", "error_description": "Client not allowed to exchange" })
                .to_string(),
        )
        .with_status(400);
    }
    let subject =
        get("subject_token").map(|t| claims(&t)["sub"].as_str().unwrap_or_default().to_owned());
    let n = count.fetch_add(1, Ordering::SeqCst) + 1;
    Response::json(
        json!({
            "access_token": format!("exchanged-{}-{n}", subject.unwrap_or_default()),
            "expires_in": 300,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        })
        .to_string(),
    )
}

/// The fake API, answering with `answer` and recording every request.
pub struct Api {
    pub server: FakeServer,
    received: Arc<Mutex<Vec<Received>>>,
}

impl Api {
    pub async fn start(answer: impl Fn(&Received) -> Response + Send + Sync + 'static) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&received);
        let server = FakeServer::start(move |request: Received| {
            let response = answer(&request);
            seen.lock().unwrap().push(request);
            async move { response }
        })
        .await;
        Self { server, received }
    }

    pub fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

/// The server between the two fakes.
pub struct Harness {
    pub issuer: Issuer,
    pub api: Api,
    /// The server's canonical URI, `http://127.0.0.1:{port}`.
    pub url: String,
    pub metrics_url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

impl Harness {
    pub async fn start(answer: impl Fn(&Received) -> Response + Send + Sync + 'static) -> Self {
        let issuer = Issuer::start().await;
        let api = Api::start(answer).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let metrics_url = format!("http://127.0.0.1:{}", metrics.local_addr().unwrap().port());
        let config = Config::try_parse_from([
            "origincloud-mcp-server",
            "--resource",
            &url,
            "--issuer",
            &issuer.id(),
            "--exchange-client-id",
            CLIENT_ID,
            "--exchange-client-secret",
            CLIENT_SECRET,
            "--api-audience",
            API_AUDIENCE,
            "--api-endpoint",
            &api.server.url(),
            "--drain-seconds",
            "1",
        ])
        .unwrap();
        let server = Server::new(config).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(server.run(listener, metrics, async move {
            let _ = stopped.await;
        }));
        Self {
            issuer,
            api,
            url,
            metrics_url,
            stop: Some(stop),
        }
    }

    /// A token the server accepts, for `sub`.
    pub fn token_for(&self, sub: &str) -> String {
        self.issuer
            .token(json!({ "sub": sub, "aud": [self.url.clone(), "mcp-server-test"] }))
    }

    /// An MCP client connected to the server's URL with `query`, presenting
    /// `token`.
    pub async fn connect(&self, token: &str, query: &str) -> Agent {
        let uri = format!("{}/{query}", self.url);
        let transport = StreamableHttpClientTransport::with_client(
            reqwest::Client::new(),
            StreamableHttpClientTransportConfig::with_uri(uri).auth_header(token.to_owned()),
        );
        Agent(().serve(transport).await.expect("the client connects"))
    }

    /// A raw MCP `initialize` POST, with `authorization` if given.
    pub async fn post(&self, query: &str, authorization: Option<&str>) -> reqwest::Response {
        let mut request = reqwest::Client::new()
            .post(format!("{}/{query}", self.url))
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .body(
                json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": { "name": "test", "version": "0" }
                    }
                })
                .to_string(),
            );
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        request.send().await.unwrap()
    }
}

/// An MCP client, the agent's side.
pub struct Agent(pub RunningService<RoleClient, ()>);

impl Agent {
    pub async fn tools(&self) -> Vec<Tool> {
        self.0.list_all_tools().await.expect("the tools are listed")
    }

    pub async fn call(&self, tool: &str, arguments: Value) -> CallToolResult {
        let Value::Object(arguments) = arguments else {
            panic!("arguments are an object")
        };
        self.0
            .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments))
            .await
            .expect("the call is answered")
    }
}

/// The text of every part of a request: what to search for a token in.
pub fn everything(r: &Received) -> String {
    let mut s = format!("{} {}?{}\n", r.method, r.path, r.query);
    for (name, value) in &r.headers {
        s.push_str(&format!("{name}: {value}\n"));
    }
    s.push_str(&String::from_utf8_lossy(&r.body));
    s
}
