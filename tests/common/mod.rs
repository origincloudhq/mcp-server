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
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
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

/// The audience of the tokens the API takes: not the server's.
pub const API_AUDIENCE: &str = "origincloud:api";
/// The zone of the fake STS, and the workload the server is to it.
pub const ZONE: &str = "test-zone-1";
pub const WORKLOAD_ID: &str = "spiffe://test.example/workload/mcp-server";

/// The fake Keycloak realm: an OpenID configuration and its key set.
pub struct Issuer {
    server: FakeServer,
    id: Arc<OnceLock<String>>,
    key: EncodingKey,
    /// A key of the same id that isn't in the key set.
    impostor: EncodingKey,
    jwk: Value,
}

/// A fresh ES256 key: its PEM, its encoding key and its public JWK.
fn key_pair() -> (String, EncodingKey, Value) {
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
        pem.to_string(),
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
        let (_, key, jwk) = key_pair();
        let (_, impostor, _) = key_pair();
        let id: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        let (issuer, published) = (Arc::clone(&id), jwk.clone());
        let server = FakeServer::start(move |r: Received| {
            let issuer = issuer.get().cloned().unwrap_or_default();
            let response = match (r.method.as_str(), r.path.as_str()) {
                ("GET", "/realms/test/.well-known/openid-configuration") => Response::json(
                    json!({
                        "issuer": issuer,
                        "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
                    })
                    .to_string(),
                ),
                ("GET", "/realms/test/protocol/openid-connect/certs") => {
                    Response::json(json!({ "keys": [published] }).to_string())
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
            jwk,
        }
    }

    /// The issuer identifier.
    pub fn id(&self) -> String {
        self.id.get().unwrap().clone()
    }

    /// The public key a token of this realm is checked with.
    pub fn public_key(&self) -> Value {
        self.jwk.clone()
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
}

/// The server's workload certificate in a directory, as the enrolment client
/// keeps it, and its public key. The certificates are placeholders: only
/// the key is used.
pub struct WorkloadFiles {
    pub dir: tempfile::TempDir,
    pub public_key: Value,
}

impl WorkloadFiles {
    pub fn new() -> Self {
        let (pem, _, jwk) = key_pair();
        let dir = tempfile::tempdir().unwrap();
        let certificate = |name: &str, body: &[u8]| {
            let pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                STANDARD.encode(body)
            );
            std::fs::write(dir.path().join(name), pem).unwrap();
        };
        std::fs::write(dir.path().join("workload.key"), pem).unwrap();
        certificate("workload.crt", b"the workload's certificate");
        certificate("chain.crt", b"the zone's intermediate");
        certificate("root.crt", b"the region's root");
        Self {
            dir,
            public_key: jwk,
        }
    }
}

/// The fake STS: `POST /v1/token`, RFC 8693. It checks what the real one
/// does of the actor (the assertion's signature by the workload's key, its
/// issuer, subject, audience and lifetime, a chain of three certificates)
/// and of the subject (the signature, by the realm's key or its own), and
/// answers `exchanged-{sub}-{n}`, recording each request.
pub struct Sts {
    server: FakeServer,
    key: EncodingKey,
    pub exchanges: Arc<Mutex<Vec<Received>>>,
    /// Makes the token endpoint refuse every exchange.
    pub refuse: Arc<AtomicBool>,
    /// Makes it answer `503`.
    pub unavailable: Arc<AtomicBool>,
}

fn components(jwk: &Value) -> DecodingKey {
    DecodingKey::from_ec_components(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap())
        .expect("a public key")
}

/// Whether `token`'s signature is `key`'s, whatever its claims say.
fn signed_by(token: &str, key: &DecodingKey) -> bool {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<Value>(token, key, &validation).is_ok()
}

impl Sts {
    pub async fn start(realm: Value, workload: Value) -> Self {
        let (_, key, jwk) = key_pair();
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let refuse = Arc::new(AtomicBool::new(false));
        let unavailable = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let (seen, refusing, down) = (
            Arc::clone(&exchanges),
            Arc::clone(&refuse),
            Arc::clone(&unavailable),
        );
        let server = FakeServer::start(move |r: Received| {
            let response = if (r.method.as_str(), r.path.as_str()) != ("POST", "/v1/token") {
                Response::json("{}").with_status(404)
            } else {
                seen.lock().unwrap().push(r.clone());
                if down.load(Ordering::SeqCst) {
                    Response::json(json!({ "error": "temporarily_unavailable" }).to_string())
                        .with_status(503)
                } else {
                    exchange(
                        &r,
                        &count,
                        refusing.load(Ordering::SeqCst),
                        &realm,
                        &workload,
                        &jwk,
                    )
                }
            };
            async move { response }
        })
        .await;
        Self {
            server,
            key,
            exchanges,
            refuse,
            unavailable,
        }
    }

    pub fn url(&self) -> String {
        self.server.url()
    }

    /// A token of this STS's zone `zone`, of `claims` completed with the
    /// issuer and a lifetime unless they name their own.
    pub fn token(&self, zone: &str, mut claims: Value) -> String {
        let defaults = json!({
            "iss": format!("origincloud:sts:{zone}"),
            "iat": now(),
            "nbf": now(),
            "exp": now() + 300,
        });
        for (k, v) in defaults.as_object().unwrap() {
            if claims.get(k).is_none() {
                claims[k] = v.clone();
            }
        }
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &self.key).expect("a token")
    }

    /// The same, signed with a key this STS doesn't hold.
    pub fn forged(&self, zone: &str, claims: Value) -> String {
        let (_, impostor, _) = key_pair();
        let token = self.token(zone, claims);
        let (signing_input, _) = token.rsplit_once('.').unwrap();
        let forged =
            jsonwebtoken::crypto::sign(signing_input.as_bytes(), &impostor, Algorithm::ES256)
                .unwrap();
        format!("{signing_input}.{forged}")
    }

    pub fn exchanges(&self) -> Vec<Received> {
        self.exchanges.lock().unwrap().clone()
    }
}

/// The form of an exchange.
pub fn form(r: &Received) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&r.body).into_owned().collect()
}

fn invalid_grant() -> Response {
    Response::json(json!({ "error": "invalid_grant" }).to_string()).with_status(400)
}

fn exchange(
    r: &Received,
    count: &AtomicUsize,
    refuse: bool,
    realm: &Value,
    workload: &Value,
    sts: &Value,
) -> Response {
    let form = form(r);
    let get = |k: &str| {
        form.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    if refuse
        || get("grant_type").as_deref() != Some("urn:ietf:params:oauth:grant-type:token-exchange")
        || get("actor_token_type").as_deref()
            != Some("urn:origincloud:params:oauth:token-type:workload-assertion")
    {
        return invalid_grant();
    }
    let (Some(subject), Some(actor)) = (get("subject_token"), get("actor_token")) else {
        return invalid_grant();
    };
    // The actor: the workload's assertion for this zone's STS.
    let header = jsonwebtoken::decode_header(&actor).expect("a JWS header");
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.x5c.as_ref().map(Vec::len), Some(3), "the chain");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[format!("origincloud:sts:{ZONE}")]);
    validation.set_issuer(&[WORKLOAD_ID]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let Ok(asserted) = jsonwebtoken::decode::<Value>(&actor, &components(workload), &validation)
    else {
        return invalid_grant();
    };
    let a = asserted.claims;
    if a["sub"] != WORKLOAD_ID
        || a["exp"].as_u64().unwrap() - a["iat"].as_u64().unwrap() > 60
        || a["jti"].as_str().is_none_or(str::is_empty)
    {
        return invalid_grant();
    }
    // The subject: signed by the realm, or by this STS.
    let sub = claims(&subject);
    let key = if sub["iss"]
        .as_str()
        .unwrap_or_default()
        .starts_with("origincloud:sts:")
    {
        sts
    } else {
        realm
    };
    if !signed_by(&subject, &components(key)) {
        return invalid_grant();
    }
    let n = count.fetch_add(1, Ordering::SeqCst) + 1;
    Response::json(
        json!({
            "access_token": format!("exchanged-{}-{n}", sub["sub"].as_str().unwrap_or_default()),
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
    pub sts: Sts,
    pub api: Api,
    pub workload: WorkloadFiles,
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
        Self::start_with(answer, &[]).await
    }

    /// The server with more flags.
    pub async fn start_with(
        answer: impl Fn(&Received) -> Response + Send + Sync + 'static,
        flags: &[&str],
    ) -> Self {
        let issuer = Issuer::start().await;
        let workload = WorkloadFiles::new();
        let sts = Sts::start(issuer.public_key(), workload.public_key.clone()).await;
        let api = Api::start(answer).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let metrics_url = format!("http://127.0.0.1:{}", metrics.local_addr().unwrap().port());
        let (issuer_id, api_url) = (issuer.id(), api.server.url());
        let sts_url = sts.url();
        let workload_dir = workload.dir.path().to_string_lossy().into_owned();
        let mut args = vec![
            "origincloud-mcp-server",
            "--resource",
            &url,
            "--issuer",
            &issuer_id,
            "--sts-url",
            &sts_url,
            "--sts-zone",
            ZONE,
            "--workload-dir",
            &workload_dir,
            "--workload-id",
            WORKLOAD_ID,
            "--api-endpoint",
            &api_url,
            "--drain-seconds",
            "1",
        ];
        args.extend_from_slice(flags);
        let config = Config::try_parse_from(args).unwrap();
        let server = Server::new(config).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(server.run(listener, metrics, async move {
            let _ = stopped.await;
        }));
        Self {
            issuer,
            sts,
            api,
            workload,
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
