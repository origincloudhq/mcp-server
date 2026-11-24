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
    /// How often the key set was fetched.
    pub key_fetches: Arc<AtomicUsize>,
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

/// The user id of a person known by `name` in a test: `name` itself when it
/// is one already.
pub fn person_id(name: &str) -> String {
    if uuid::Uuid::parse_str(name).is_ok() {
        return name.to_owned();
    }
    let sum: u64 = name.bytes().fold(7, |a, b| a * 31 + u64::from(b));
    format!(
        "{:08x}-0000-4000-8000-{:012x}",
        sum as u32,
        (sum >> 8) & 0xffff_ffff_ffff
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
        let key_fetches = Arc::new(AtomicUsize::new(0));
        let fetches = Arc::clone(&key_fetches);
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
                    fetches.fetch_add(1, Ordering::SeqCst);
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
            key_fetches,
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

    /// A token of exactly `claims` with a header of the caller's making.
    pub fn token_without_defaults_with(&self, header: &Header, claims: Value) -> String {
        jsonwebtoken::encode(header, &claims, &self.key).expect("a token")
    }

    /// The same, signed with a key the issuer doesn't publish.
    pub fn forged(&self, claims: Value) -> String {
        self.sign(&self.impostor, claims)
    }

    fn sign(&self, key: &EncodingKey, mut claims: Value) -> String {
        let defaults = json!({
            "iss": self.id(), "iat": now(), "exp": now() + 300, "azp": "origincloud-mcp",
            "typ": "Bearer", "email": "person@example.com", "email_verified": true,
            "name": "A Person", "given_name": "A", "family_name": "Person",
        });
        for (k, v) in defaults.as_object().unwrap() {
            if claims.get(k).is_none() {
                claims[k] = v.clone();
            }
        }
        // A person is named by a user id, a UUID: a short name is mapped to one.
        if let Some(sub) = claims["sub"].as_str() {
            claims["sub"] = person_id(sub).into();
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
///
/// An exchange naming a `service_account` is an impersonation: the subject
/// must be a person of the realm holding one of [`Sts::bindings`], and the
/// answer is `impersonated-{account id}-by-{sub}-{n}`; anything else is
/// `invalid_grant`, as the real STS answers every refusal.
pub struct Sts {
    server: FakeServer,
    key: EncodingKey,
    impostor: EncodingKey,
    pub exchanges: Arc<Mutex<Vec<Received>>>,
    /// Makes the token endpoint refuse every exchange.
    pub refuse: Arc<AtomicBool>,
    /// Makes it answer `503`.
    pub unavailable: Arc<AtomicBool>,
    /// The error a refusal answers with (`400`).
    pub error: Arc<Mutex<String>>,
    /// How long an exchange takes, in milliseconds.
    pub delay_ms: Arc<AtomicUsize>,
    /// Who may impersonate which service account: (the person's `sub`, the
    /// account's full name).
    pub bindings: Arc<Mutex<Vec<(String, String)>>>,
}

/// A fresh Ed25519 key as the STS signs with: its encoding key and the
/// public key's base64url.
fn ed_key_pair() -> (EncodingKey, String) {
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let der = key.to_pkcs8_der().expect("a DER");
    (
        EncodingKey::from_ed_der(der.as_bytes()),
        URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
    )
}

/// The key id the fake STS names in its tokens, as the real one does.
pub const STS_KID: &str = "sts-key-1";

fn components(jwk: &Value) -> DecodingKey {
    DecodingKey::from_ec_components(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap())
        .expect("a public key")
}

/// Whether `token`'s signature is `key`'s, whatever its claims say.
fn signed_by(token: &str, key: &DecodingKey, alg: Algorithm) -> bool {
    let mut validation = Validation::new(alg);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<Value>(token, key, &validation).is_ok()
}

impl Sts {
    pub async fn start(realm: Value, workload: Value) -> Self {
        let (key, public) = ed_key_pair();
        let (impostor, _) = ed_key_pair();
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let refuse = Arc::new(AtomicBool::new(false));
        let unavailable = Arc::new(AtomicBool::new(false));
        let error = Arc::new(Mutex::new("invalid_grant".to_owned()));
        let delay_ms = Arc::new(AtomicUsize::new(0));
        let bindings = Arc::new(Mutex::new(Vec::new()));
        let bound = Arc::clone(&bindings);
        let count = Arc::new(AtomicUsize::new(0));
        let (seen, refusing, down, code, delay) = (
            Arc::clone(&exchanges),
            Arc::clone(&refuse),
            Arc::clone(&unavailable),
            Arc::clone(&error),
            Arc::clone(&delay_ms),
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
                    let code = code.lock().unwrap().clone();
                    exchange(
                        &r,
                        &count,
                        refusing.load(Ordering::SeqCst),
                        Keys {
                            realm: &realm,
                            workload: &workload,
                            sts: &public,
                        },
                        &code,
                        &bound.lock().unwrap(),
                    )
                }
            };
            let wait = delay.load(Ordering::SeqCst) as u64;
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                response
            }
        })
        .await;
        Self {
            server,
            key,
            impostor,
            exchanges,
            refuse,
            unavailable,
            error,
            delay_ms,
            bindings,
        }
    }

    /// Lets `person` (a name or a user id) impersonate `account`.
    pub fn bind(&self, person: &str, account: &str) {
        self.bindings
            .lock()
            .unwrap()
            .push((person_id(person), account.to_owned()));
    }

    pub fn url(&self) -> String {
        self.server.url()
    }

    fn complete(zone: &str, mut claims: Value) -> Value {
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
        claims
    }

    /// A token of this STS's zone `zone`, of `claims` completed with the
    /// issuer and a lifetime unless they name their own, signed EdDSA with
    /// a named key as the real STS does.
    pub fn token(&self, zone: &str, claims: Value) -> String {
        self.sign(&self.key, zone, claims)
    }

    /// The same, signed with a key this STS doesn't hold.
    pub fn forged(&self, zone: &str, claims: Value) -> String {
        self.sign(&self.impostor, zone, claims)
    }

    fn sign(&self, key: &EncodingKey, zone: &str, claims: Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(STS_KID.to_owned());
        jsonwebtoken::encode(&header, &Self::complete(zone, claims), key).expect("a token")
    }

    /// A token with a header of the caller's making, signed with whichever
    /// key suits `header.alg`.
    pub fn token_with(&self, header: &Header, zone: &str, claims: Value) -> String {
        let key = match header.alg {
            Algorithm::EdDSA => self.key.clone(),
            _ => key_pair().1,
        };
        jsonwebtoken::encode(header, &Self::complete(zone, claims), &key).expect("a token")
    }

    pub fn exchanges(&self) -> Vec<Received> {
        self.exchanges.lock().unwrap().clone()
    }
}

/// The form of an exchange.
pub fn form(r: &Received) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&r.body).into_owned().collect()
}

/// The public keys the fake STS checks tokens with: the realm's, the
/// workload's, and its own.
struct Keys<'a> {
    realm: &'a Value,
    workload: &'a Value,
    sts: &'a str,
}

fn exchange(
    r: &Received,
    count: &AtomicUsize,
    refuse: bool,
    keys: Keys<'_>,
    error: &str,
    bindings: &[(String, String)],
) -> Response {
    let invalid_grant = || Response::json(json!({ "error": error }).to_string()).with_status(400);
    // The actor's assertion not accepted: the acting client failed to
    // authenticate (RFC 6749, section 5.2), as the real STS answers it.
    let invalid_client =
        || Response::json(json!({ "error": "invalid_client" }).to_string()).with_status(401);
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
    let Ok(asserted) =
        jsonwebtoken::decode::<Value>(&actor, &components(keys.workload), &validation)
    else {
        return invalid_client();
    };
    let a = asserted.claims;
    if a["sub"] != WORKLOAD_ID
        || a["exp"].as_u64().unwrap() - a["iat"].as_u64().unwrap() > 60
        || a["jti"].as_str().is_none_or(str::is_empty)
    {
        return invalid_client();
    }
    // The subject: signed by the realm, or by this STS.
    let sub = claims(&subject);
    let of_sts = sub["iss"]
        .as_str()
        .unwrap_or_default()
        .starts_with("origincloud:sts:");
    let signed = if of_sts {
        signed_by(
            &subject,
            &DecodingKey::from_ed_components(keys.sts).unwrap(),
            Algorithm::EdDSA,
        )
    } else {
        signed_by(&subject, &components(keys.realm), Algorithm::ES256)
    };
    if !signed {
        return invalid_grant();
    }
    let subject_id = sub["sub"].as_str().unwrap_or_default().to_owned();
    if let Some(account) = get("service_account") {
        // Only a person impersonates, and only an account bound to them.
        if of_sts
            || !bindings
                .iter()
                .any(|(person, bound)| *person == subject_id && *bound == account)
        {
            return invalid_grant();
        }
        let n = count.fetch_add(1, Ordering::SeqCst) + 1;
        let id = account.rsplit('/').next().unwrap_or_default();
        return Response::json(
            json!({
                "access_token": format!("impersonated-{id}-by-{subject_id}-{n}"),
                "expires_in": 300,
                "token_type": "Bearer",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            })
            .to_string(),
        );
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
