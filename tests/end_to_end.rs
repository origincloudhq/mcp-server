//! The server between a fake authorization server and a fake API, through
//! an MCP client: who gets in, which token reaches the API, and what a
//! connection's options expose.

mod common;

use common::{claims, everything, form, now, person_id, Harness, API_AUDIENCE, WORKLOAD_ID, ZONE};
use fake_server::{Received, Response};
use origincloud_mcp::{ClientSource, Options};
use rmcp::ServerHandler;
use serde_json::{json, Value};

const VOLUME: &str = "projects/p/zones/z/volumes/v";

/// The fake PVS: a volume `v` to read; deleting it is done at once.
fn pvs(r: &Received) -> Response {
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/v1beta1/projects/p/zones/z/volumes/v") => Response::json(
            json!({ "name": VOLUME, "sizeGib": 8, "state": "AVAILABLE" }).to_string(),
        ),
        ("DELETE", "/v1beta1/projects/p/zones/z/volumes/v") => Response::json(
            json!({
                "name": "projects/p/zones/z/operations/op-1",
                "done": true,
                "response": { "@type": "type.googleapis.com/google.protobuf.Empty" }
            })
            .to_string(),
        ),
        _ => Response::json("{}").with_status(404),
    }
}

fn header<'a>(response: &'a reqwest::Response, name: &str) -> &'a str {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_request_without_a_token_is_told_where_to_get_one() {
    let h = Harness::start(pvs).await;

    let response = h.post("", None).await;
    assert_eq!(response.status(), 401);
    let metadata_url = format!("{}/.well-known/oauth-protected-resource", h.url);
    assert_eq!(
        header(&response, "www-authenticate"),
        format!("Bearer resource_metadata=\"{metadata_url}\", scope=\"mcp\"")
    );

    let metadata: Value = reqwest::get(&metadata_url)
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["resource"], h.url);
    assert_eq!(metadata["authorization_servers"], json!([h.issuer.id()]));
    assert_eq!(metadata["scopes_supported"], json!(["mcp"]));
    assert_eq!(metadata["bearer_methods_supported"], json!(["header"]));
    assert!(h.api.received().is_empty());
}

#[tokio::test]
async fn a_token_issued_for_another_audience_is_refused() {
    let h = Harness::start(pvs).await;
    // A token the API itself would take.
    let token = h
        .issuer
        .token(json!({ "sub": "alice", "aud": API_AUDIENCE }));

    let response = h.post("", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), 401);
    let challenge = header(&response, "www-authenticate");
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
    assert!(
        challenge.contains(&format!("the token wasn't issued for {}", h.url)),
        "{challenge}"
    );
    assert!(h.sts.exchanges().is_empty(), "nothing is exchanged");
    assert!(h.api.received().is_empty(), "nothing reaches the API");
}

/// A token for the server's audience is served whatever client it was
/// issued to, such as a client of a dynamic registration or a client's own
/// credentials.
#[tokio::test]
async fn a_token_of_any_client_is_served() {
    let h = Harness::start(pvs).await;
    let aud = json!([h.url.clone(), "origincloud-mcp-server"]);
    let mut tokens = vec![];
    for azp in ["origin-cli", "https://client.example/metadata.json", ""] {
        tokens.push((
            azp,
            h.issuer
                .token(json!({ "sub": "alice", "aud": aud, "azp": azp })),
        ));
    }
    // The fake issuer's defaults name a client; this token names none.
    let mut claims = claims(&h.token_for("alice"));
    claims.as_object_mut().unwrap().remove("azp");
    tokens.push(("none", h.issuer.token_without_defaults(claims)));
    for (client, token) in &tokens {
        let response = h.post("", Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), 200, "the token of client {client:?}");
    }
    let agent = h.connect(&tokens[0].1, "").await;
    let read = agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    assert_ne!(read.is_error, Some(true), "{read:?}");
}

/// With `--allowed-clients`, a token of another client, or of none, such as
/// a zone STS's, is refused before any exchange.
#[tokio::test]
async fn a_server_restricted_to_clients_refuses_the_others() {
    let h = Harness::start_with(pvs, &["--allowed-clients", "origincloud-mcp"]).await;
    let aud = json!([h.url.clone(), "origincloud-mcp-server"]);
    let mut clientless = claims(&h.token_for("alice"));
    clientless.as_object_mut().unwrap().remove("azp");
    let tokens = [
        (
            "another client's",
            h.issuer
                .token(json!({ "sub": "alice", "aud": aud, "azp": "origin-cli" })),
        ),
        (
            "an empty client's",
            h.issuer
                .token(json!({ "sub": "alice", "aud": aud, "azp": "" })),
        ),
        ("a clientless", h.issuer.token_without_defaults(clientless)),
        (
            "a zone STS's",
            h.sts.token(ZONE, json!({ "sub": "sa", "aud": aud })),
        ),
    ];
    for (what, token) in tokens {
        let response = h.post("", Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), 403, "{what} token");
        let challenge = header(&response, "www-authenticate");
        assert!(challenge.contains("insufficient_scope"), "{what} token");
        assert!(!challenge.contains("scope=\"mcp\""), "{challenge}");
    }
    assert!(h.sts.exchanges().is_empty());
    assert!(h.api.received().is_empty());
    let metrics = reqwest::get(format!("{}/metrics", h.metrics_url))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("origincloud_mcp_auth_refusals_total{reason=\"client\"}"),
        "{metrics}"
    );

    // The login client's token still works.
    let agent = h.connect(&h.token_for("alice"), "").await;
    let read = agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    assert_ne!(read.is_error, Some(true), "{read:?}");
    assert_eq!(h.api.received().len(), 1);
}

/// A service account's token of a zone's STS for the server's audience is
/// served: the STS checks its signature when the server exchanges it, and the
/// token the API receives is the exchanged one.
#[tokio::test]
async fn a_service_account_s_sts_token_is_served() {
    let h = Harness::start(pvs).await;
    let account = "//iam.example/organizations/o/serviceAccounts/sa-1";
    // From any zone: the STS of another zone than the server's.
    let token = h.sts.token(
        "other-zone-9",
        json!({ "sub": account, "aud": [h.url.clone()] }),
    );
    let agent = h.connect(&token, "").await;

    let read = agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    assert_ne!(read.is_error, Some(true), "{read:?}");
    let received = h.api.received();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].header("authorization"),
        Some(format!("Bearer exchanged-{account}-1").as_str())
    );
    assert!(!everything(&received[0]).contains(&token));
    // Checked by the exchange that admitted the request, and used by the call.
    assert_eq!(h.sts.exchanges().len(), 1);
}

/// What the STS is sent: the caller's token as subject, the server's
/// workload assertion as actor, and nothing else.
#[tokio::test]
async fn the_exchange_names_the_caller_and_proves_the_server() {
    let h = Harness::start(pvs).await;
    let token = h.token_for("alice");
    let agent = h.connect(&token, "").await;
    agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;

    let exchanges = h.sts.exchanges();
    assert_eq!(exchanges.len(), 1);
    let form = form(&exchanges[0]);
    let get = |k: &str| {
        form.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(
        get("grant_type"),
        Some("urn:ietf:params:oauth:grant-type:token-exchange")
    );
    assert_eq!(get("subject_token"), Some(token.as_str()));
    assert_eq!(
        get("subject_token_type"),
        Some("urn:ietf:params:oauth:token-type:access_token")
    );
    assert_eq!(
        get("requested_token_type"),
        Some("urn:ietf:params:oauth:token-type:access_token")
    );
    assert_eq!(
        get("actor_token_type"),
        Some("urn:origincloud:params:oauth:token-type:workload-assertion")
    );
    let actor = claims(get("actor_token").expect("an actor token"));
    assert_eq!(actor["iss"], WORKLOAD_ID);
    assert_eq!(actor["sub"], WORKLOAD_ID);
    assert_eq!(actor["aud"], format!("origincloud:sts:{ZONE}"));
    // No client credentials of any kind, and no audience: the STS issues
    // for the API.
    assert!(exchanges[0].header("authorization").is_none());
    assert!(get("audience").is_none());
}

/// A token of the STS the server can refuse itself is refused without
/// asking the STS; one with a forged signature is the STS's to find.
#[tokio::test]
async fn a_bad_sts_token_is_refused() {
    let h = Harness::start(pvs).await;
    let aud = json!([h.url.clone()]);
    let local = [
        (
            "for another audience",
            h.sts
                .token(ZONE, json!({ "sub": "sa", "aud": API_AUDIENCE })),
        ),
        (
            "expired",
            h.sts
                .token(ZONE, json!({ "sub": "sa", "aud": aud, "exp": now() - 120 })),
        ),
        (
            "not yet valid",
            h.sts
                .token(ZONE, json!({ "sub": "sa", "aud": aud, "nbf": now() + 600 })),
        ),
        (
            "of an unknown issuer",
            h.sts.token(
                ZONE,
                json!({ "sub": "sa", "aud": aud, "iss": "origincloud:other" }),
            ),
        ),
        (
            "of a malformed zone",
            h.sts.token(
                ZONE,
                json!({ "sub": "sa", "aud": aud, "iss": "origincloud:sts:../x" }),
            ),
        ),
        ("subjectless", h.sts.token(ZONE, json!({ "aud": aud }))),
    ];
    for (what, token) in local {
        let response = h.post("", Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), 401, "a token {what}");
        assert!(
            header(&response, "www-authenticate").contains("invalid_token"),
            "a token {what}"
        );
    }
    assert!(h.sts.exchanges().is_empty(), "nothing was exchanged");

    // The same forged token isn't asked about again at once.
    let forged = h.sts.forged(ZONE, json!({ "sub": "sa", "aud": aud }));
    for _ in 0..3 {
        let response = h.post("", Some(&format!("Bearer {forged}"))).await;
        assert_eq!(response.status(), 401, "a forged token");
    }
    assert_eq!(h.sts.exchanges().len(), 1);
    assert!(h.api.received().is_empty());
}

/// An STS that can't answer decides nothing about a token: the request is
/// answered `503` to retry, while a realm's token is still served.
#[tokio::test]
async fn an_sts_that_cannot_answer_is_unavailable_not_a_refusal() {
    let h = Harness::start(pvs).await;
    h.sts
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let token = h
        .sts
        .token(ZONE, json!({ "sub": "sa", "aud": [h.url.clone()] }));
    let response = h.post("", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), 503);
    assert_eq!(header(&response, "retry-after"), "5");

    let people = h
        .post("", Some(&format!("Bearer {}", h.token_for("alice"))))
        .await;
    assert_eq!(people.status(), 200);

    // Asked again once it answers: the outage wasn't remembered.
    h.sts
        .unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let response = h.post("", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), 200);
}

/// Without its certificate the server can't exchange: a tool call fails,
/// and an STS token is answered `503` rather than as refused.
#[tokio::test]
async fn a_server_without_its_certificate_cannot_exchange() {
    let h = Harness::start(pvs).await;
    std::fs::remove_file(h.workload.dir.path().join("workload.key")).unwrap();

    let agent = h.connect(&h.token_for("alice"), "").await;
    let read = agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    assert_eq!(read.is_error, Some(true));
    assert!(h.api.received().is_empty());

    let token = h
        .sts
        .token(ZONE, json!({ "sub": "sa", "aud": [h.url.clone()] }));
    let response = h.post("", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), 503);
    assert!(h.sts.exchanges().is_empty());
}

#[tokio::test]
async fn only_the_issuer_s_unexpired_tokens_are_accepted() {
    let h = Harness::start(pvs).await;
    let aud = json!([h.url.clone()]);
    let refused = [
        (
            "forged",
            h.issuer.forged(json!({ "sub": "alice", "aud": aud })),
        ),
        (
            "expired",
            h.issuer
                .token(json!({ "sub": "alice", "aud": aud, "exp": now() - 120 })),
        ),
        (
            "another issuer's",
            h.issuer
                .token(json!({ "sub": "alice", "aud": aud, "iss": "https://elsewhere.example" })),
        ),
        ("subjectless", h.issuer.token(json!({ "aud": aud }))),
        ("not a JWT", "opaque".to_owned()),
    ];
    for (what, token) in refused {
        let response = h.post("", Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), 401, "a {what} token");
        assert!(
            header(&response, "www-authenticate").contains("invalid_token"),
            "a {what} token"
        );
    }
    let accepted = h
        .post("", Some(&format!("Bearer {}", h.token_for("alice"))))
        .await;
    assert_eq!(accepted.status(), 200);
    assert!(h.api.received().is_empty());
}

#[tokio::test]
async fn a_tool_call_reaches_the_api_with_an_exchanged_token_never_the_caller_s() {
    let h = Harness::start(pvs).await;
    let token = h.token_for("alice");
    let agent = h.connect(&token, "").await;

    for _ in 0..2 {
        let read = agent
            .call("pvs_get_volume", json!({ "name": VOLUME }))
            .await;
        assert_ne!(read.is_error, Some(true), "{read:?}");
        assert_eq!(read.structured_content.as_ref().unwrap()["sizeGib"], 8);
    }

    let received = h.api.received();
    assert_eq!(received.len(), 2);
    for r in &received {
        assert_eq!(
            r.header("authorization"),
            Some(format!("Bearer exchanged-{}-1", person_id("alice")).as_str())
        );
        assert!(
            !everything(r).contains(&token),
            "the caller's token reached the API"
        );
    }

    // One exchange, its token used for both calls until it is due.
    assert_eq!(h.sts.exchanges().len(), 1);
    assert_eq!(claims(&token)["sub"], person_id("alice"));
}

#[tokio::test]
async fn each_caller_calls_with_a_token_exchanged_for_their_own() {
    let h = Harness::start(pvs).await;
    let alice = h.connect(&h.token_for("alice"), "").await;
    let bob = h.connect(&h.token_for("bob"), "").await;

    alice
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    bob.call("pvs_get_volume", json!({ "name": VOLUME })).await;

    let tokens: Vec<_> = h
        .api
        .received()
        .iter()
        .map(|r| r.header("authorization").unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        tokens,
        [
            format!("Bearer exchanged-{}-1", person_id("alice")),
            format!("Bearer exchanged-{}-2", person_id("bob"))
        ]
    );
}

#[tokio::test]
async fn a_refused_exchange_is_the_tool_s_error_and_reaches_no_api() {
    let h = Harness::start(pvs).await;
    h.sts
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let agent = h.connect(&h.token_for("alice"), "").await;

    let read = agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    assert_eq!(read.is_error, Some(true));
    let text = serde_json::to_string(&read).unwrap();
    assert!(text.contains("refused to exchange"), "{text}");
    assert!(h.api.received().is_empty());
}

#[tokio::test]
async fn a_read_only_connection_lists_no_mutating_tool() {
    let h = Harness::start(pvs).await;
    let token = h.token_for("alice");
    let everything = h.connect(&token, "").await.tools().await;
    let read_only = h.connect(&token, "?read_only=true").await;
    let tools = read_only.tools().await;

    assert!(tools.len() < everything.len());
    assert!(everything.iter().any(|t| t.name == "pvs_delete_volume"));
    for tool in &tools {
        let hints = tool.annotations.as_ref().expect("annotations");
        assert_eq!(
            hints.read_only_hint,
            Some(true),
            "{} changes something",
            tool.name
        );
    }
    assert!(tools.iter().any(|t| t.name == "pvs_get_volume"));

    let deleted = read_only
        .call("pvs_delete_volume", json!({ "name": VOLUME }))
        .await;
    assert_eq!(deleted.is_error, Some(true));
    assert!(h.api.received().is_empty(), "the delete reached the API");
}

#[tokio::test]
async fn toolsets_select_the_tools_and_a_misspelt_option_is_refused() {
    let h = Harness::start(pvs).await;
    let token = h.token_for("alice");
    let tools = h.connect(&token, "?toolsets=pvs").await.tools().await;
    assert!(tools.iter().any(|t| t.name == "pvs_create_volume"));
    for tool in &tools {
        assert!(
            tool.name.starts_with("pvs_") || tool.name == "current_context",
            "{} isn't pvs'",
            tool.name
        );
    }

    let response = h
        .post("?toolsets=pvss", Some(&format!("Bearer {token}")))
        .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("\"pvss\""),
        "{body}"
    );
}

/// A client of the 2025-06-18 protocol, as many clients still speak it:
/// the server keeps no session, and answers each request on its own.
#[tokio::test]
async fn a_client_of_an_earlier_protocol_calls_tools_without_a_session() {
    let h = Harness::start(pvs).await;
    let bearer = format!("Bearer {}", h.token_for("alice"));
    let initialized = h.post("", Some(&bearer)).await;
    assert_eq!(initialized.status(), 200);
    assert!(initialized.headers().get("mcp-session-id").is_none());

    let send = |body: Value| {
        reqwest::Client::new()
            .post(format!("{}/", h.url))
            .header("authorization", &bearer)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2025-06-18")
            .body(body.to_string())
            .send()
    };
    let notified = send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await
        .unwrap();
    assert_eq!(notified.status(), 202);
    let called = send(json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "pvs_get_volume", "arguments": { "name": VOLUME } }
    }))
    .await
    .unwrap();
    assert_eq!(called.status(), 200);
    let body: Value = called.json().await.unwrap();
    assert_eq!(body["result"]["structuredContent"]["sizeGib"], 8, "{body}");
    assert_eq!(
        h.api.received()[0].header("authorization"),
        Some(format!("Bearer exchanged-{}-1", person_id("alice")).as_str())
    );
}

/// A source the library's own server is built with, to compare with.
struct Nowhere;

impl ClientSource for Nowhere {
    fn client(&self, _: &str) -> Result<origincloud_core::Client, origincloud_core::Error> {
        Err(origincloud_core::Error::NoCredentials)
    }
}

#[tokio::test]
async fn the_server_gives_the_library_s_instructions() {
    let h = Harness::start(pvs).await;
    let agent = h.connect(&h.token_for("alice"), "").await;
    let hosted = agent
        .0
        .peer_info()
        .expect("the server's info")
        .instructions
        .clone();
    let library = origincloud_mcp::Server::new(Nowhere, Options::default())
        .unwrap()
        .get_info()
        .instructions;
    assert!(hosted.is_some());
    assert_eq!(hosted, library);
}

#[tokio::test]
async fn the_server_reports_metrics_and_readiness() {
    let h = Harness::start(pvs).await;
    let agent = h.connect(&h.token_for("alice"), "").await;
    agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    let _ = h.post("", None).await;

    let ready = reqwest::get(format!("{}/readyz", h.metrics_url))
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);
    let metrics = reqwest::get(format!("{}/metrics", h.metrics_url))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for series in [
        "origincloud_mcp_tool_calls_total{outcome=\"ok\",tool=\"pvs_get_volume\"}",
        "origincloud_mcp_token_exchanges_total{outcome=\"exchanged\"}",
        "origincloud_mcp_auth_refusals_total{reason=\"missing\"}",
        "origincloud_http_requests_total{method=\"POST\",route=\"/\",status_class=\"2xx\"}",
        "origincloud_build_info",
    ] {
        assert!(metrics.contains(series), "{series} is missing:\n{metrics}");
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// Tokens a realm doesn't sign, or signs for someone that isn't a person,
/// or that aren't valid now, are refused, and a stream of tokens naming
/// made-up keys doesn't become a stream of fetches of the realm's keys.
#[tokio::test]
async fn a_realm_token_that_is_not_a_valid_person_s_is_refused() {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    let h = Harness::start(pvs).await;
    let aud = json!([h.url.clone()]);
    let public = h.issuer.public_key();
    let signed = |header: &Header, claims: Value| {
        // The issuer's public key as an HMAC secret.
        let key = EncodingKey::from_secret(public["x"].as_str().unwrap().as_bytes());
        jsonwebtoken::encode(header, &claims, &key).unwrap()
    };
    let base = json!({
        "iss": h.issuer.id(), "aud": aud, "sub": person_id("alice"),
        "exp": now() + 300, "typ": "Bearer", "email": "a@example.com",
        "email_verified": true, "name": "A", "given_name": "A", "family_name": "B",
    });
    let mut unknown_kid = Header::new(Algorithm::ES256);
    unknown_kid.kid = Some("not-published".to_owned());
    let alg_none = format!(
        "{}.{}.",
        base64_url(br#"{"alg":"none","typ":"JWT"}"#),
        base64_url(base.to_string().as_bytes())
    );
    let with = |claims: Value| h.issuer.token_without_defaults(claims);
    let mut tokens = vec![
        (
            "HS256",
            signed(&Header::new(Algorithm::HS256), base.clone()),
        ),
        ("alg none", alg_none),
        (
            "an unknown key",
            h.issuer
                .token_without_defaults_with(&unknown_kid, base.clone()),
        ),
        (
            "not yet valid",
            with(merge(&base, json!({ "nbf": now() + 600 }))),
        ),
        (
            "a huge exp",
            with(merge(
                &base,
                json!({ "exp": 10_000_000_000_000_000_000u64 }),
            )),
        ),
        (
            "a distant exp",
            with(merge(&base, json!({ "exp": now() + 30 * 86_400 }))),
        ),
        (
            "typed Refresh",
            with(merge(&base, json!({ "typ": "Refresh" }))),
        ),
        (
            "not a user's id",
            with(merge(&base, json!({ "sub": "alice" }))),
        ),
        (
            "without an email",
            with(merge(&base, json!({ "email": null }))),
        ),
        (
            "without email_verified",
            with(merge(&base, json!({ "email_verified": null }))),
        ),
        ("without a name", with(merge(&base, json!({ "name": "" })))),
    ];
    tokens.push((
        "oversize",
        with(merge(&base, json!({ "pad": "x".repeat(20_000) }))),
    ));
    // A well-formed one is accepted, which has the realm's keys fetched.
    let accepted = with(base.clone());
    assert_eq!(h.post("", Some(&bearer(&accepted))).await.status(), 200);
    let before = h
        .issuer
        .key_fetches
        .load(std::sync::atomic::Ordering::SeqCst);
    for (what, token) in &tokens {
        for _ in 0..2 {
            let response = h.post("", Some(&bearer(token))).await;
            assert_eq!(response.status(), 401, "a token {what}");
        }
    }
    assert_eq!(
        h.issuer
            .key_fetches
            .load(std::sync::atomic::Ordering::SeqCst),
        before,
        "the realm's keys were fetched for tokens that name unknown keys"
    );
    assert!(h.sts.exchanges().is_empty());
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn merge(base: &Value, over: Value) -> Value {
    let mut merged = base.clone();
    for (k, v) in over.as_object().unwrap() {
        if v.is_null() {
            merged.as_object_mut().unwrap().remove(k);
        } else {
            merged[k] = v.clone();
        }
    }
    merged
}

/// An STS token the server can tell isn't one, without asking the STS, is
/// refused, and doesn't panic the server for an expiry no clock reaches.
#[tokio::test]
async fn an_sts_token_that_is_malformed_is_refused_without_asking_the_sts() {
    use jsonwebtoken::{Algorithm, Header};
    let h = Harness::start(pvs).await;
    let aud = json!([h.url.clone()]);
    let mut no_kid = Header::new(Algorithm::EdDSA);
    no_kid.kid = None;
    let mut es256 = Header::new(Algorithm::ES256);
    es256.kid = Some("k".to_owned());
    let tokens = [
        (
            "a huge exp",
            h.sts.token(
                ZONE,
                json!({ "sub": "sa", "aud": aud, "exp": 10_000_000_000_000_000_000u64 }),
            ),
        ),
        (
            "a distant exp",
            h.sts.token(
                ZONE,
                json!({ "sub": "sa", "aud": aud, "exp": now() + 30 * 86_400 }),
            ),
        ),
        (
            "without a key id",
            h.sts
                .token_with(&no_kid, ZONE, json!({ "sub": "sa", "aud": aud })),
        ),
        (
            "signed ES256",
            h.sts
                .token_with(&es256, ZONE, json!({ "sub": "sa", "aud": aud })),
        ),
        (
            "oversize",
            h.sts.token(
                ZONE,
                json!({ "sub": "sa", "aud": aud, "pad": "x".repeat(20_000) }),
            ),
        ),
    ];
    for (what, token) in tokens {
        let response = h.post("", Some(&bearer(&token))).await;
        assert_eq!(response.status(), 401, "a token {what}");
    }
    assert!(h.sts.exchanges().is_empty());
    // The server still answers.
    assert_eq!(
        h.post("", Some(&bearer(&h.token_for("alice"))))
            .await
            .status(),
        200
    );
}

/// Only `invalid_grant` is a refusal of the token. What else the STS
/// answers is a fault of this server's request: `503`, and asked again.
#[tokio::test]
async fn an_error_that_is_not_about_the_token_is_not_a_refusal() {
    let h = Harness::start(pvs).await;
    let token = h
        .sts
        .token(ZONE, json!({ "sub": "sa", "aud": [h.url.clone()] }));
    for code in [
        "invalid_request",
        "invalid_target",
        "unsupported_grant_type",
        "invalid_client",
    ] {
        *h.sts.error.lock().unwrap() = code.to_owned();
        h.sts
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let before = h.sts.exchanges().len();
        for _ in 0..2 {
            let response = h.post("", Some(&bearer(&token))).await;
            assert_eq!(response.status(), 503, "{code}");
        }
        assert_eq!(h.sts.exchanges().len(), before + 2, "{code} was remembered");
    }
    // `invalid_grant` is the token's refusal, and is remembered.
    *h.sts.error.lock().unwrap() = "invalid_grant".to_owned();
    let before = h.sts.exchanges().len();
    for _ in 0..2 {
        assert_eq!(h.post("", Some(&bearer(&token))).await.status(), 401);
    }
    assert_eq!(h.sts.exchanges().len(), before + 1);
}

/// A token that isn't valid yet may be taken a moment later: its refusal
/// isn't remembered.
#[tokio::test]
async fn a_refusal_of_a_token_not_yet_valid_is_not_remembered() {
    let h = Harness::start(pvs).await;
    h.sts
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let token = h.sts.token(
        ZONE,
        json!({ "sub": "sa", "aud": [h.url.clone()], "nbf": now() + 20 }),
    );
    for _ in 0..2 {
        assert_eq!(h.post("", Some(&bearer(&token))).await.status(), 401);
    }
    assert_eq!(h.sts.exchanges().len(), 2);
}

/// Callers presenting one token at once share one exchange.
#[tokio::test]
async fn parallel_requests_of_one_token_make_one_exchange() {
    let h = Harness::start(pvs).await;
    h.sts
        .delay_ms
        .store(300, std::sync::atomic::Ordering::SeqCst);
    let token = h
        .sts
        .token(ZONE, json!({ "sub": "sa", "aud": [h.url.clone()] }));
    let mut posts = Vec::new();
    for _ in 0..10 {
        let (url, header) = (h.url.clone(), bearer(&token));
        posts.push(tokio::spawn(async move { post(&url, &header).await }));
    }
    for task in posts {
        assert_eq!(task.await.unwrap(), 200);
    }
    assert_eq!(h.sts.exchanges().len(), 1);
}

/// Tokens nobody has checked are exchanged at a limited rate: past it the
/// request is answered `503`, while a token exchanged before, and a realm's
/// token, are unaffected.
#[tokio::test]
async fn exchanges_of_unchecked_tokens_are_limited() {
    let h = Harness::start(pvs).await;
    let known = h
        .sts
        .token(ZONE, json!({ "sub": "known", "aud": [h.url.clone()] }));
    assert_eq!(h.post("", Some(&bearer(&known))).await.status(), 200);

    h.sts
        .delay_ms
        .store(400, std::sync::atomic::Ordering::SeqCst);
    let mut posts = Vec::new();
    for n in 0..60 {
        let token = h.sts.token(
            ZONE,
            json!({ "sub": format!("sa-{n}"), "aud": [h.url.clone()] }),
        );
        let (url, header) = (h.url.clone(), bearer(&token));
        posts.push(tokio::spawn(async move { post(&url, &header).await }));
    }
    // While they wait: the known token and a person's are served.
    assert_eq!(h.post("", Some(&bearer(&known))).await.status(), 200);
    assert_eq!(
        h.post("", Some(&bearer(&h.token_for("alice"))))
            .await
            .status(),
        200
    );
    let mut statuses = Vec::new();
    for task in posts {
        statuses.push(task.await.unwrap());
    }
    let busy = statuses.iter().filter(|s| **s == 503).count();
    assert!(busy > 0, "nothing was limited: {statuses:?}");
    let metrics = reqwest::get(format!("{}/metrics", h.metrics_url))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("origincloud_mcp_token_exchanges_total{outcome=\"busy\"}"),
        "{metrics}"
    );
    assert!(statuses.contains(&200));
    assert!(
        h.sts.exchanges().len() <= 1 + 40,
        "{} exchanges",
        h.sts.exchanges().len()
    );
}

async fn post(url: &str, authorization: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("{url}/"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("authorization", authorization)
        .body(
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" } }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}
