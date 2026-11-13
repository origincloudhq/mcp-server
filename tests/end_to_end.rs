//! The server between a fake authorization server and a fake API, through
//! an MCP client: who gets in, which token reaches the API, and what a
//! connection's options expose.

mod common;

use common::{claims, everything, now, Harness, API_AUDIENCE};
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
    assert!(h.issuer.exchanges().is_empty(), "nothing is exchanged");
    assert!(h.api.received().is_empty(), "nothing reaches the API");
}

/// A service account's token: Keycloak's client credentials grant, issued to
/// the account's own client, with the claims that grant sets.
#[tokio::test]
async fn a_service_account_s_token_is_refused_before_any_exchange() {
    let h = Harness::start(pvs).await;
    let account = "sa-0b5e2c1a-7d4f-4e0a-9c3b-2f6d8e1a4b7c";
    let token = h.issuer.token(json!({
        "sub": "5f1c9e2a-3b7d-4c8e-a1f0-6d2b9e4c7a13",
        "aud": [h.url.clone(), "origincloud-mcp-server"],
        "azp": account,
        "client_id": account,
        "clientHost": "203.0.113.7",
        "clientAddress": "203.0.113.7",
        "scope": "mcp",
    }));

    let response = h.post("", Some(&format!("Bearer {token}"))).await;
    assert_eq!(response.status(), 403);
    let challenge = header(&response, "www-authenticate").to_owned();
    assert!(challenge.starts_with("Bearer "), "{challenge}");
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    assert!(
        challenge.contains(&format!(
            "resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
            h.url
        )),
        "{challenge}"
    );
    assert!(
        !challenge.contains("scope=\"mcp\""),
        "a scope no service account can use: {challenge}"
    );
    assert!(challenge.contains("origin mcp serve"), "{challenge}");
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "insufficient_scope");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("origin mcp serve"),
        "{body}"
    );

    assert!(h.issuer.exchanges().is_empty(), "the token was exchanged");
    assert!(h.api.received().is_empty(), "something reached the API");
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
}

/// A token for the server's audience issued to another client than the one
/// people sign in to it with, or naming none, is refused the same way.
#[tokio::test]
async fn a_token_of_another_client_is_refused() {
    let h = Harness::start(pvs).await;
    let aud = json!([h.url.clone(), "origincloud-mcp-server"]);
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
        ("a clientless", {
            // The fake issuer's defaults name the login client; this names none.
            let mut claims = common::claims(&h.token_for("alice"));
            claims.as_object_mut().unwrap().remove("azp");
            h.issuer.token_without_defaults(claims)
        }),
    ];
    for (what, token) in tokens {
        let response = h.post("", Some(&format!("Bearer {token}"))).await;
        assert_eq!(response.status(), 403, "{what} token");
        assert!(
            header(&response, "www-authenticate").contains("insufficient_scope"),
            "{what} token"
        );
    }
    assert!(h.issuer.exchanges().is_empty());
    assert!(h.api.received().is_empty());

    // The login client's token still works.
    let agent = h.connect(&h.token_for("alice"), "").await;
    let read = agent
        .call("pvs_get_volume", json!({ "name": VOLUME }))
        .await;
    assert_ne!(read.is_error, Some(true), "{read:?}");
    assert_eq!(h.api.received().len(), 1);
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
        assert_eq!(r.header("authorization"), Some("Bearer exchanged-alice-1"));
        assert!(
            !everything(r).contains(&token),
            "the caller's token reached the API"
        );
    }

    // One exchange, its token used for both calls until it is due.
    let exchanges = h.issuer.exchanges();
    assert_eq!(exchanges.len(), 1);
    let form: Vec<(String, String)> = url::form_urlencoded::parse(&exchanges[0].body)
        .into_owned()
        .collect();
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
    assert_eq!(get("audience"), Some(API_AUDIENCE));
    // As the server's own client, which the fake checks.
    assert!(exchanges[0]
        .header("authorization")
        .unwrap()
        .starts_with("Basic "));
    assert_eq!(claims(&token)["sub"], "alice");
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
        ["Bearer exchanged-alice-1", "Bearer exchanged-bob-2"]
    );
}

#[tokio::test]
async fn a_refused_exchange_is_the_tool_s_error_and_reaches_no_api() {
    let h = Harness::start(pvs).await;
    h.issuer
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
        Some("Bearer exchanged-alice-1")
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
