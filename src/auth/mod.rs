//! The server as an OAuth resource server: it accepts a request only with a
//! bearer token its authorization server issued for it, and tells a client
//! without one where to get one.

mod issuer;

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

pub use issuer::{Issuer, IssuerError};

/// How far the clocks of the issuer and the server may differ.
const LEEWAY: Duration = Duration::from_secs(30);

/// The algorithms a token may be signed with: asymmetric ones only, so that
/// the issuer's public keys can't verify a token signed with themselves.
const ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Who a request is from: the subject of its access token, and the token,
/// which the server only ever exchanges.
#[derive(Clone)]
pub struct Caller {
    /// The token's subject, `sub`, a user or a service account.
    pub subject: String,
    /// The client the token was issued to, `azp`, such as an MCP client.
    pub client: Option<String>,
    /// The access token itself.
    pub token: Arc<str>,
    /// When the token expires.
    pub expires_at: SystemTime,
}

impl fmt::Debug for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Caller")
            .field("subject", &self.subject)
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

/// Why a request isn't accepted.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The request has no bearer token: the client is to get one.
    #[error("the request has no bearer token")]
    Missing,
    /// The token isn't one the server accepts.
    #[error("{0}")]
    Invalid(String),
    /// The token is valid, but was issued to a client the server doesn't
    /// serve, such as a service account's: the server is for people who
    /// sign in through an MCP client.
    #[error("{0}")]
    Client(String),
    /// The issuer's keys couldn't be read, so no token can be checked.
    #[error("the authorization server can't be reached: {0}")]
    Unavailable(#[source] IssuerError),
}

impl Refusal {
    /// The `reason` label of the refusal's metric.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid(_) => "invalid",
            Self::Client(_) => "client",
            Self::Unavailable(_) => "unavailable",
        }
    }
}

/// The claims of an access token the server reads; the library checks
/// `iss`, `aud`, `exp` and `nbf`.
#[derive(Deserialize)]
struct Claims {
    sub: Option<String>,
    azp: Option<String>,
    exp: u64,
}

/// Checks access tokens: signed by the issuer with one of its keys, issued
/// by it, for the server's audience, in their lifetime, and to one of the
/// clients people sign in to the server with (`azp`).
pub struct Authenticator {
    issuer: Arc<Issuer>,
    audience: String,
    clients: Vec<String>,
}

impl Authenticator {
    pub fn new(issuer: Arc<Issuer>, audience: String, clients: Vec<String>) -> Self {
        Self {
            issuer,
            audience,
            clients,
        }
    }

    /// The caller of a request with `headers`.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Caller, Refusal> {
        let token = bearer(headers)?;
        self.verify(token).await
    }

    /// The caller `token` names, if the server accepts it.
    pub async fn verify(&self, token: &str) -> Result<Caller, Refusal> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| Refusal::Invalid("the token isn't a JWT".to_owned()))?;
        if !ALGORITHMS.contains(&header.alg) {
            return Err(Refusal::Invalid(format!(
                "the token is signed with {:?}, which isn't accepted",
                header.alg
            )));
        }
        let keys = self
            .issuer
            .keys_for(header.kid.as_deref())
            .await
            .map_err(Refusal::Unavailable)?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.issuer.id()]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY.as_secs();
        validation.validate_nbf = true;

        // The last reason a key refused the token, which says more than
        // "no key verified it" when the signature was right but a claim
        // wasn't.
        let mut refused = None;
        for key in keys.iter().filter(|k| usable(k, header.alg)) {
            let Ok(decoding) = DecodingKey::from_jwk(key) else {
                continue;
            };
            match jsonwebtoken::decode::<Claims>(token, &decoding, &validation) {
                Ok(data) => return self.caller(token, data.claims),
                Err(error) => refused = Some(error),
            }
        }
        Err(Refusal::Invalid(match refused {
            Some(error) => describe(&error, &self.audience),
            None => "no key of the issuer verifies the token".to_owned(),
        }))
    }
}

/// The bearer token of a request (RFC 6750, section 2.1).
fn bearer(headers: &HeaderMap) -> Result<&str, Refusal> {
    let Some(value) = headers.get(http::header::AUTHORIZATION) else {
        return Err(Refusal::Missing);
    };
    let value = value
        .to_str()
        .map_err(|_| Refusal::Invalid("the Authorization header isn't text".to_owned()))?;
    match value.split_once(' ') {
        Some((scheme, token))
            if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() =>
        {
            Ok(token.trim())
        }
        _ => Err(Refusal::Missing),
    }
}

/// Whether `key` can verify a token signed with `alg`: its own algorithm,
/// when it names one, is `alg`, and its type fits.
fn usable(key: &Jwk, alg: Algorithm) -> bool {
    if let Some(key_alg) = key.common.key_algorithm {
        if key_alg.to_string() != format!("{alg:?}") {
            return false;
        }
    }
    matches!(
        (&key.algorithm, alg),
        (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
        ) | (
            AlgorithmParameters::EllipticCurve(_),
            Algorithm::ES256 | Algorithm::ES384
        ) | (AlgorithmParameters::OctetKeyPair(_), Algorithm::EdDSA)
    )
}

impl Authenticator {
    /// The caller of a verified token, if it was issued to a client people
    /// sign in with. A service account's token is issued to the account's
    /// own client, so it is refused here, before it is ever exchanged.
    fn caller(&self, token: &str, claims: Claims) -> Result<Caller, Refusal> {
        let subject = claims
            .sub
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Refusal::Invalid("the token has no subject".to_owned()))?;
        let client = claims.azp.filter(|c| !c.is_empty());
        if !client
            .as_deref()
            .is_some_and(|c| self.clients.iter().any(|allowed| allowed == c))
        {
            return Err(Refusal::Client(NOT_FOR_THIS_CLIENT.to_owned()));
        }
        Ok(Caller {
            subject,
            client,
            token: Arc::from(token),
            expires_at: UNIX_EPOCH + Duration::from_secs(claims.exp),
        })
    }
}

/// Why a token issued to another client, such as a service account's, is
/// refused, and what to do instead.
pub const NOT_FOR_THIS_CLIENT: &str = "the hosted MCP server is for people who sign in \
    through their MCP client; a service account runs `origin mcp serve` with its own \
    credentials instead";

/// What a client is told about a token the server refused.
fn describe(error: &jsonwebtoken::errors::Error, audience: &str) -> String {
    use jsonwebtoken::errors::ErrorKind;
    match error.kind() {
        ErrorKind::ExpiredSignature => "the token has expired".to_owned(),
        ErrorKind::ImmatureSignature => "the token isn't valid yet".to_owned(),
        ErrorKind::InvalidAudience => format!("the token wasn't issued for {audience}"),
        ErrorKind::InvalidIssuer => {
            "the token wasn't issued by this server's authorization server".to_owned()
        }
        ErrorKind::InvalidSignature => "no key of the issuer verifies the token".to_owned(),
        ErrorKind::MissingRequiredClaim(claim) => format!("the token has no {claim}"),
        _ => "the token isn't valid".to_owned(),
    }
}

/// The `WWW-Authenticate` challenge of a refused request (RFC 6750, section
/// 3; RFC 9728, section 5.1): where the protected resource metadata is, the
/// scopes to request, and, for a token that was presented, why it was
/// refused.
///
/// A token of another client is valid, so it isn't `invalid_token`; the
/// request needs privileges that token doesn't carry, which RFC 6750 calls
/// `insufficient_scope` and answers with 403. No `scope` is named: no scope
/// a service account could request makes its token acceptable, and a
/// client stepping up would only ask for the same token again.
pub fn challenge(metadata_url: &str, scopes: &[String], refusal: &Refusal) -> String {
    let mut params = vec![format!("resource_metadata=\"{metadata_url}\"")];
    if let Refusal::Client(description) = refusal {
        params.push("error=\"insufficient_scope\"".to_owned());
        params.push(format!(
            "error_description=\"{}\"",
            description.replace(['"', '\\'], "'")
        ));
        return format!("Bearer {}", params.join(", "));
    }
    let scopes: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if !scopes.is_empty() {
        let mut scopes = scopes;
        scopes.sort_unstable();
        params.push(format!("scope=\"{}\"", scopes.join(" ")));
    }
    if let Refusal::Invalid(description) = refusal {
        params.push("error=\"invalid_token\"".to_owned());
        params.push(format!(
            "error_description=\"{}\"",
            description.replace(['"', '\\'], "'")
        ));
    }
    format!("Bearer {}", params.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_names_the_metadata_and_the_scopes() {
        let c = challenge(
            "https://mcp.example.com/.well-known/oauth-protected-resource",
            &["mcp".to_owned()],
            &Refusal::Missing,
        );
        assert_eq!(
            c,
            "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp\""
        );
    }

    #[test]
    fn a_refused_token_s_challenge_says_why() {
        let c = challenge(
            "https://m/.well-known/oauth-protected-resource",
            &[],
            &Refusal::Invalid("the token wasn't issued for \"x\"".to_owned()),
        );
        assert_eq!(
            c,
            "Bearer resource_metadata=\"https://m/.well-known/oauth-protected-resource\", error=\"invalid_token\", error_description=\"the token wasn't issued for 'x'\""
        );
    }

    #[test]
    fn another_client_s_token_is_challenged_for_insufficient_scope_without_a_scope() {
        let c = challenge(
            "https://m/.well-known/oauth-protected-resource",
            &["mcp".to_owned()],
            &Refusal::Client(NOT_FOR_THIS_CLIENT.to_owned()),
        );
        assert!(c.starts_with("Bearer resource_metadata=\"https://m/.well-known/oauth-protected-resource\", error=\"insufficient_scope\", error_description=\""), "{c}");
        assert!(!c.contains("scope=\"mcp\""), "{c}");
        assert!(c.contains("`origin mcp serve`"), "{c}");
    }

    #[test]
    fn only_a_bearer_token_is_read() {
        let mut headers = HeaderMap::new();
        assert!(matches!(bearer(&headers), Err(Refusal::Missing)));
        headers.insert(http::header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(matches!(bearer(&headers), Err(Refusal::Missing)));
        headers.insert(http::header::AUTHORIZATION, "bearer abc".parse().unwrap());
        assert_eq!(bearer(&headers).unwrap(), "abc");
    }
}
