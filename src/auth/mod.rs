//! The server as an OAuth resource server: it accepts a request only with a
//! bearer token issued for it, by the Keycloak realm people sign in at or by
//! a zone's STS, and tells a client without one where to get one.
//!
//! A realm's token is checked here, against the keys of the realm's JWKS. A
//! zone's STS (`origincloud:sts:<zone>`) publishes no key set this server
//! can read, so the signature of its tokens is checked by the STS itself,
//! which this server asks to exchange the token before the request is
//! served ([`Proof::Exchange`]); everything else is checked here first.

mod issuer;

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http::HeaderMap;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

pub use issuer::Issuer;

/// How far the clocks of the issuer and the server may differ: a token
/// whose `nbf` is that far ahead is still taken. A token is never taken
/// after its `exp`.
pub const LEEWAY: Duration = Duration::from_secs(30);

/// The furthest ahead a token's `exp` may be: an access token lives
/// minutes, so a later one is no token of the issuers this server trusts.
const MAX_LIFETIME: Duration = Duration::from_secs(7 * 24 * 3600);

/// The longest token read: a realm's token with many roles is a few
/// kilobytes.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

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

/// The prefix of the `iss` of a zone STS's tokens, then the zone's name.
const STS_ISSUER_PREFIX: &str = "origincloud:sts:";

/// What has checked a token's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    /// This server, against its issuer's keys.
    Signature,
    /// Nothing yet: the STS checks it when it exchanges the token, which
    /// the server does before it serves the request.
    Exchange,
}

/// Who a request is from: the subject of its access token, and the token,
/// which the server only ever exchanges.
#[derive(Clone)]
pub struct Caller {
    /// The token's subject, `sub`, a user or a service account.
    pub subject: String,
    /// Who issued the token: the realm, or a zone's STS.
    pub issuer: String,
    /// The client the token was issued to, `azp`, such as an MCP client.
    /// A zone STS's tokens name none.
    pub client: Option<String>,
    /// What has checked the token's signature.
    pub proof: Proof,
    /// The access token itself.
    pub token: Arc<str>,
    /// When the token expires.
    pub expires_at: SystemTime,
    /// When the token becomes valid, if it says.
    pub not_before: Option<SystemTime>,
    /// The service account the caller acts as on this connection, by its
    /// full name (`?service_account=`): the API is called with that
    /// account's token, never the caller's own.
    pub service_account: Option<Arc<str>>,
}

impl fmt::Debug for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Caller")
            .field("subject", &self.subject)
            .field("client", &self.client)
            .field("service_account", &self.service_account)
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
    /// The token is valid, but was issued to a client the server was
    /// restricted not to serve (`--allowed-clients`).
    #[error("{0}")]
    Client(String),
    /// The token is valid, but the STS refused to let its caller act as
    /// the service account the connection names (`?service_account=`).
    #[error("{0}")]
    Impersonation(String),
    /// The token couldn't be checked: the issuer's keys couldn't be read,
    /// or the STS couldn't be asked.
    #[error("the token couldn't be checked: {0}")]
    Unavailable(String),
    /// The STS is being asked about too many tokens nobody has checked:
    /// try again shortly. Counted as `unavailable`, but not an error of
    /// the server's, and not logged as one.
    #[error("too many tokens are being checked")]
    Busy,
}

impl Refusal {
    /// The `reason` label of the refusal's metric.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid(_) => "invalid",
            Self::Client(_) => "client",
            Self::Impersonation(_) => "impersonation",
            Self::Unavailable(_) | Self::Busy => "unavailable",
        }
    }
}

/// The claims of an access token the server reads; for a realm's token the
/// library checks `iss`, `aud`, `exp` and `nbf`.
#[derive(Deserialize)]
struct Claims {
    sub: Option<String>,
    azp: Option<String>,
    exp: u64,
    nbf: Option<u64>,
    typ: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

/// An STS token's claims, read before its signature is checked, to refuse
/// what can be refused without asking the STS.
#[derive(Deserialize)]
struct StsClaims {
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<u64>,
    nbf: Option<u64>,
}

/// What a token's lifetime says, checked against `now` (seconds since the
/// epoch): not expired, not further ahead than [`MAX_LIFETIME`], and not
/// valid later than the leeway. `exp` isn't given leeway, so that a token
/// this server takes is one the exchange won't find expired.
fn lifetime(
    exp: u64,
    nbf: Option<u64>,
    now: u64,
) -> Result<(SystemTime, Option<SystemTime>), Refusal> {
    if exp <= now {
        return Err(Refusal::Invalid("the token has expired".to_owned()));
    }
    if exp - now > MAX_LIFETIME.as_secs() {
        return Err(Refusal::Invalid(
            "the token's expiry is further ahead than this server accepts".to_owned(),
        ));
    }
    let not_yet = || Refusal::Invalid("the token isn't valid yet".to_owned());
    if nbf.is_some_and(|nbf| nbf > now.saturating_add(LEEWAY.as_secs())) {
        return Err(not_yet());
    }
    let at = |seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds));
    let expires = at(exp).ok_or_else(not_yet)?;
    Ok((expires, nbf.and_then(at)))
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `aud` is a string or a list of them (RFC 7519, section 4.1.3).
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, audience: &str) -> bool {
        match self {
            Self::One(a) => a == audience,
            Self::Many(all) => all.iter().any(|a| a == audience),
        }
    }
}

/// Checks access tokens: issued by the realm or by a zone's STS, for the
/// server's audience, in their lifetime, and signed by the issuer (by this
/// server for the realm's, by the STS at the exchange for an STS's). When
/// restricted to clients (`azp`), only those clients' tokens are accepted.
pub struct Authenticator {
    issuer: Arc<Issuer>,
    audience: String,
    /// The clients a token must have been issued to; any when empty.
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
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Refusal::Invalid("the token is too long".to_owned()));
        }
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| Refusal::Invalid("the token isn't a JWT".to_owned()))?;
        if !ALGORITHMS.contains(&header.alg) {
            return Err(Refusal::Invalid(format!(
                "the token is signed with {:?}, which isn't accepted",
                header.alg
            )));
        }
        // Only which check applies is read from the unverified token.
        let issuer = unverified_issuer(token)
            .ok_or_else(|| Refusal::Invalid("the token isn't a JWT".to_owned()))?;
        if is_sts_issuer(&issuer) {
            // The STS signs EdDSA and names its key: a token that doesn't
            // is none of its, and isn't worth asking it about.
            if header.alg != Algorithm::EdDSA || header.kid.as_deref().is_none_or(str::is_empty) {
                return Err(Refusal::Invalid(
                    "the token isn't signed as the STS signs its tokens".to_owned(),
                ));
            }
            return self.sts_caller(token, issuer);
        }
        if issuer != self.issuer.id() {
            return Err(Refusal::Invalid(
                "the token was issued by an issuer this server doesn't trust".to_owned(),
            ));
        }
        let keys = self
            .issuer
            .keys_for(header.kid.as_deref())
            .await
            .map_err(|e| Refusal::Unavailable(e.to_string()))?;
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

/// The `iss` of a JWT, read without checking anything.
fn unverified_issuer(token: &str) -> Option<String> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("iss")?.as_str().map(str::to_owned)
}

/// Whether `iss` is a zone STS's: `origincloud:sts:` and a zone's name,
/// lowercase letters, digits and hyphens.
fn is_sts_issuer(iss: &str) -> bool {
    iss.strip_prefix(STS_ISSUER_PREFIX).is_some_and(|zone| {
        !zone.is_empty()
            && zone
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
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
    /// The caller of a realm's token, whose signature is checked, unless
    /// the server is restricted to some clients and the token isn't one's.
    /// It must be a person's, as the STS requires: an access token of a
    /// user, with the claims that say who.
    fn caller(&self, token: &str, claims: Claims) -> Result<Caller, Refusal> {
        let (expires_at, not_before) = lifetime(claims.exp, claims.nbf, now_seconds())?;
        let subject = claims
            .sub
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Refusal::Invalid("the token has no subject".to_owned()))?;
        let client = claims.azp.filter(|c| !c.is_empty());
        self.allow_client(client.as_deref())?;
        let not_a_person =
            |why: &str| Refusal::Invalid(format!("the token isn't a person's access token: {why}"));
        if claims.typ.as_deref().is_some_and(|typ| typ != "Bearer") {
            return Err(not_a_person("its type isn't Bearer"));
        }
        if uuid::Uuid::parse_str(&subject).is_err() {
            return Err(not_a_person("its subject isn't a user's id"));
        }
        let named = |claim: &Option<String>| claim.as_deref().is_some_and(|c| !c.is_empty());
        if !(named(&claims.email)
            && claims.email_verified.is_some()
            && named(&claims.name)
            && named(&claims.given_name)
            && named(&claims.family_name))
        {
            return Err(not_a_person(
                "it lacks the email, email_verified, name, given_name or family_name claim",
            ));
        }
        Ok(Caller {
            subject,
            issuer: self.issuer.id().to_owned(),
            client,
            proof: Proof::Signature,
            token: Arc::from(token),
            expires_at,
            not_before,
            service_account: None,
        })
    }

    /// The caller of a zone STS's token, whose issuer, audience and
    /// lifetime are checked here and whose signature is the STS's to check
    /// ([`Proof::Exchange`]).
    fn sts_caller(&self, token: &str, issuer: String) -> Result<Caller, Refusal> {
        let payload = token
            .split('.')
            .nth(1)
            .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .ok_or_else(|| Refusal::Invalid("the token isn't a JWT".to_owned()))?;
        let claims: StsClaims = serde_json::from_slice(&payload)
            .map_err(|_| Refusal::Invalid("the token isn't a JWT".to_owned()))?;
        let exp = claims
            .exp
            .ok_or_else(|| Refusal::Invalid("the token has no exp".to_owned()))?;
        let (expires_at, not_before) = lifetime(exp, claims.nbf, now_seconds())?;
        if !claims
            .aud
            .as_ref()
            .is_some_and(|aud| aud.contains(&self.audience))
        {
            return Err(Refusal::Invalid(format!(
                "the token wasn't issued for {}",
                self.audience
            )));
        }
        let subject = claims
            .sub
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Refusal::Invalid("the token has no subject".to_owned()))?;
        self.allow_client(None)?;
        Ok(Caller {
            subject,
            issuer,
            client: None,
            proof: Proof::Exchange,
            token: Arc::from(token),
            expires_at,
            not_before,
            service_account: None,
        })
    }

    /// Whether a token issued to `client` is served: any is, unless the
    /// server is restricted to some clients.
    fn allow_client(&self, client: Option<&str>) -> Result<(), Refusal> {
        if self.clients.is_empty()
            || client.is_some_and(|c| self.clients.iter().any(|allowed| allowed == c))
        {
            return Ok(());
        }
        Err(Refusal::Client(NOT_FOR_THIS_CLIENT.to_owned()))
    }
}

/// Why a token issued to another client is refused when the server is
/// restricted to some clients.
pub const NOT_FOR_THIS_CLIENT: &str =
    "the token wasn't issued to a client this server is restricted to";

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
/// A token of a client the server is restricted from is valid, so it isn't
/// `invalid_token`; the request needs privileges that token doesn't carry,
/// which RFC 6750 calls `insufficient_scope` and answers with 403. No
/// `scope` is named: no scope would make that client's token acceptable,
/// and a client stepping up would only ask for the same token again.
pub fn challenge(metadata_url: &str, scopes: &[String], refusal: &Refusal) -> String {
    let mut params = vec![format!("resource_metadata=\"{metadata_url}\"")];
    if let Refusal::Client(description) | Refusal::Impersonation(description) = refusal {
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
        assert!(c.contains("restricted"), "{c}");
    }

    #[test]
    fn only_a_zone_s_sts_is_an_sts_issuer() {
        assert!(is_sts_issuer("origincloud:sts:eu-central1-az1"));
        assert!(!is_sts_issuer("origincloud:sts:"));
        assert!(!is_sts_issuer("origincloud:sts:EU/1"));
        assert!(!is_sts_issuer("origincloud:api"));
        assert!(!is_sts_issuer("https://auth.example.com"));
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
