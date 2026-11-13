//! Token exchange (RFC 8693): the caller's token, issued for this server,
//! for one the API accepts, issued to this server's client on the caller's
//! behalf. The caller's token itself never leaves the server except to the
//! authorization server that issued it.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::auth::{Caller, Issuer};
use crate::config::Secret;
use crate::metrics;

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// How long before its expiry an exchanged token is replaced, so that it
/// doesn't expire on the way to the API.
const EXPIRY_MARGIN: Duration = Duration::from_secs(30);

/// How long an exchange may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The most exchanged tokens held; past it, the ones expiring soonest are
/// dropped.
const MAX_CACHED: usize = 10_000;

/// Why a token couldn't be exchanged.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("the caller's token has expired; sign in again")]
    Expired,
    #[error("the authorization server can't be reached: {0}")]
    Unreachable(String),
    #[error("the authorization server refused to exchange the caller's token ({error}{})", description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    Refused {
        error: String,
        description: Option<String>,
    },
    #[error("the authorization server's answer couldn't be read: {0}")]
    Malformed(String),
}

/// The token endpoint's answer (RFC 8693, section 2.2).
#[derive(Deserialize)]
struct Issued {
    access_token: String,
    expires_in: Option<u64>,
}

/// Its error answer (RFC 6749, section 5.2).
#[derive(Deserialize)]
struct Refused {
    error: String,
    error_description: Option<String>,
}

#[derive(Clone)]
struct Exchanged {
    token: Arc<str>,
    /// When it is replaced: before its expiry, never after the caller's.
    renew_at: SystemTime,
}

/// Exchanges callers' tokens as one confidential client, and keeps each
/// exchanged token until it is due to be replaced.
pub struct Exchanger {
    http: reqwest::Client,
    issuer: Arc<Issuer>,
    client_id: String,
    client_secret: Secret,
    audience: String,
    /// By the SHA-256 of the caller's token: the server holds the tokens it
    /// was issued, not the callers'.
    cache: Mutex<HashMap<[u8; 32], Exchanged>>,
}

impl fmt::Debug for Exchanger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchanger")
            .field("client_id", &self.client_id)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl Exchanger {
    pub fn new(
        http: reqwest::Client,
        issuer: Arc<Issuer>,
        client_id: String,
        client_secret: Secret,
        audience: String,
    ) -> Self {
        Self {
            http,
            issuer,
            client_id,
            client_secret,
            audience,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// An access token for the API on `caller`'s behalf: the one exchanged
    /// for the caller's token before, while it is valid, or a new one.
    pub async fn token(&self, caller: &Caller) -> Result<Arc<str>, ExchangeError> {
        let now = SystemTime::now();
        if caller.expires_at <= now {
            return Err(ExchangeError::Expired);
        }
        let key: [u8; 32] = Sha256::digest(caller.token.as_bytes()).into();
        if let Some(found) = self.lock().get(&key).filter(|e| e.renew_at > now) {
            metrics::exchange("cached");
            return Ok(Arc::clone(&found.token));
        }
        let issued = match self.exchange(&caller.token).await {
            Ok(issued) => issued,
            Err(error) => {
                metrics::exchange("failed");
                return Err(error);
            }
        };
        metrics::exchange("exchanged");
        let token: Arc<str> = Arc::from(issued.access_token);
        let lifetime = Duration::from_secs(issued.expires_in.unwrap_or(0));
        let renew_at = (now + lifetime)
            .min(caller.expires_at)
            .checked_sub(EXPIRY_MARGIN)
            .unwrap_or(now);
        if renew_at > now {
            self.remember(
                key,
                Exchanged {
                    token: Arc::clone(&token),
                    renew_at,
                },
                now,
            );
        }
        Ok(token)
    }

    /// The exchange itself, as this server's client (RFC 8693, section 2.1).
    async fn exchange(&self, subject_token: &str) -> Result<Issued, ExchangeError> {
        let endpoint = self
            .issuer
            .metadata()
            .await
            .map_err(|e| ExchangeError::Unreachable(e.to_string()))?
            .token_endpoint
            .clone();
        let response = self
            .http
            .post(&endpoint)
            .timeout(REQUEST_TIMEOUT)
            .basic_auth(&self.client_id, Some(self.client_secret.expose()))
            .form(&[
                ("grant_type", GRANT_TYPE),
                ("subject_token", subject_token),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("requested_token_type", ACCESS_TOKEN_TYPE),
                ("audience", self.audience.as_str()),
            ])
            .send()
            .await
            .map_err(|e| ExchangeError::Unreachable(e.without_url().to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| ExchangeError::Unreachable(e.without_url().to_string()))?;
        if status.is_success() {
            return serde_json::from_slice::<Issued>(&body)
                .map_err(|e| ExchangeError::Malformed(e.to_string()));
        }
        match serde_json::from_slice::<Refused>(&body) {
            Ok(refused) => {
                tracing::warn!(status = status.as_u16(), error = %refused.error, "the token exchange was refused");
                Err(ExchangeError::Refused {
                    error: refused.error,
                    description: refused.error_description,
                })
            }
            Err(_) if status.is_server_error() => Err(ExchangeError::Unreachable(format!(
                "the token endpoint answered {status}"
            ))),
            Err(_) => Err(ExchangeError::Malformed(format!(
                "the token endpoint answered {status}"
            ))),
        }
    }

    fn remember(&self, key: [u8; 32], exchanged: Exchanged, now: SystemTime) {
        let mut cache = self.lock();
        if cache.len() >= MAX_CACHED {
            cache.retain(|_, e| e.renew_at > now);
        }
        while cache.len() >= MAX_CACHED {
            let Some(soonest) = cache
                .iter()
                .min_by_key(|(_, e)| e.renew_at)
                .map(|(k, _)| *k)
            else {
                break;
            };
            cache.remove(&soonest);
        }
        cache.insert(key, exchanged);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Exchanged>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}
