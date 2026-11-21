//! Token exchange (RFC 8693) at the zone's security token service (STS): the
//! caller's token, issued for this server, for one the API accepts, which
//! keeps the caller as its subject and names this server as the party acting
//! for them (`act`). The server proves itself with its workload certificate
//! as the `actor_token` ([`crate::workload`]). The caller's token never
//! leaves the server except to the STS.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::auth::Caller;
use crate::metrics;
use crate::workload::{Workload, WorkloadError, ASSERTION_TOKEN_TYPE};

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

/// How long a token the STS refused is refused again without asking: a
/// stream of one made-up token mustn't become a stream of requests to the
/// STS.
const REFUSAL_MEMORY: Duration = Duration::from_secs(30);

/// The most refusals remembered; past it, new ones are asked for again each
/// time.
const MAX_REFUSALS: usize = 10_000;

/// Why a token couldn't be exchanged.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExchangeError {
    #[error("the caller's token has expired; sign in again")]
    Expired,
    #[error("this server has no credential for the STS to take: {0}")]
    Actor(String),
    #[error("the STS can't be reached: {0}")]
    Unreachable(String),
    #[error("the STS refused to exchange the caller's token ({error}{})", description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    Refused {
        error: String,
        description: Option<String>,
    },
    #[error("the STS's answer couldn't be read: {0}")]
    Malformed(String),
}

impl From<WorkloadError> for ExchangeError {
    fn from(error: WorkloadError) -> Self {
        ExchangeError::Actor(error.to_string())
    }
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

/// Exchanges callers' tokens as the workload the STS knows this server as,
/// and keeps each exchanged token until it is due to be replaced.
pub struct Exchanger {
    http: reqwest::Client,
    /// The STS's token endpoint.
    endpoint: Url,
    workload: Workload,
    /// By the SHA-256 of the caller's token: the server holds the tokens it
    /// was issued, not the callers'.
    cache: Mutex<HashMap<[u8; 32], Exchanged>>,
    /// The tokens the STS refused, and when that is forgotten.
    refused: Mutex<HashMap<[u8; 32], (Instant, ExchangeError)>>,
}

impl fmt::Debug for Exchanger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchanger")
            .field("endpoint", &self.endpoint.as_str())
            .field("workload", &self.workload)
            .finish_non_exhaustive()
    }
}

impl Exchanger {
    /// An exchanger asking the STS at `sts` (its base URL), as `workload`.
    /// `http` must not follow redirects: the assertion and the caller's
    /// token go to the configured STS alone.
    pub fn new(http: reqwest::Client, sts: &Url, workload: Workload) -> Self {
        Self {
            http,
            endpoint: sts.join("/v1/token").expect("a base URL joins a path"),
            workload,
            cache: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
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
        if let Some(error) = self.refusal_of(&key) {
            metrics::exchange("failed");
            return Err(error);
        }
        let issued = match self.exchange(&caller.token, now).await {
            Ok(issued) => issued,
            Err(error) => {
                metrics::exchange("failed");
                if matches!(error, ExchangeError::Refused { .. }) {
                    self.remember_refusal(key, error.clone());
                }
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

    /// The exchange itself (RFC 8693, section 2.1): the caller's token as
    /// the subject, this server's workload assertion as the actor.
    async fn exchange(
        &self,
        subject_token: &str,
        now: SystemTime,
    ) -> Result<Issued, ExchangeError> {
        let seconds = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let assertion = self.workload.assertion(seconds).await?;
        let response = self
            .http
            .post(self.endpoint.clone())
            .timeout(REQUEST_TIMEOUT)
            .form(&[
                ("grant_type", GRANT_TYPE),
                ("subject_token", subject_token),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("requested_token_type", ACCESS_TOKEN_TYPE),
                ("actor_token", assertion.as_str()),
                ("actor_token_type", ASSERTION_TOKEN_TYPE),
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
        // The STS answers `503 temporarily_unavailable` for facts it can't
        // read yet: that decides nothing about the token, so it is asked
        // again, unlike a refusal.
        if status.is_server_error() || status == http::StatusCode::TOO_MANY_REQUESTS {
            return Err(ExchangeError::Unreachable(format!(
                "the STS answered {status}"
            )));
        }
        match serde_json::from_slice::<Refused>(&body) {
            Ok(refused) => {
                tracing::warn!(status = status.as_u16(), error = %refused.error, "the token exchange was refused");
                Err(ExchangeError::Refused {
                    error: refused.error,
                    description: refused.error_description,
                })
            }
            Err(_) => Err(ExchangeError::Malformed(format!(
                "the STS answered {status}"
            ))),
        }
    }

    fn refusal_of(&self, key: &[u8; 32]) -> Option<ExchangeError> {
        let mut refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
        match refused.get(key) {
            Some((until, error)) if *until > Instant::now() => Some(error.clone()),
            Some(_) => {
                refused.remove(key);
                None
            }
            None => None,
        }
    }

    fn remember_refusal(&self, key: [u8; 32], error: ExchangeError) {
        let mut refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if refused.len() >= MAX_REFUSALS {
            refused.retain(|_, (until, _)| *until > now);
        }
        if refused.len() < MAX_REFUSALS {
            refused.insert(key, (now + REFUSAL_MEMORY, error));
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
