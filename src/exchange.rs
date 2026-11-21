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
use tokio::sync::{OnceCell, Semaphore};
use url::Url;

use crate::auth::{Caller, Proof};
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

/// The most refusals remembered; past it, the oldest is forgotten for a new
/// one.
const MAX_REFUSALS: usize = 10_000;

/// The most distinct tokens being exchanged at once; past it, a new one is
/// answered as busy.
const MAX_INFLIGHT: usize = 10_000;

/// How many exchanges of tokens this server hasn't checked may be in flight
/// at once, and how many it starts per second (with a burst of twice
/// that): whoever holds such a token might have made it up, and each one
/// costs the STS a check of this server's certificate chain. Tokens that
/// were exchanged before, and tokens this server checked, aren't limited.
const UNPROVEN_CONCURRENCY: usize = 8;
const UNPROVEN_PER_SECOND: f64 = 20.0;

/// Why a token couldn't be exchanged. The detail is for the logs; what a
/// caller is told is [`ExchangeError::public`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExchangeError {
    #[error("the caller's token has expired; sign in again")]
    Expired,
    #[error("this server has no credential for the STS to take: {0}")]
    Actor(String),
    #[error("the STS can't be reached: {0}")]
    Unreachable(String),
    /// The STS decided the token isn't one it exchanges (`invalid_grant`).
    #[error("the STS refused to exchange the caller's token ({error}{})", description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    Refused {
        error: String,
        description: Option<String>,
    },
    /// The STS answered an error that isn't about the token: this server's
    /// request or its credential is wrong (`invalid_request`,
    /// `invalid_client`, `invalid_target`, ...), and asking again changes
    /// nothing until someone fixes it.
    #[error("the STS answered that this server's request is wrong ({error}{})", description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    Fault {
        error: String,
        description: Option<String>,
    },
    #[error("the STS's answer couldn't be read: {0}")]
    Malformed(String),
    /// Too many tokens this server hasn't checked are being exchanged.
    #[error("too many tokens are being checked")]
    Busy,
}

impl ExchangeError {
    /// What a caller may be told: nothing of this server's files, the STS's
    /// words or its own configuration.
    pub fn public(&self) -> &'static str {
        match self {
            Self::Expired => "the caller's token has expired; sign in again",
            Self::Refused { .. } => "the STS refused to exchange the caller's token",
            _ => "the caller's token couldn't be exchanged now; try again later",
        }
    }
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
    /// When the caller's token expires: until then the STS has taken it
    /// once, so exchanging it again isn't a first check.
    proven_until: SystemTime,
}

type Flight = Arc<OnceCell<Result<Arc<str>, ExchangeError>>>;
type Inflight = HashMap<[u8; 32], Flight>;

/// A caller's place in an exchange in flight. When the last one leaves,
/// however it does, the exchange is forgotten: a caller that is dropped
/// mid-exchange mustn't leave its entry behind.
struct Joined {
    key: [u8; 32],
    flight: Flight,
    inflight: Arc<Mutex<Inflight>>,
}

impl Drop for Joined {
    fn drop(&mut self) {
        let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        // Held by the map and this caller alone: no waiter is left.
        if Arc::strong_count(&self.flight) == 2
            && inflight
                .get(&self.key)
                .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
        {
            inflight.remove(&self.key);
        }
    }
}

/// A rate limit by a bucket that fills continuously.
struct Bucket {
    tokens: f64,
    at: Instant,
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
    /// The exchanges in flight, one per token: callers presenting the same
    /// token wait for the first one's exchange and take its result, failed
    /// or not. If the caller doing the exchange goes away (its request is
    /// dropped), the next waiter does it.
    inflight: Arc<Mutex<Inflight>>,
    unproven: Semaphore,
    rate: Mutex<Bucket>,
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
            inflight: Arc::default(),
            unproven: Semaphore::new(UNPROVEN_CONCURRENCY),
            rate: Mutex::new(Bucket {
                tokens: UNPROVEN_PER_SECOND * 2.0,
                at: Instant::now(),
            }),
        }
    }

    /// An access token for the API on `caller`'s behalf: the one exchanged
    /// for the caller's token before, while it is valid, or a new one.
    /// Callers presenting one token at once share one exchange.
    pub async fn token(&self, caller: &Caller) -> Result<Arc<str>, ExchangeError> {
        let now = SystemTime::now();
        if caller.expires_at <= now {
            return Err(ExchangeError::Expired);
        }
        let key: [u8; 32] = Sha256::digest(caller.token.as_bytes()).into();
        if let Some(found) = self.held(&key, now) {
            return found;
        }
        let joined = {
            let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if !inflight.contains_key(&key) && inflight.len() >= MAX_INFLIGHT {
                metrics::exchange("busy");
                return Err(ExchangeError::Busy);
            }
            let flight = Arc::clone(inflight.entry(key).or_default());
            Joined {
                key,
                flight,
                inflight: Arc::clone(&self.inflight),
            }
        };
        joined
            .flight
            .get_or_init(|| async {
                match self.held(&key, SystemTime::now()) {
                    // Another flight of this token finished meanwhile.
                    Some(found) => found,
                    None => self.exchange_new(&key, caller).await,
                }
            })
            .await
            .clone()
    }

    /// What is known of `key` without asking: its exchanged token while
    /// valid, or the STS's refusal of it.
    fn held(&self, key: &[u8; 32], now: SystemTime) -> Option<Result<Arc<str>, ExchangeError>> {
        if let Some(found) = self.lock().get(key).filter(|e| e.renew_at > now) {
            metrics::exchange("cached");
            return Some(Ok(Arc::clone(&found.token)));
        }
        let error = self.refusal_of(key)?;
        metrics::exchange("failed");
        Some(Err(error))
    }

    async fn exchange_new(
        &self,
        key: &[u8; 32],
        caller: &Caller,
    ) -> Result<Arc<str>, ExchangeError> {
        let now = SystemTime::now();
        // A token this server can't tell is genuine, and the STS hasn't
        // taken before, is exchanged at a limited rate.
        let first = caller.proof == Proof::Exchange
            && !self
                .lock()
                .get(key)
                .is_some_and(|known| known.proven_until > now);
        let _permit = if first {
            Some(
                self.admit_unproven()
                    .inspect_err(|_| metrics::exchange("busy"))?,
            )
        } else {
            None
        };
        let issued = match self.exchange(&caller.token, now).await {
            Ok(issued) => issued,
            Err(error) => {
                metrics::exchange("failed");
                // Only the STS's decision about the token is remembered,
                // and not while the token isn't valid yet: the STS may
                // take it a moment later.
                let early = caller.not_before.is_some_and(|nbf| nbf > now);
                if matches!(error, ExchangeError::Refused { .. }) && !early {
                    self.remember_refusal(*key, error.clone());
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
                *key,
                Exchanged {
                    token: Arc::clone(&token),
                    renew_at,
                    proven_until: caller.expires_at,
                },
                now,
            );
        }
        Ok(token)
    }

    /// A place among the exchanges of unchecked tokens, or [`ExchangeError::Busy`].
    fn admit_unproven(&self) -> Result<tokio::sync::SemaphorePermit<'_>, ExchangeError> {
        {
            let mut bucket = self.rate.lock().unwrap_or_else(|e| e.into_inner());
            let elapsed = bucket.at.elapsed().as_secs_f64();
            bucket.at = Instant::now();
            bucket.tokens =
                (bucket.tokens + elapsed * UNPROVEN_PER_SECOND).min(UNPROVEN_PER_SECOND * 2.0);
            if bucket.tokens < 1.0 {
                return Err(ExchangeError::Busy);
            }
            bucket.tokens -= 1.0;
        }
        self.unproven.try_acquire().map_err(|_| ExchangeError::Busy)
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
            // Only `invalid_grant` says the token, or this server's proof
            // of itself, isn't accepted. Anything else is this server's
            // request or credential being wrong.
            Ok(refused) if refused.error == "invalid_grant" => {
                tracing::warn!(status = status.as_u16(), "the STS refused a token");
                Err(ExchangeError::Refused {
                    error: refused.error,
                    description: refused.error_description,
                })
            }
            Ok(refused) => {
                tracing::error!(
                    status = status.as_u16(),
                    error = %refused.error,
                    description = refused.error_description.as_deref().unwrap_or_default(),
                    "the STS answered that this server's request is wrong"
                );
                Err(ExchangeError::Fault {
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
        // Still full: the oldest refusal makes room for this one.
        while refused.len() >= MAX_REFUSALS {
            let Some(oldest) = refused
                .iter()
                .min_by_key(|(_, (until, _))| *until)
                .map(|(k, _)| *k)
            else {
                break;
            };
            refused.remove(&oldest);
        }
        refused.insert(key, (now + REFUSAL_MEMORY, error));
    }

    fn remember(&self, key: [u8; 32], exchanged: Exchanged, now: SystemTime) {
        let mut cache = self.lock();
        if cache.len() >= MAX_CACHED {
            cache.retain(|_, e| e.proven_until > now);
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use tokio::net::TcpListener;

    use super::*;

    /// An exchanger for an STS at `port` of this machine, and the
    /// certificate files it needs.
    fn exchanger(port: u16) -> (Exchanger, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::random(&mut rand_core::OsRng);
        std::fs::write(
            dir.path().join("workload.key"),
            key.to_pkcs8_pem(LineEnding::LF).unwrap(),
        )
        .unwrap();
        for file in ["workload.crt", "chain.crt", "root.crt"] {
            std::fs::write(
                dir.path().join(file),
                "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n",
            )
            .unwrap();
        }
        let workload = Workload::new(dir.path().to_path_buf(), "spiffe://x/y".to_owned(), "z");
        let url = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        (Exchanger::new(reqwest::Client::new(), &url, workload), dir)
    }

    fn caller(token: &str) -> Caller {
        Caller {
            subject: "s".to_owned(),
            issuer: "origincloud:sts:z".to_owned(),
            client: None,
            proof: Proof::Exchange,
            token: Arc::from(token),
            expires_at: SystemTime::now() + Duration::from_secs(300),
            not_before: None,
        }
    }

    fn inflight(exchanger: &Exchanger) -> usize {
        exchanger.inflight.lock().unwrap().len()
    }

    /// A server that accepts connections, counts them, and either hangs up
    /// at once or never answers.
    async fn server(hang: bool) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                if hang {
                    held.push(stream);
                }
            }
        });
        (port, accepted)
    }

    #[tokio::test]
    async fn an_exchange_dropped_midway_leaves_nothing_behind() {
        let (port, accepted) = server(true).await;
        let (exchanger, _dir) = exchanger(port);
        let exchanger = Arc::new(exchanger);
        let mut tasks = Vec::new();
        for n in 0..5 {
            let (e, c) = (Arc::clone(&exchanger), caller(&format!("token-{n}")));
            tasks.push(tokio::spawn(async move { e.token(&c).await }));
        }
        while accepted.load(Ordering::SeqCst) < 5 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(inflight(&exchanger), 5);
        // The clients go away: the requests are dropped mid-exchange.
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        assert_eq!(inflight(&exchanger), 0);
    }

    #[tokio::test]
    async fn a_dropped_exchange_is_taken_over_by_a_waiter() {
        let (port, accepted) = server(true).await;
        let (exchanger, _dir) = exchanger(port);
        let exchanger = Arc::new(exchanger);
        let first = {
            let (e, c) = (Arc::clone(&exchanger), caller("same"));
            tokio::spawn(async move { e.token(&c).await })
        };
        while accepted.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let second = {
            let (e, c) = (Arc::clone(&exchanger), caller("same"));
            tokio::spawn(async move { e.token(&c).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        first.abort();
        let _ = first.await;
        // The waiter starts its own exchange, and the entry stays for it.
        while accepted.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(inflight(&exchanger), 1);
        second.abort();
        let _ = second.await;
        assert_eq!(inflight(&exchanger), 0);
    }

    #[tokio::test]
    async fn waiters_share_a_failed_exchange() {
        let (port, accepted) = server(false).await;
        let (exchanger, _dir) = exchanger(port);
        let exchanger = Arc::new(exchanger);
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let (e, c) = (Arc::clone(&exchanger), caller("same"));
            tasks.push(tokio::spawn(async move { e.token(&c).await }));
        }
        for task in tasks {
            assert!(matches!(
                task.await.unwrap(),
                Err(ExchangeError::Unreachable(_))
            ));
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "one exchange for all");
        assert_eq!(inflight(&exchanger), 0);
        // Not remembered beyond the flight: asked again.
        let _ = exchanger.token(&caller("same")).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_refusal_memory_is_bounded_and_forgets_the_oldest() {
        let (exchanger, _dir) = exchanger(1);
        let key = |n: u64| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&n.to_be_bytes());
            k
        };
        let refusal = || ExchangeError::Refused {
            error: "invalid_grant".to_owned(),
            description: None,
        };
        for n in 0..(MAX_REFUSALS as u64 + 5) {
            exchanger.remember_refusal(key(n), refusal());
        }
        let refused = exchanger.refused.lock().unwrap();
        assert_eq!(refused.len(), MAX_REFUSALS);
        assert!(!refused.contains_key(&key(0)), "the oldest was kept");
        assert!(
            refused.contains_key(&key(MAX_REFUSALS as u64 + 4)),
            "the newest was dropped"
        );
    }
}
