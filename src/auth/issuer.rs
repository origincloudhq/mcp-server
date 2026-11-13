//! The authorization server: its OpenID configuration and the keys it signs
//! tokens with.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde::Deserialize;
use tokio::sync::{OnceCell, RwLock};

/// How long the keys are used before they are fetched again, so that a key
/// the issuer retired stops verifying tokens.
const KEYS_MAX_AGE: Duration = Duration::from_secs(600);

/// The least time between two fetches of the keys asked for by a token whose
/// key isn't known: a stream of tokens naming made-up keys must not become a
/// stream of requests to the issuer.
const KEYS_MIN_REFETCH: Duration = Duration::from_secs(30);

/// How long a request to the issuer may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// What the server needs of the issuer's OpenID configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
}

/// Why the issuer couldn't be asked.
#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("reading {url}: {source}")]
    Request {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("the OpenID configuration at {url} names the issuer {found:?}, not {expected:?}")]
    WrongIssuer {
        url: String,
        found: String,
        expected: String,
    },
}

/// The issuer, its configuration discovered once, its keys refetched as
/// they age or as a token names a key that isn't known.
pub struct Issuer {
    id: String,
    http: reqwest::Client,
    metadata: OnceCell<Metadata>,
    keys: RwLock<Option<Keys>>,
}

struct Keys {
    set: Arc<JwkSet>,
    fetched: Instant,
}

impl Issuer {
    pub fn new(id: String, http: reqwest::Client) -> Self {
        Self {
            id,
            http,
            metadata: OnceCell::new(),
            keys: RwLock::new(None),
        }
    }

    /// The issuer identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the configuration has been read.
    pub fn discovered(&self) -> bool {
        self.metadata.initialized()
    }

    /// The issuer's OpenID configuration, read once. Its `issuer` must be
    /// this issuer's identifier (OpenID Connect Discovery, section 4.3).
    pub async fn metadata(&self) -> Result<&Metadata, IssuerError> {
        self.metadata
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", self.id);
                let metadata: Metadata = self.get_json(&url).await?;
                if metadata.issuer != self.id {
                    return Err(IssuerError::WrongIssuer {
                        url,
                        found: metadata.issuer,
                        expected: self.id.clone(),
                    });
                }
                Ok(metadata)
            })
            .await
    }

    /// The key `kid` names, or the keys usable for `alg` when the token
    /// names none. Keys older than [`KEYS_MAX_AGE`] are fetched again, and
    /// so are keys that don't hold `kid`, at most every
    /// [`KEYS_MIN_REFETCH`].
    pub async fn keys_for(&self, kid: Option<&str>) -> Result<Vec<Jwk>, IssuerError> {
        let (set, fresh) = self.current_keys(false).await?;
        let found = select(&set, kid);
        if !found.is_empty() || kid.is_none() || fresh {
            return Ok(found);
        }
        let (set, _) = self.current_keys(true).await?;
        Ok(select(&set, kid))
    }

    /// The keys, fetched again when they are too old, or when `unknown_kid`
    /// and they are old enough to fetch again. The flag says whether they
    /// were fetched by this call.
    async fn current_keys(&self, unknown_kid: bool) -> Result<(Arc<JwkSet>, bool), IssuerError> {
        let stale = |keys: &Option<Keys>| match keys {
            None => true,
            Some(k) => {
                let age = k.fetched.elapsed();
                age >= KEYS_MAX_AGE || (unknown_kid && age >= KEYS_MIN_REFETCH)
            }
        };
        {
            let keys = self.keys.read().await;
            if !stale(&keys) {
                let set = Arc::clone(&keys.as_ref().expect("not stale").set);
                return Ok((set, false));
            }
        }
        let mut keys = self.keys.write().await;
        // Another request may have fetched them while this one waited.
        if !stale(&keys) {
            let set = Arc::clone(&keys.as_ref().expect("not stale").set);
            return Ok((set, false));
        }
        let url = self.metadata().await?.jwks_uri.clone();
        let set: Arc<JwkSet> = match self.get_json::<JwkSet>(&url).await {
            Ok(set) => Arc::new(set),
            // The keys held are better than none while the issuer can't be
            // reached; they are asked for again on the next token.
            Err(error) => match keys.as_ref() {
                Some(k) if k.fetched.elapsed() < KEYS_MAX_AGE * 6 => {
                    tracing::warn!(%error, "the issuer's keys couldn't be fetched again; using the ones held");
                    return Ok((Arc::clone(&k.set), false));
                }
                _ => return Err(error),
            },
        };
        tracing::info!(keys = set.keys.len(), "fetched the issuer's keys");
        *keys = Some(Keys {
            set: Arc::clone(&set),
            fetched: Instant::now(),
        });
        Ok((set, true))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, IssuerError> {
        let error = |source| IssuerError::Request {
            url: url.to_owned(),
            source,
        };
        self.http
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(error)?
            .json()
            .await
            .map_err(error)
    }
}

/// The keys of `set` for a token naming `kid`: that key, or every key when
/// the token names none.
fn select(set: &JwkSet, kid: Option<&str>) -> Vec<Jwk> {
    match kid {
        Some(kid) => set.find(kid).cloned().into_iter().collect(),
        None => set.keys.clone(),
    }
}
