//! The SDK clients the tools call the API through: one per caller, holding
//! the caller's latest token and the consistency token of the caller's
//! writes, so that a read sees what the caller wrote before, from any of the
//! caller's connections to this server.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use origincloud_core::credentials::TokenFuture;
use origincloud_core::{Client, Credentials};

use crate::auth::Caller;
use crate::exchange::Exchanger;

/// How long a caller's client is kept after its last call.
const IDLE: Duration = Duration::from_secs(3600);

/// The most callers whose clients are kept; past it, the ones idle longest
/// are dropped.
const MAX_CALLERS: usize = 10_000;

/// Where the API is, for every caller.
#[derive(Clone, Debug, Default)]
pub struct Api {
    /// The region whose front door the calls go to.
    pub region: Option<String>,
    /// One endpoint for every service instead of the public hosts.
    pub endpoint: Option<String>,
}

/// The clients of the callers this server has served lately.
pub struct Registry {
    api: Api,
    exchanger: Arc<Exchanger>,
    http: reqwest::Client,
    callers: Mutex<HashMap<String, Held>>,
}

struct Held {
    client: Client,
    credentials: Arc<CallerCredentials>,
    used: Instant,
}

impl Registry {
    pub fn new(api: Api, exchanger: Arc<Exchanger>, http: reqwest::Client) -> Self {
        Self {
            api,
            exchanger,
            http,
            callers: Mutex::new(HashMap::new()),
        }
    }

    /// `caller`'s client, its credentials now presenting `caller`'s token.
    pub fn client(&self, caller: &Caller) -> Result<Client, origincloud_core::Error> {
        let now = Instant::now();
        let mut callers = self.callers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(held) = callers.get_mut(&caller.subject) {
            held.credentials.present(caller);
            held.used = now;
            return Ok(held.client.clone());
        }
        let credentials = Arc::new(CallerCredentials {
            exchanger: Arc::clone(&self.exchanger),
            caller: Mutex::new(caller.clone()),
        });
        let mut builder = Client::builder()
            .credentials(Shared(Arc::clone(&credentials)))
            .http_client(self.http.clone())
            .user_agent(concat!(
                "origincloud-mcp-server/",
                env!("CARGO_PKG_VERSION")
            ));
        if let Some(region) = &self.api.region {
            builder = builder.region(region.clone());
        }
        if let Some(endpoint) = &self.api.endpoint {
            builder = builder.endpoint(endpoint.clone());
        }
        let client = builder.build()?;
        if callers.len() >= MAX_CALLERS {
            callers.retain(|_, h| now.duration_since(h.used) < IDLE);
        }
        while callers.len() >= MAX_CALLERS {
            let Some(idlest) = callers
                .iter()
                .min_by_key(|(_, h)| h.used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            callers.remove(&idlest);
        }
        callers.insert(
            caller.subject.clone(),
            Held {
                client: client.clone(),
                credentials,
                used: now,
            },
        );
        Ok(client)
    }
}

/// A caller's credentials: the token exchanged for the caller's latest one.
struct CallerCredentials {
    exchanger: Arc<Exchanger>,
    caller: Mutex<Caller>,
}

impl CallerCredentials {
    /// Presents `caller`'s token from now on: the latest the caller sent,
    /// all of them the same subject's.
    fn present(&self, caller: &Caller) {
        *self.caller.lock().unwrap_or_else(|e| e.into_inner()) = caller.clone();
    }
}

/// [`CallerCredentials`] as the SDK takes them, shared with the registry.
struct Shared(Arc<CallerCredentials>);

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallerCredentials(..)")
    }
}

impl Credentials for Shared {
    fn token(&self) -> TokenFuture<'_> {
        Box::pin(async move {
            let caller = self
                .0
                .caller
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            self.0
                .exchanger
                .token(&caller)
                .await
                .map(|t| t.to_string())
                .map_err(|e| origincloud_core::Error::Credentials(e.to_string()))
        })
    }
}
