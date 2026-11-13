//! The server's configuration: flags, each also read from an environment
//! variable. The defaults are Origin Cloud's production values, except the
//! exchange client's secret, which has none.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use url::Url;

/// The hosted Origin Cloud MCP server.
///
/// It serves Origin Cloud's MCP tools over Streamable HTTP to clients that
/// present an access token issued for it, and calls the API with a token
/// it exchanges the caller's for.
#[derive(Clone, Debug, Parser)]
#[command(version, about)]
pub struct Config {
    /// Where the MCP endpoint and the protected resource metadata are
    /// served.
    #[arg(long, env = "MCP_LISTEN_ADDRESS", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Where `/metrics`, `/healthz` and `/readyz` are served: a port of its
    /// own, not published with the MCP endpoint.
    #[arg(
        long,
        env = "MCP_METRICS_LISTEN_ADDRESS",
        default_value = "0.0.0.0:9090"
    )]
    pub metrics_listen: SocketAddr,

    /// The server's canonical URI (RFC 8707): the `resource` of its
    /// protected resource metadata, what clients request tokens for, and
    /// the host it answers for.
    #[arg(
        long,
        env = "MCP_RESOURCE",
        default_value = "https://mcp.origincloudapis.eu"
    )]
    pub resource: Url,

    /// The audience a token must carry to be accepted; the canonical URI
    /// when not given.
    #[arg(long, env = "MCP_AUDIENCE")]
    pub audience: Option<String>,

    /// The authorization server: it issues the tokens the server accepts,
    /// signs them with the keys of its JWKS, and exchanges them at its token
    /// endpoint, both found through its OpenID configuration.
    #[arg(
        long,
        env = "MCP_ISSUER",
        default_value = "https://auth.origincloud.eu/realms/origincloud"
    )]
    pub issuer: Url,

    /// The scopes a client requests a token with, which the protected
    /// resource metadata and the `WWW-Authenticate` challenge name;
    /// space-separated.
    #[arg(long, env = "MCP_SCOPES", default_value = "mcp", value_delimiter = ' ')]
    pub scopes: Vec<String>,

    /// The clients people sign in to the server with: a token must have been
    /// issued to one of them (`azp`). Any other token, such as a service
    /// account's, is refused before it is exchanged; comma-separated.
    #[arg(
        long,
        env = "MCP_ALLOWED_CLIENTS",
        default_value = "origincloud-mcp",
        value_delimiter = ','
    )]
    pub allowed_clients: Vec<String>,

    /// The confidential client the server exchanges callers' tokens as.
    #[arg(
        long,
        env = "MCP_EXCHANGE_CLIENT_ID",
        default_value = "origincloud-mcp-server"
    )]
    pub exchange_client_id: String,

    /// That client's secret.
    #[arg(long, env = "MCP_EXCHANGE_CLIENT_SECRET", hide_env_values = true)]
    pub exchange_client_secret: Secret,

    /// The audience an exchanged token is requested for: the one the API
    /// accepts.
    #[arg(long, env = "MCP_API_AUDIENCE", default_value = "account")]
    pub api_audience: String,

    /// The region whose front door the API calls go to, such as
    /// `eu-central1`; the regionless front door when not given.
    #[arg(long, env = "MCP_API_REGION")]
    pub api_region: Option<String>,

    /// One endpoint for every service's calls instead of the public hosts,
    /// such as a local fake of the API.
    #[arg(long, env = "MCP_API_ENDPOINT")]
    pub api_endpoint: Option<String>,

    /// More `Host` values to answer than the canonical URI's host, such as
    /// `localhost:8080`; comma-separated.
    #[arg(long, env = "MCP_ALLOWED_HOSTS", value_delimiter = ',')]
    pub allowed_hosts: Vec<String>,

    /// On a termination signal, how long the server reports unready while
    /// still serving, so that a load balancer stops sending it requests.
    #[arg(long, env = "MCP_UNREADY_ON_STOP_SECONDS", default_value_t = 0)]
    pub unready_on_stop_seconds: u64,

    /// Then how long requests in flight may take to finish; longer than a
    /// tool waiting on an operation.
    #[arg(long, env = "MCP_DRAIN_SECONDS", default_value_t = 65)]
    pub drain_seconds: u64,

    /// The log format.
    #[arg(long, env = "MCP_LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,
}

/// How logs are written to standard output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// One JSON object per line.
    Json,
    /// Text for a terminal.
    Text,
}

/// A value that is never printed.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl std::str::FromStr for Secret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

/// A [`Config`] that can't be served.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("the resource must be an absolute https URL without a query or fragment, got {0}")]
    Resource(String),
    #[error("the issuer must be an absolute URL, got {0}")]
    Issuer(String),
    #[error("the exchange client's secret is empty")]
    EmptySecret,
    #[error("no client is allowed: name at least one in --allowed-clients")]
    NoClient,
}

impl Config {
    /// Checks what the flags can't.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let r = &self.resource;
        let local = matches!(r.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(r.scheme() == "https" || (r.scheme() == "http" && local))
            || r.host_str().is_none()
            || r.query().is_some()
            || r.fragment().is_some()
        {
            return Err(ConfigError::Resource(r.to_string()));
        }
        if self.issuer.host_str().is_none() || self.issuer.cannot_be_a_base() {
            return Err(ConfigError::Issuer(self.issuer.to_string()));
        }
        if self.exchange_client_secret.expose().is_empty() {
            return Err(ConfigError::EmptySecret);
        }
        if !self.allowed_clients.iter().any(|c| !c.trim().is_empty()) {
            return Err(ConfigError::NoClient);
        }
        Ok(())
    }

    /// The canonical URI, as the protected resource metadata names it:
    /// without the trailing slash of a URI with no path.
    pub fn canonical_resource(&self) -> String {
        canonical(&self.resource)
    }

    /// The audience a token must carry.
    pub fn accepted_audience(&self) -> String {
        self.audience
            .clone()
            .unwrap_or_else(|| self.canonical_resource())
    }

    /// The issuer identifier, as the authorization server's metadata and
    /// its tokens name it.
    pub fn issuer_id(&self) -> String {
        canonical(&self.issuer)
    }

    /// The path of the protected resource metadata (RFC 9728, section 3):
    /// the well-known prefix, then the resource's path, if any.
    pub fn metadata_path(&self) -> String {
        let path = self.resource.path().trim_end_matches('/');
        format!("/.well-known/oauth-protected-resource{path}")
    }

    /// The URL of the protected resource metadata.
    pub fn metadata_url(&self) -> String {
        let mut origin = self.resource.origin().ascii_serialization();
        origin.push_str(&self.metadata_path());
        origin
    }

    /// The path the MCP endpoint is served at: the resource's.
    pub fn endpoint_path(&self) -> String {
        match self.resource.path().trim_end_matches('/') {
            "" => "/".to_owned(),
            path => path.to_owned(),
        }
    }

    /// The `Host` values the server answers: the resource's authority and
    /// the ones configured.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        if let Some(host) = self.resource.host_str() {
            hosts.push(host.to_owned());
            if let Some(port) = self.resource.port() {
                hosts.push(format!("{host}:{port}"));
            }
        }
        hosts.extend(self.allowed_hosts.iter().filter(|h| !h.is_empty()).cloned());
        hosts
    }

    pub fn unready_on_stop(&self) -> Duration {
        Duration::from_secs(self.unready_on_stop_seconds)
    }

    pub fn drain(&self) -> Duration {
        Duration::from_secs(self.drain_seconds)
    }
}

/// `url` as an identifier: without the trailing slash of a URL with no path.
fn canonical(url: &Url) -> String {
    let s = url.as_str();
    if url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
        s.trim_end_matches('/').to_owned()
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(args: &[&str]) -> Config {
        let mut all = vec!["origincloud-mcp-server", "--exchange-client-secret", "s"];
        all.extend_from_slice(args);
        Config::try_parse_from(all).unwrap()
    }

    #[test]
    fn the_defaults_are_production_s() {
        let c = config(&[]);
        c.validate().unwrap();
        assert_eq!(c.canonical_resource(), "https://mcp.origincloudapis.eu");
        assert_eq!(c.accepted_audience(), "https://mcp.origincloudapis.eu");
        assert_eq!(
            c.metadata_url(),
            "https://mcp.origincloudapis.eu/.well-known/oauth-protected-resource"
        );
        assert_eq!(c.endpoint_path(), "/");
        assert_eq!(
            c.issuer_id(),
            "https://auth.origincloud.eu/realms/origincloud"
        );
        assert_eq!(c.scopes, ["mcp"]);
        assert_eq!(c.allowed_clients, ["origincloud-mcp"]);
        assert_eq!(c.hosts(), ["mcp.origincloudapis.eu"]);
    }

    #[test]
    fn a_resource_with_a_path_has_its_metadata_under_that_path() {
        let c = config(&["--resource", "https://example.com/tools/mcp"]);
        assert_eq!(c.canonical_resource(), "https://example.com/tools/mcp");
        assert_eq!(
            c.metadata_url(),
            "https://example.com/.well-known/oauth-protected-resource/tools/mcp"
        );
        assert_eq!(c.endpoint_path(), "/tools/mcp");
    }

    #[test]
    fn a_resource_must_be_https_except_on_this_machine() {
        assert!(config(&["--resource", "http://example.com"])
            .validate()
            .is_err());
        assert!(config(&["--resource", "https://example.com/?a=b"])
            .validate()
            .is_err());
        config(&["--resource", "http://127.0.0.1:8080"])
            .validate()
            .unwrap();
        assert_eq!(
            config(&["--resource", "http://127.0.0.1:8080"]).hosts(),
            ["127.0.0.1", "127.0.0.1:8080"]
        );
    }

    #[test]
    fn the_secret_is_never_printed() {
        let c = config(&[]);
        assert!(!format!("{c:?}").contains("\"s\""));
        let c = Config::try_parse_from(["origincloud-mcp-server", "--exchange-client-secret", ""])
            .unwrap();
        assert!(matches!(c.validate(), Err(ConfigError::EmptySecret)));
    }
}
