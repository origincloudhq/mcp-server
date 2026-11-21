//! The server's configuration: flags, each also read from an environment
//! variable. The defaults are Origin Cloud's production values, except where
//! the server is told who it is to the STS, which has none.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use url::Url;

/// The hosted Origin Cloud MCP server.
///
/// It serves Origin Cloud's MCP tools over Streamable HTTP to clients that
/// present an access token issued for it, by the realm people sign in at or
/// by a zone's STS, and calls the API with a token the STS exchanges the
/// caller's for.
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

    /// The Keycloak realm people sign in at: it issues the tokens of people
    /// the server accepts and signs them with the keys of its JWKS, found
    /// through its OpenID configuration. The server also accepts the tokens
    /// of any zone's STS (`origincloud:sts:<zone>`).
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

    /// Restricts the server to tokens issued to these clients (`azp`),
    /// comma-separated. Empty, the default, accepts any valid token for the
    /// server's audience whatever the client; a zone STS's tokens name no
    /// client, so they are refused when this is set.
    #[arg(long, env = "MCP_ALLOWED_CLIENTS", value_delimiter = ',')]
    pub allowed_clients: Vec<String>,

    /// The base URL of the STS that exchanges callers' tokens, as its zone's
    /// workloads reach it. The assertion proving this server goes there, so
    /// it must be `https` (`http` on this machine only).
    #[arg(long, env = "MCP_STS_URL")]
    pub sts_url: Url,

    /// The zone whose STS `--sts-url` is: the assertion proving this server
    /// is for that zone's STS alone.
    #[arg(long, env = "MCP_STS_ZONE")]
    pub sts_zone: String,

    /// PEM certificates that are the only trust for the STS's name, when it
    /// isn't signed by a public authority.
    #[arg(long, env = "MCP_STS_CA_FILE")]
    pub sts_ca_file: Option<PathBuf>,

    /// The directory with this server's zone-CA workload certificate:
    /// `workload.key`, `workload.crt`, `chain.crt` and `root.crt`. Read for
    /// every exchange, so that a renewed certificate is used at once.
    #[arg(long, env = "MCP_WORKLOAD_DIR")]
    pub workload_dir: PathBuf,

    /// This server's workload identity, its certificate's SPIFFE id
    /// (`spiffe://...`): the STS names it in the tokens it issues, and only
    /// takes the one workload it is configured with.
    #[arg(long, env = "MCP_WORKLOAD_ID")]
    pub workload_id: String,

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

/// A [`Config`] that can't be served.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("the resource must be an absolute https URL without a query or fragment, got {0}")]
    Resource(String),
    #[error("the issuer must be an absolute URL, got {0}")]
    Issuer(String),
    #[error("the STS must be an absolute https URL (http on this machine only), got {0}")]
    StsUrl(String),
    #[error("the STS's zone must be lowercase letters, digits and hyphens, got {0:?}")]
    StsZone(String),
    #[error("the workload's identity must be a SPIFFE id (spiffe://...), got {0:?}")]
    WorkloadId(String),
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
        let sts = &self.sts_url;
        let local = matches!(sts.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(sts.scheme() == "https" || (sts.scheme() == "http" && local))
            || sts.host_str().is_none()
            || sts.cannot_be_a_base()
        {
            return Err(ConfigError::StsUrl(sts.to_string()));
        }
        if self.sts_zone.is_empty()
            || !self
                .sts_zone
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ConfigError::StsZone(self.sts_zone.clone()));
        }
        if !self.workload_id.starts_with("spiffe://") || self.workload_id.len() <= 9 {
            return Err(ConfigError::WorkloadId(self.workload_id.clone()));
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

    /// The config of the flags the STS needs and `args`, which replace the
    /// ones of the same name.
    fn config(args: &[&str]) -> Config {
        let mut flags: Vec<(&str, &str)> = vec![
            ("--sts-url", "https://sts.example.com"),
            ("--sts-zone", "zone-1"),
            ("--workload-dir", "/workload"),
            ("--workload-id", "spiffe://example.com/mcp-server"),
        ];
        for pair in args.chunks(2) {
            match flags.iter_mut().find(|(name, _)| *name == pair[0]) {
                Some(found) => found.1 = pair[1],
                None => flags.push((pair[0], pair[1])),
            }
        }
        let mut all = vec!["origincloud-mcp-server"];
        for (name, value) in flags {
            all.push(name);
            all.push(value);
        }
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
        assert!(c.allowed_clients.is_empty(), "any client by default");
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
    fn the_sts_and_the_workload_must_be_well_formed() {
        assert!(config(&["--sts-url", "http://sts.example.com"])
            .validate()
            .is_err());
        config(&["--sts-url", "http://127.0.0.1:9091"])
            .validate()
            .unwrap();
        assert!(config(&["--sts-zone", "Zone/1"]).validate().is_err());
        assert!(config(&["--workload-id", "mcp-server"]).validate().is_err());
    }

    #[test]
    fn clients_can_be_restricted() {
        let c = config(&["--allowed-clients", "a,b"]);
        assert_eq!(c.allowed_clients, ["a", "b"]);
    }
}
