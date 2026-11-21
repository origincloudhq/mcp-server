//! The server's own credential for the STS: a workload certificate of the
//! zone's certificate authority, which the pod's enrolment client keeps in a
//! directory. The server proves itself to the STS with an assertion (a
//! compact JWS, ES256) signed with that certificate's key and carrying its
//! chain, as the `actor_token` of a token exchange (RFC 8693, section 2.1).
//!
//! The directory holds, as the enrolment client writes them:
//!
//! | File | Holds |
//! |---|---|
//! | `workload.key` | the certificate's key, PKCS#8 PEM |
//! | `workload.crt` | the workload's certificate, PEM |
//! | `chain.crt` | the intermediate that issued it, PEM |
//! | `root.crt` | the region's root, PEM |
//!
//! The files are read for each assertion, so that a renewed certificate is
//! used as soon as it is in place. The key never leaves this process.

use std::fmt;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

/// The RFC 8693 `actor_token_type` of an assertion of a workload.
pub const ASSERTION_TOKEN_TYPE: &str = "urn:origincloud:params:oauth:token-type:workload-assertion";

/// How long an assertion lives, from its `iat`: it is made for one
/// exchange, and the STS takes none that lives longer than 60 seconds.
const ASSERTION_LIFETIME_SECONDS: u64 = 60;

/// How far `iat` is put back, so that an STS whose clock is a little behind
/// doesn't find the assertion issued in its future.
const BACKDATE_SECONDS: u64 = 5;

/// Why no assertion could be made.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    #[error("{file}: {source}")]
    Read {
        file: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{0} holds no certificate or key in PEM")]
    NotPem(&'static str),
    #[error("signing the assertion failed: {0}")]
    Signing(#[from] jsonwebtoken::errors::Error),
}

/// The claims of an assertion: the workload as issuer and subject, for the
/// STS of one zone.
#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
}

/// The server's workload certificate, as a way to make assertions.
#[derive(Clone)]
pub struct Workload {
    dir: PathBuf,
    /// The workload's SPIFFE id, its certificate's identity.
    id: String,
    /// The STS the assertion is for: the issuer of that zone's tokens,
    /// `origincloud:sts:<zone>`.
    audience: String,
}

impl fmt::Debug for Workload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Workload")
            .field("id", &self.id)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl Workload {
    pub fn new(dir: PathBuf, id: String, zone: &str) -> Self {
        Self {
            dir,
            id,
            audience: format!("origincloud:sts:{zone}"),
        }
    }

    /// An assertion made at `now` (seconds since the epoch): issued a few
    /// seconds before, living a minute from then.
    pub async fn assertion(&self, now: u64) -> Result<String, WorkloadError> {
        let key = self.read("workload.key").await?;
        let certificate = first_certificate("workload.crt", &self.read("workload.crt").await?)?;
        let intermediate = first_certificate("chain.crt", &self.read("chain.crt").await?)?;
        let root = first_certificate("root.crt", &self.read("root.crt").await?)?;
        let key = EncodingKey::from_ec_pem(key.as_bytes())
            .map_err(|_| WorkloadError::NotPem("workload.key"))?;
        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![certificate, intermediate, root]);
        let issued = now.saturating_sub(BACKDATE_SECONDS);
        let claims = Claims {
            iss: &self.id,
            sub: &self.id,
            aud: &self.audience,
            iat: issued,
            exp: issued + ASSERTION_LIFETIME_SECONDS,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        Ok(jsonwebtoken::encode(&header, &claims, &key)?)
    }

    async fn read(&self, file: &'static str) -> Result<String, WorkloadError> {
        tokio::fs::read_to_string(self.dir.join(file))
            .await
            .map_err(|source| WorkloadError::Read { file, source })
    }
}

/// The first certificate of a PEM file as `x5c` carries it (RFC 7515,
/// section 4.1.6): its DER in standard base64, which is the PEM body.
fn first_certificate(file: &'static str, pem: &str) -> Result<String, WorkloadError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let body = pem
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(body, _)| body.split_whitespace().collect::<String>())
        .filter(|body| STANDARD.decode(body).is_ok_and(|der| !der.is_empty()))
        .ok_or(WorkloadError::NotPem(file))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_is_its_pem_body_without_the_armor() {
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nAAEC\nAwQ=\n-----END CERTIFICATE-----\n";
        assert_eq!(first_certificate("c", pem).unwrap(), "AAECAwQ=");
    }

    #[test]
    fn something_that_is_no_certificate_is_refused() {
        assert!(first_certificate("c", "").is_err());
        assert!(first_certificate(
            "c",
            "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----"
        )
        .is_err());
        assert!(first_certificate(
            "c",
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"
        )
        .is_err());
    }
}
