//! A connection's options, from the query of the URL a client connects to,
//! such as `https://mcp.origincloudapis.eu/?toolsets=pvs,compute&read_only=true`:
//! many MCP clients take nothing but a URL. Without them, a connection gets
//! what `origin mcp serve` gives: every toolset, read-write, as the person
//! who signed in.
//!
//! `service_account` names a service account, by its full name, that the
//! connection acts as instead: every token for the API is that account's,
//! which the zone's STS issues only to a person allowed to impersonate it
//! (`roles/iam.service-account-token-creator`). The account's roles, not
//! the person's, decide what the API allows.

use std::sync::Arc;

use origincloud_core::names::{FullName, Principal};
use origincloud_mcp::{toolsets, Defaults, Options};

/// The parameters there are.
const TOOLSETS: &str = "toolsets";
const READ_ONLY: &str = "read_only";
const SERVICE_ACCOUNT: &str = "service_account";

/// What a connection's URL asks for.
#[derive(Debug, Clone)]
pub struct Connection {
    /// The tools it exposes.
    pub options: Options,
    /// The service account it acts as, by its full name, if any.
    pub service_account: Option<Arc<str>>,
}

/// A query that names no options the server has.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OptionsError {
    #[error("there is no toolset {name:?}; the toolsets are {}", toolsets().collect::<Vec<_>>().join(", "))]
    UnknownToolset { name: String },
    #[error("read_only is true or false, got {0:?}")]
    ReadOnly(String),
    #[error(
        "there is no parameter {0:?}; the parameters are toolsets, read_only and service_account"
    )]
    UnknownParameter(String),
    #[error("toolsets names no toolset; leave it out for every toolset")]
    NoToolset,
    #[error("service_account is a service account's full name, //iam.origincloudapis.eu/organizations/{{organization}}/serviceAccounts/{{service_account}}; got {0:?}")]
    NotAServiceAccount(String),
    #[error("service_account names one service account; got it more than once")]
    ServiceAccountRepeated,
}

/// The connection to the URL with `query`, and `defaults` for
/// `current_context`.
pub fn parse(query: Option<&str>, defaults: Defaults) -> Result<Connection, OptionsError> {
    let mut selected: Option<Vec<String>> = None;
    let mut read_only = false;
    let mut service_account: Option<Arc<str>> = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            // Comma-separated, or the parameter repeated.
            TOOLSETS => {
                let names = selected.get_or_insert_with(Vec::new);
                for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                    if !toolsets().any(|t| t == name) {
                        return Err(OptionsError::UnknownToolset {
                            name: name.to_owned(),
                        });
                    }
                    if !names.iter().any(|n| n == name) {
                        names.push(name.to_owned());
                    }
                }
            }
            READ_ONLY => {
                read_only = match value.as_ref() {
                    "true" | "1" => true,
                    "false" | "0" => false,
                    other => return Err(OptionsError::ReadOnly(other.to_owned())),
                }
            }
            SERVICE_ACCOUNT => {
                if service_account.is_some() {
                    return Err(OptionsError::ServiceAccountRepeated);
                }
                service_account = Some(service_account_name(&value)?);
            }
            other => return Err(OptionsError::UnknownParameter(other.to_owned())),
        }
    }
    if selected.as_ref().is_some_and(Vec::is_empty) {
        return Err(OptionsError::NoToolset);
    }
    Ok(Connection {
        options: Options {
            toolsets: selected,
            read_only,
            defaults,
        },
        service_account,
    })
}

/// `value` if it is a service account's full name, in its one spelling:
/// anything else is refused here, before the STS is asked.
fn service_account_name(value: &str) -> Result<Arc<str>, OptionsError> {
    let refused = || OptionsError::NotAServiceAccount(value.to_owned());
    let name: FullName = value.parse().map_err(|_| refused())?;
    match name.principal() {
        Some(Principal::ServiceAccount {
            organization,
            service_account,
        }) if !organization.is_empty() && !service_account.is_empty() => {
            Ok(Arc::from(name.as_str()))
        }
        _ => Err(refused()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "//iam.origincloudapis.eu/organizations/o-1/serviceAccounts/sa-1";

    fn parse(query: &str) -> Result<Options, OptionsError> {
        connect(query).map(|c| c.options)
    }

    fn connect(query: &str) -> Result<Connection, OptionsError> {
        super::parse(Some(query), Defaults::default())
    }

    #[test]
    fn without_a_query_every_toolset_is_read_write_as_the_caller() {
        let c = super::parse(None, Defaults::default()).unwrap();
        assert_eq!(c.options.toolsets, None);
        assert!(!c.options.read_only);
        assert_eq!(c.service_account, None);
        let c = connect("").unwrap();
        assert_eq!(c.options.toolsets, None);
        assert_eq!(c.service_account, None);
    }

    #[test]
    fn a_service_account_is_named_by_its_full_name() {
        let encoded: String = url::form_urlencoded::byte_serialize(ACCOUNT.as_bytes()).collect();
        for query in [
            format!("service_account={ACCOUNT}"),
            format!("service_account={encoded}&read_only=true"),
        ] {
            let c = connect(&query).unwrap();
            assert_eq!(c.service_account.as_deref(), Some(ACCOUNT), "{query}");
        }
        assert!(
            connect(&format!("service_account={encoded}&read_only=true"))
                .unwrap()
                .options
                .read_only
        );
    }

    #[test]
    fn anything_but_a_service_account_s_full_name_is_refused() {
        for value in [
            "",
            "sa-1",
            "organizations/o-1/serviceAccounts/sa-1",
            "//iam.origincloudapis.eu/users/u-1",
            "//iam.origincloudapis.eu/serviceAgents/pvs",
            "//iam.origincloudapis.eu/organizations/o-1/serviceAccounts/sa-1/keys/k",
            "//iam.origincloudapis.eu/organizations/o-1/serviceAccounts/",
            "//iam.origincloudapis.eu/organizations//serviceAccounts/sa-1",
            "//pvs.origincloudapis.eu/organizations/o-1/serviceAccounts/sa-1",
            "https://iam.origincloudapis.eu/organizations/o-1/serviceAccounts/sa-1",
            "//IAM.origincloudapis.eu/organizations/o-1/serviceAccounts/sa-1",
            "//iam.origincloudapis.eu/organizations/o-1/serviceAccounts/sa-1/",
        ] {
            let encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
            assert_eq!(
                connect(&format!("service_account={encoded}")).unwrap_err(),
                OptionsError::NotAServiceAccount(value.to_owned()),
                "{value:?}"
            );
        }
        assert_eq!(
            connect(&format!(
                "service_account={ACCOUNT}&service_account={ACCOUNT}"
            ))
            .unwrap_err(),
            OptionsError::ServiceAccountRepeated
        );
    }

    #[test]
    fn toolsets_are_comma_separated_or_repeated() {
        let o = parse("toolsets=pvs,compute&toolsets=location&read_only=true").unwrap();
        assert_eq!(o.toolsets.unwrap(), ["pvs", "compute", "location"]);
        assert!(o.read_only);
        let o = parse("toolsets=pvs%2Ccompute&read_only=0").unwrap();
        assert_eq!(o.toolsets.unwrap(), ["pvs", "compute"]);
        assert!(!o.read_only);
    }

    #[test]
    fn a_misspelt_option_is_refused_by_name() {
        assert_eq!(
            parse("toolsets=pvss").unwrap_err(),
            OptionsError::UnknownToolset {
                name: "pvss".to_owned()
            }
        );
        assert!(parse("toolsets=pvss")
            .unwrap_err()
            .to_string()
            .contains("pvs"));
        assert_eq!(
            parse("readonly=true").unwrap_err(),
            OptionsError::UnknownParameter("readonly".to_owned())
        );
        assert_eq!(
            parse("read_only=yes").unwrap_err(),
            OptionsError::ReadOnly("yes".to_owned())
        );
        assert_eq!(parse("toolsets=").unwrap_err(), OptionsError::NoToolset);
    }
}
