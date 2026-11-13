//! A connection's options, from the query of the URL a client connects to,
//! such as `https://mcp.origincloudapis.eu/?toolsets=pvs,compute&read_only=true`:
//! many MCP clients take nothing but a URL. Without them, a connection gets
//! what `origin mcp serve` gives: every toolset, read-write.

use origincloud_mcp::{toolsets, Defaults, Options};

/// The parameters there are.
const TOOLSETS: &str = "toolsets";
const READ_ONLY: &str = "read_only";

/// A query that names no options the server has.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OptionsError {
    #[error("there is no toolset {name:?}; the toolsets are {}", toolsets().collect::<Vec<_>>().join(", "))]
    UnknownToolset { name: String },
    #[error("read_only is true or false, got {0:?}")]
    ReadOnly(String),
    #[error("there is no parameter {0:?}; the parameters are toolsets and read_only")]
    UnknownParameter(String),
    #[error("toolsets names no toolset; leave it out for every toolset")]
    NoToolset,
}

/// The options of a connection to the URL with `query`, and `defaults` for
/// `current_context`.
pub fn parse(query: Option<&str>, defaults: Defaults) -> Result<Options, OptionsError> {
    let mut selected: Option<Vec<String>> = None;
    let mut read_only = false;
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
            other => return Err(OptionsError::UnknownParameter(other.to_owned())),
        }
    }
    if selected.as_ref().is_some_and(Vec::is_empty) {
        return Err(OptionsError::NoToolset);
    }
    Ok(Options {
        toolsets: selected,
        read_only,
        defaults,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(query: &str) -> Result<Options, OptionsError> {
        super::parse(Some(query), Defaults::default())
    }

    #[test]
    fn without_a_query_every_toolset_is_read_write() {
        let o = super::parse(None, Defaults::default()).unwrap();
        assert_eq!(o.toolsets, None);
        assert!(!o.read_only);
        let o = parse("").unwrap();
        assert_eq!(o.toolsets, None);
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
