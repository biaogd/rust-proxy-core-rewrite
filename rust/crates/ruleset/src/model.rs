use thiserror::Error;

pub(crate) const MRS_MAGIC: &[u8; 4] = b"MRS\x01";
pub(crate) const DOMAIN_BEHAVIOR: u8 = 0;
pub(crate) const IPCIDR_BEHAVIOR: u8 = 1;
pub(crate) const IPCIDR_SET_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum RulesetError {
    #[error("MRS I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid MRS: {0}")]
    Invalid(&'static str),
    #[error("invalid YAML rule set: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("file must have a `payload` field")]
    MissingPayload,
    #[error("empty rule")]
    Empty,
}

/// Source syntax accepted by the MRS encoders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceFormat {
    Text,
    Yaml,
}
