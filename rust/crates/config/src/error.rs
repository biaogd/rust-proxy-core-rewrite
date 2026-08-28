use std::path::PathBuf;

use rewrite_rules::RuleError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration YAML error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("cannot read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid mode")]
    InvalidMode,
    #[error("invalid log-level")]
    InvalidLogLevel,
    #[error("rule error: {0}")]
    Rule(#[from] RuleError),
    #[error("unsupported configuration key for the current rewrite phase: {0}")]
    UnsupportedKey(String),
    #[error("unsupported Phase 2 proxy specification: {0}")]
    UnsupportedProxy(String),
    #[error("invalid mixed-port for listener: {0}")]
    InvalidRuntimePort(i64),
    #[error("invalid external-controller address: {0}")]
    InvalidControllerAddress(String),
    #[error("path is not a absolute path")]
    InvalidConfigPath,
    #[error(
        "path is not subpath of home directory or SAFE_PATHS: {path} \n allowed paths: [{home}]"
    )]
    UnsafeConfigPath { path: PathBuf, home: PathBuf },
    #[error("invalid Phase 4A DNS configuration: {0}")]
    InvalidDns(String),
    #[error("invalid Phase 4B hosts configuration: {0}")]
    InvalidHosts(String),
    #[error("invalid local inbound configuration: {0}")]
    InvalidInbound(String),
    #[error("configuration is parsed but not executable in the current rewrite runtime: {0}")]
    UnsupportedRuntime(String),
}
