use std::net::SocketAddr;

use url::Url;

use crate::ConfigError;
use crate::model::ShadowsocksInboundConfig;
use crate::proxy::{
    shadowsocks_2022_cipher, supported_shadowsocks_cipher, validate_shadowsocks_inbound_key,
};

impl ShadowsocksInboundConfig {
    /// Parses a legacy `ss-config:` URI (`ss://cipher:password@host:port`).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInbound`] when the URI is malformed or incomplete.
    pub fn parse_ss_url(
        value: &str,
        allow_lan: bool,
        bind_address: &str,
    ) -> Result<Self, ConfigError> {
        if value.is_empty() {
            return Err(ConfigError::InvalidInbound(
                "ss-config must not be empty when declared".to_owned(),
            ));
        }
        let value = normalize_ss_config_uri(value, allow_lan);
        let url = Url::parse(&value).map_err(|error| {
            ConfigError::InvalidInbound(format!("invalid ss-config URI: {error}"))
        })?;
        if url.scheme() != "ss" {
            return Err(ConfigError::InvalidInbound(
                "ss-config URI must use the ss scheme".to_owned(),
            ));
        }
        let cipher = percent_decode(url.username());
        if cipher.is_empty() {
            return Err(ConfigError::InvalidInbound(
                "ss-config URI must include a cipher".to_owned(),
            ));
        }
        let password = url
            .password()
            .map(percent_decode)
            .filter(|password| !password.is_empty())
            .ok_or_else(|| {
                ConfigError::InvalidInbound("ss-config URI must include a password".to_owned())
            })?;
        let listen = resolve_ss_listen_host(url.host_str(), url.port(), allow_lan, bind_address)?;
        if !supported_shadowsocks_cipher(&cipher) {
            return Err(ConfigError::InvalidInbound(format!(
                "unsupported shadowsocks inbound cipher: {cipher}"
            )));
        }
        validate_shadowsocks_inbound_key(&cipher, &password)?;
        let udp = !shadowsocks_2022_cipher(&cipher);
        Ok(Self {
            name: "DEFAULT-SHADOWSOCKS".to_owned(),
            cipher,
            password,
            listen,
            udp,
            simple_obfs: None,
        })
    }
}

fn normalize_ss_config_uri(value: &str, allow_lan: bool) -> String {
    let Some(rest) = value.strip_prefix("ss://") else {
        return value.to_owned();
    };
    let Some(at) = rest.rfind('@') else {
        return value.to_owned();
    };
    let host_part = &rest[at + 1..];
    if !host_part.starts_with(':') {
        return value.to_owned();
    }
    let port = &host_part[1..];
    if !port.chars().all(|character| character.is_ascii_digit()) {
        return value.to_owned();
    }
    let host = if allow_lan { "0.0.0.0" } else { "127.0.0.1" };
    format!("ss://{}@{host}:{port}", &rest[..at])
}

fn percent_decode(value: &str) -> String {
    url::form_urlencoded::parse(value.as_bytes())
        .map(|(key, value)| {
            if value.is_empty() {
                key.into_owned()
            } else {
                format!("{key}={value}")
            }
        })
        .collect()
}

pub(crate) fn resolve_ss_listen_host(
    host: Option<&str>,
    port: Option<u16>,
    allow_lan: bool,
    bind_address: &str,
) -> Result<SocketAddr, ConfigError> {
    let port = port.unwrap_or(8388);
    if let Some(host) = host.filter(|value| !value.is_empty()) {
        if host == "0.0.0.0" || host == "::" || host == "[::]" {
            return wildcard_listener_address(port, bind_address);
        }
        let authority = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        return authority.parse().map_err(|error| {
            ConfigError::InvalidInbound(format!("invalid ss-config listen address: {error}"))
        });
    }
    if allow_lan {
        wildcard_listener_address(port, bind_address)
    } else {
        Ok(SocketAddr::from(([127, 0, 0, 1], port)))
    }
}

fn wildcard_listener_address(port: u16, bind_address: &str) -> Result<SocketAddr, ConfigError> {
    use std::net::{IpAddr, Ipv6Addr};

    if bind_address == "*" {
        return Ok(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port));
    }
    bind_address
        .strip_prefix('[')
        .and_then(|address| address.strip_suffix(']'))
        .unwrap_or(bind_address)
        .parse::<IpAddr>()
        .map(|address| SocketAddr::new(address, port))
        .map_err(|_| {
            ConfigError::InvalidInbound(format!(
                "bind-address is not an IP address: {bind_address}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_ss_config_uri() {
        let config = ShadowsocksInboundConfig::parse_ss_url(
            "ss://aes-128-gcm:phase6c-password@127.0.0.1:18388",
            false,
            "*",
        )
        .expect("parse");
        assert_eq!(config.name, "DEFAULT-SHADOWSOCKS");
        assert_eq!(config.cipher, "aes-128-gcm");
        assert_eq!(config.password, "phase6c-password");
        assert_eq!(config.listen, "127.0.0.1:18388".parse().expect("addr"));
        assert!(config.udp);
        assert!(config.simple_obfs.is_none());
    }

    #[test]
    fn parses_hostless_ss_config_port_only() {
        let config = ShadowsocksInboundConfig::parse_ss_url(
            "ss://aes-128-gcm:phase6c-password@:18389",
            false,
            "*",
        )
        .expect("parse");
        assert_eq!(config.listen.port(), 18389);
        assert_eq!(config.listen.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn parses_2022_ss_config_uri_without_udp() {
        let config = ShadowsocksInboundConfig::parse_ss_url(
            "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==@127.0.0.1:18392",
            false,
            "*",
        )
        .expect("parse");
        assert_eq!(config.cipher, "2022-blake3-aes-128-gcm");
        assert_eq!(config.password, "AAECAwQFBgcICQoLDA0ODw==");
        assert!(!config.udp);
    }

    #[test]
    fn rejects_invalid_2022_ss_config_key() {
        let error = ShadowsocksInboundConfig::parse_ss_url(
            "ss://2022-blake3-aes-128-gcm:not-base64@127.0.0.1:18393",
            false,
            "*",
        )
        .expect_err("invalid key");
        assert!(matches!(error, ConfigError::InvalidInbound(_)));
    }
}
