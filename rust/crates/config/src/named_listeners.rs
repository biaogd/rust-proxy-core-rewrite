use serde_yaml_ng::{Mapping, Value};

use crate::ConfigError;
use crate::model::{
    ShadowTlsHandshakeConfig, ShadowTlsUserConfig, ShadowsocksInboundConfig,
    ShadowsocksShadowTlsConfig, ShadowsocksSimpleObfsConfig,
};
use crate::proxy::{
    shadowsocks_2022_cipher, supported_shadowsocks_cipher, validate_shadowsocks_inbound_key,
};
use crate::shadowsocks_inbound::resolve_ss_listen_host;

pub(crate) fn parse_shadowsocks_listeners(
    listeners: Option<Vec<Mapping>>,
    allow_lan: bool,
    bind_address: &str,
) -> Result<Vec<ShadowsocksInboundConfig>, ConfigError> {
    let Some(listeners) = listeners else {
        return Ok(Vec::new());
    };
    let mut parsed = Vec::with_capacity(listeners.len());
    let mut names = std::collections::BTreeSet::new();
    for (index, mapping) in listeners.into_iter().enumerate() {
        let listener_type = mapping_string(&mapping, "type").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {index} is missing type"))
        })?;
        if listener_type != "shadowsocks" {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {index} has unsupported type: {listener_type}"
            )));
        }
        let name = mapping_string(&mapping, "name").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {index} is missing name"))
        })?;
        if !names.insert(name.clone()) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener name is duplicated: {name}"
            )));
        }
        let cipher = mapping_string(&mapping, "cipher").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {name} is missing cipher"))
        })?;
        let password = mapping_string(&mapping, "password").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {name} is missing password"))
        })?;
        if !supported_shadowsocks_cipher(&cipher) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} has unsupported cipher: {cipher}"
            )));
        }
        validate_shadowsocks_inbound_key(&cipher, &password)?;
        let listen_host = mapping_string(&mapping, "listen").unwrap_or_else(|| {
            if allow_lan {
                "0.0.0.0".to_owned()
            } else {
                "127.0.0.1".to_owned()
            }
        });
        let port = mapping
            .get(&Value::from("port"))
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| {
                ConfigError::InvalidInbound(format!("listener {name} is missing port"))
            })?;
        let listen = resolve_ss_listen_host(Some(&listen_host), Some(port), allow_lan, bind_address)?;
        if shadowsocks_2022_cipher(&cipher)
            && mapping
                .get(&Value::from("udp"))
                .and_then(Value::as_bool)
                == Some(true)
        {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} cannot enable UDP for Shadowsocks 2022"
            )));
        }
        let udp = mapping
            .get(&Value::from("udp"))
            .and_then(Value::as_bool)
            .unwrap_or(true)
            && !shadowsocks_2022_cipher(&cipher);
        let simple_obfs = parse_simple_obfs(&mapping, &name)?;
        let shadow_tls = parse_shadow_tls(&mapping, &name)?;
        if simple_obfs.is_some() && shadow_tls.is_some() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} cannot enable both simple-obfs and shadow-tls"
            )));
        }
        parsed.push(ShadowsocksInboundConfig {
            name,
            cipher,
            password,
            listen,
            udp,
            simple_obfs,
            shadow_tls,
        });
    }
    Ok(parsed)
}

fn parse_simple_obfs(
    mapping: &Mapping,
    name: &str,
) -> Result<Option<ShadowsocksSimpleObfsConfig>, ConfigError> {
    let Some(value) = mapping.get(&Value::from("simple-obfs")) else {
        return Ok(None);
    };
    let Some(mapping) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid simple-obfs configuration"
        )));
    };
    let enabled = mapping
        .get(&Value::from("enable"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !enabled {
        return Ok(None);
    }
    let mode = mapping_string(mapping, "mode").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} simple-obfs is missing mode"))
    })?;
    if mode != "http" && mode != "tls" {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has unsupported simple-obfs mode: {mode}"
        )));
    }
    Ok(Some(ShadowsocksSimpleObfsConfig { mode }))
}

fn parse_shadow_tls(
    mapping: &Mapping,
    name: &str,
) -> Result<Option<ShadowsocksShadowTlsConfig>, ConfigError> {
    let Some(value) = mapping.get(&Value::from("shadow-tls")) else {
        return Ok(None);
    };
    let Some(mapping) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid shadow-tls configuration"
        )));
    };
    let enabled = mapping
        .get(&Value::from("enable"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !enabled {
        return Ok(None);
    }
    let version = mapping
        .get(&Value::from("version"))
        .and_then(Value::as_u64)
        .map(|version| u8::try_from(version).map_err(|_| {
            ConfigError::InvalidInbound(format!("listener {name} has invalid shadow-tls version"))
        }))
        .transpose()?
        .unwrap_or(3);
    if !(1..=3).contains(&version) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has unsupported shadow-tls version: {version}"
        )));
    }
    let password = mapping_string(mapping, "password");
    let users = parse_shadow_tls_users(mapping, name)?;
    if version == 3 && users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} shadow-tls v3 requires at least one user"
        )));
    }
    if version == 2 && password.is_none() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} shadow-tls v2 requires password"
        )));
    }
    let handshake = mapping
        .get(&Value::from("handshake"))
        .and_then(Value::as_mapping)
        .ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} shadow-tls is missing handshake configuration"
            ))
        })?;
    let dest = mapping_string(handshake, "dest").ok_or_else(|| {
        ConfigError::InvalidInbound(format!(
            "listener {name} shadow-tls handshake is missing dest"
        ))
    })?;
    let proxy = mapping_string(handshake, "proxy");
    let strict_mode = mapping
        .get(&Value::from("strict-mode"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(Some(ShadowsocksShadowTlsConfig {
        version,
        password,
        users,
        handshake: ShadowTlsHandshakeConfig { dest, proxy },
        strict_mode,
    }))
}

fn parse_shadow_tls_users(
    mapping: &Mapping,
    name: &str,
) -> Result<Vec<ShadowTlsUserConfig>, ConfigError> {
    let Some(value) = mapping.get(&Value::from("users")) else {
        return Ok(Vec::new());
    };
    let Some(sequence) = value.as_sequence() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid shadow-tls users"
        )));
    };
    let mut users = Vec::with_capacity(sequence.len());
    for (index, entry) in sequence.iter().enumerate() {
        let Some(mapping) = entry.as_mapping() else {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} shadow-tls user {index} is invalid"
            )));
        };
        let user_name = mapping_string(mapping, "name").ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} shadow-tls user {index} is missing name"
            ))
        })?;
        let user_password = mapping_string(mapping, "password").ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} shadow-tls user {index} is missing password"
            ))
        })?;
        users.push(ShadowTlsUserConfig {
            name: user_name,
            password: user_password,
        });
    }
    Ok(users)
}

fn mapping_string(mapping: &Mapping, key: &str) -> Option<String> {
    mapping
        .get(&Value::from(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

pub(crate) fn validate_shadowsocks_listener_ports(
    listeners: &[ShadowsocksInboundConfig],
) -> Result<(), ConfigError> {
    let mut ports = std::collections::BTreeSet::new();
    for listener in listeners {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "shadowsocks listener address is duplicated: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}
