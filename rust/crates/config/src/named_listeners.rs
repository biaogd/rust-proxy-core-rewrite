use serde_yaml_ng::{Mapping, Value};

use crate::ConfigError;
use crate::model::{
    ShadowTlsHandshakeConfig, ShadowTlsUserConfig, ShadowsocksInboundConfig,
    ShadowsocksShadowTlsConfig, ShadowsocksSimpleObfsConfig, TrojanInboundConfig,
    TrojanInboundUser,
};
use crate::proxy::{
    shadowsocks_2022_cipher, shadowsocks_2022_udp_cipher, supported_shadowsocks_cipher,
    validate_shadowsocks_inbound_key,
};
use crate::shadowsocks_inbound::resolve_ss_listen_host;

pub(crate) struct NamedListeners {
    pub shadowsocks: Vec<ShadowsocksInboundConfig>,
    pub trojan: Vec<TrojanInboundConfig>,
}

pub(crate) fn parse_named_listeners(
    listeners: Option<Vec<Mapping>>,
    allow_lan: bool,
    bind_address: &str,
) -> Result<NamedListeners, ConfigError> {
    let Some(listeners) = listeners else {
        return Ok(NamedListeners {
            shadowsocks: Vec::new(),
            trojan: Vec::new(),
        });
    };
    let mut shadowsocks = Vec::new();
    let mut trojan = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for (index, mapping) in listeners.into_iter().enumerate() {
        let listener_type = mapping_string(&mapping, "type").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {index} is missing type"))
        })?;
        match listener_type.as_str() {
            "shadowsocks" => {
                shadowsocks.push(parse_shadowsocks_listener(
                    mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            "trojan" => {
                trojan.push(parse_trojan_listener(
                    mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            other => {
                return Err(ConfigError::InvalidInbound(format!(
                    "listener {index} has unsupported type: {other}"
                )));
            }
        }
    }
    Ok(NamedListeners {
        shadowsocks,
        trojan,
    })
}

fn parse_shadowsocks_listener(
    mapping: Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<ShadowsocksInboundConfig, ConfigError> {
    validate_mapping_keys(
        &mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "cipher",
            "password",
            "udp",
            "simple-obfs",
            "shadow-tls",
        ],
        &format!("listener {index}"),
    )?;
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
        .get(Value::from("port"))
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {name} is missing port")))?;
    let listen = resolve_ss_listen_host(Some(&listen_host), Some(port), allow_lan, bind_address)?;
    let requested_udp = mapping
        .get(Value::from("udp"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if shadowsocks_2022_cipher(&cipher) && !shadowsocks_2022_udp_cipher(&cipher) {
        if requested_udp
            && mapping
                .get(Value::from("udp"))
                .and_then(Value::as_bool)
                .is_some_and(|enabled| enabled)
        {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} cannot enable UDP for Shadowsocks 2022 cipher {cipher}"
            )));
        }
    }
    let udp = if shadowsocks_2022_cipher(&cipher) {
        requested_udp && shadowsocks_2022_udp_cipher(&cipher)
    } else {
        requested_udp
    };
    let simple_obfs = parse_simple_obfs(&mapping, &name)?;
    let shadow_tls = parse_shadow_tls(&mapping, &name)?;
    if simple_obfs.is_some() && shadow_tls.is_some() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} cannot enable both simple-obfs and shadow-tls"
        )));
    }
    Ok(ShadowsocksInboundConfig {
        name,
        cipher,
        password,
        listen,
        udp,
        simple_obfs,
        shadow_tls,
    })
}

fn parse_trojan_listener(
    mapping: Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<TrojanInboundConfig, ConfigError> {
    validate_mapping_keys(
        &mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "users",
            "certificate",
            "private-key",
        ],
        &format!("listener {index}"),
    )?;
    let name = mapping_string(&mapping, "name").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {index} is missing name"))
    })?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let listen_host = mapping_string(&mapping, "listen").unwrap_or_else(|| {
        if allow_lan {
            "0.0.0.0".to_owned()
        } else {
            "127.0.0.1".to_owned()
        }
    });
    let port = mapping
        .get(Value::from("port"))
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {name} is missing port")))?;
    let listen = resolve_ss_listen_host(Some(&listen_host), Some(port), allow_lan, bind_address)?;
    let certificate = mapping_string(&mapping, "certificate").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing certificate"))
    })?;
    let private_key = mapping_string(&mapping, "private-key").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing private-key"))
    })?;
    if certificate.trim().is_empty() || private_key.trim().is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires non-empty certificate and private-key"
        )));
    }
    let users = parse_trojan_users(&mapping, &name)?;
    if users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires at least one user password"
        )));
    }
    Ok(TrojanInboundConfig {
        name,
        listen,
        users,
        certificate,
        private_key,
    })
}

fn parse_trojan_users(
    mapping: &Mapping,
    name: &str,
) -> Result<Vec<TrojanInboundUser>, ConfigError> {
    let Some(value) = mapping.get(Value::from("users")) else {
        return Ok(Vec::new());
    };
    let Some(users) = value.as_sequence() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid users configuration"
        )));
    };
    let mut parsed = Vec::with_capacity(users.len());
    for (index, user) in users.iter().enumerate() {
        let Some(user) = user.as_mapping() else {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} user {index} is invalid"
            )));
        };
        validate_mapping_keys(
            user,
            &["username", "password"],
            &format!("listener {name} user {index}"),
        )?;
        let password = mapping_string(user, "password").ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} user {index} is missing password"
            ))
        })?;
        if password.is_empty() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} user {index} password must not be empty"
            )));
        }
        let username = mapping_string(user, "username").unwrap_or_default();
        parsed.push(TrojanInboundUser { username, password });
    }
    Ok(parsed)
}

fn parse_simple_obfs(
    mapping: &Mapping,
    name: &str,
) -> Result<Option<ShadowsocksSimpleObfsConfig>, ConfigError> {
    let Some(value) = mapping.get(Value::from("simple-obfs")) else {
        return Ok(None);
    };
    let Some(mapping) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid simple-obfs configuration"
        )));
    };
    validate_mapping_keys(
        mapping,
        &["enable", "mode"],
        &format!("listener {name} simple-obfs"),
    )?;
    let enabled = mapping
        .get(Value::from("enable"))
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
    let Some(value) = mapping.get(Value::from("shadow-tls")) else {
        return Ok(None);
    };
    let Some(mapping) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid shadow-tls configuration"
        )));
    };
    validate_mapping_keys(
        mapping,
        &[
            "enable",
            "version",
            "password",
            "users",
            "handshake",
            "strict-mode",
        ],
        &format!("listener {name} shadow-tls"),
    )?;
    let enabled = mapping
        .get(Value::from("enable"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !enabled {
        return Ok(None);
    }
    let version = mapping
        .get(Value::from("version"))
        .and_then(Value::as_u64)
        .map(|version| {
            u8::try_from(version).map_err(|_| {
                ConfigError::InvalidInbound(format!(
                    "listener {name} has invalid shadow-tls version"
                ))
            })
        })
        .transpose()?
        .unwrap_or(3);
    if !(1..=3).contains(&version) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has unsupported shadow-tls version: {version}"
        )));
    }
    if version != 3 {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} shadow-tls version {version} is not supported; only v3 is implemented"
        )));
    }
    let password = mapping_string(mapping, "password");
    let users = parse_shadow_tls_users(mapping, name)?;
    if users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} shadow-tls v3 requires at least one user"
        )));
    }
    let handshake = mapping
        .get(Value::from("handshake"))
        .and_then(Value::as_mapping)
        .ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} shadow-tls is missing handshake configuration"
            ))
        })?;
    validate_mapping_keys(
        handshake,
        &["dest", "proxy"],
        &format!("listener {name} shadow-tls handshake"),
    )?;
    let dest = mapping_string(handshake, "dest").ok_or_else(|| {
        ConfigError::InvalidInbound(format!(
            "listener {name} shadow-tls handshake is missing dest"
        ))
    })?;
    let proxy = mapping_string(handshake, "proxy");
    let strict_mode = mapping
        .get(Value::from("strict-mode"))
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
    let Some(value) = mapping.get(Value::from("users")) else {
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
        validate_mapping_keys(
            mapping,
            &["name", "password"],
            &format!("listener {name} shadow-tls user {index}"),
        )?;
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
        .get(Value::from(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn validate_mapping_keys(
    mapping: &Mapping,
    allowed: &[&str],
    context: &str,
) -> Result<(), ConfigError> {
    for key in mapping.keys() {
        let Some(key) = key.as_str() else {
            return Err(ConfigError::InvalidInbound(format!(
                "{context} contains a non-string configuration key"
            )));
        };
        if !allowed.contains(&key) {
            return Err(ConfigError::InvalidInbound(format!(
                "{context} has unsupported field: {key}"
            )));
        }
    }
    Ok(())
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

pub(crate) fn validate_trojan_listener_ports(
    listeners: &[TrojanInboundConfig],
) -> Result<(), ConfigError> {
    let mut ports = std::collections::BTreeSet::new();
    for listener in listeners {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "trojan listener address is duplicated: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_named_listener_ports(
    shadowsocks: &[ShadowsocksInboundConfig],
    trojan: &[TrojanInboundConfig],
) -> Result<(), ConfigError> {
    validate_shadowsocks_listener_ports(shadowsocks)?;
    validate_trojan_listener_ports(trojan)?;
    let mut ports = std::collections::BTreeSet::new();
    for listener in shadowsocks {
        ports.insert((listener.listen.ip(), listener.listen.port()));
    }
    for listener in trojan {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener address is duplicated across inbound types: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}
