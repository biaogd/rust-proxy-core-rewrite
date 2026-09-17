use serde_yaml_ng::{Mapping, Value};

use crate::ConfigError;
use crate::model::{
    AnyTlsInboundConfig, AnyTlsInboundUser, Hysteria2InboundConfig, Hysteria2InboundUser,
    RealityInboundConfig, ShadowTlsHandshakeConfig, ShadowTlsUserConfig, ShadowsocksInboundConfig,
    ShadowsocksShadowTlsConfig, ShadowsocksSimpleObfsConfig, TrojanInboundConfig, TrojanInboundUser,
    TuicInboundConfig, TuicInboundUser, VlessFlow, VlessInboundConfig, VlessInboundUser,
    VmessInboundConfig, VmessInboundUser,
};
use crate::proxy::{
    shadowsocks_2022_cipher, shadowsocks_2022_udp_cipher, supported_shadowsocks_cipher,
    validate_shadowsocks_inbound_key,
};
use crate::shadowsocks_inbound::resolve_ss_listen_host;

pub(crate) struct NamedListeners {
    pub shadowsocks: Vec<ShadowsocksInboundConfig>,
    pub trojan: Vec<TrojanInboundConfig>,
    pub vless: Vec<VlessInboundConfig>,
    pub vmess: Vec<VmessInboundConfig>,
    pub hysteria2: Vec<Hysteria2InboundConfig>,
    pub tuic: Vec<TuicInboundConfig>,
    pub anytls: Vec<AnyTlsInboundConfig>,
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
            vless: Vec::new(),
            vmess: Vec::new(),
            hysteria2: Vec::new(),
            tuic: Vec::new(),
            anytls: Vec::new(),
        });
    };
    let mut shadowsocks = Vec::new();
    let mut trojan = Vec::new();
    let mut vless = Vec::new();
    let mut vmess = Vec::new();
    let mut hysteria2 = Vec::new();
    let mut tuic = Vec::new();
    let mut anytls = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for (index, mapping) in listeners.into_iter().enumerate() {
        let listener_type = mapping_string(&mapping, "type").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {index} is missing type"))
        })?;
        match listener_type.as_str() {
            "shadowsocks" => {
                shadowsocks.push(parse_shadowsocks_listener(
                    &mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            "trojan" => {
                trojan.push(parse_trojan_listener(
                    &mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            "vless" => {
                vless.push(parse_vless_listener(
                    &mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            "vmess" => {
                vmess.push(parse_vmess_listener(
                    &mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            "hysteria2" => {
                hysteria2.push(parse_hysteria2_listener(
                    &mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            "tuic" => {
                tuic.push(parse_tuic_listener(
                    &mapping,
                    index,
                    allow_lan,
                    bind_address,
                    &mut names,
                )?);
            }
            "anytls" => {
                anytls.push(parse_anytls_listener(
                    &mapping,
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
        vless,
        vmess,
        hysteria2,
        tuic,
        anytls,
    })
}

fn parse_shadowsocks_listener(
    mapping: &Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<ShadowsocksInboundConfig, ConfigError> {
    validate_mapping_keys(
        mapping,
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
    let name = mapping_string(mapping, "name")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {index} is missing name")))?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let cipher = mapping_string(mapping, "cipher")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {name} is missing cipher")))?;
    let password = mapping_string(mapping, "password").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing password"))
    })?;
    if !supported_shadowsocks_cipher(&cipher) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has unsupported cipher: {cipher}"
        )));
    }
    validate_shadowsocks_inbound_key(&cipher, &password)?;
    let listen_host = mapping_string(mapping, "listen").unwrap_or_else(|| {
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
    if shadowsocks_2022_cipher(&cipher)
        && !shadowsocks_2022_udp_cipher(&cipher)
        && mapping
            .get(Value::from("udp"))
            .and_then(Value::as_bool)
            .is_some_and(|enabled| enabled)
    {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} cannot enable UDP for Shadowsocks 2022 cipher {cipher}"
        )));
    }
    let udp = if shadowsocks_2022_cipher(&cipher) {
        requested_udp && shadowsocks_2022_udp_cipher(&cipher)
    } else {
        requested_udp
    };
    let simple_obfs = parse_simple_obfs(mapping, &name)?;
    let shadow_tls = parse_shadow_tls(mapping, &name)?;
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
    mapping: &Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<TrojanInboundConfig, ConfigError> {
    validate_mapping_keys(
        mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "users",
            "certificate",
            "private-key",
            "reality-config",
            "ws-path",
            "grpc-service-name",
        ],
        &format!("listener {index}"),
    )?;
    let name = mapping_string(mapping, "name")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {index} is missing name")))?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let listen_host = mapping_string(mapping, "listen").unwrap_or_else(|| {
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
    let certificate = mapping_string(mapping, "certificate").and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let private_key = mapping_string(mapping, "private-key").and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let reality = parse_reality_config(mapping, &name)?;
    match (
        certificate.is_some() && private_key.is_some(),
        reality.is_some(),
    ) {
        (true, true) => {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} cannot combine certificate/private-key with reality-config"
            )));
        }
        (false, false) => {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} requires certificate and private-key, or reality-config"
            )));
        }
        _ => {}
    }
    if certificate.is_some() ^ private_key.is_some() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires both certificate and private-key together"
        )));
    }
    let ws_path = mapping_string(mapping, "ws-path").and_then(|path| {
        let trimmed = path.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let grpc_service_name = mapping_string(mapping, "grpc-service-name").and_then(|name| {
        let trimmed = name.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    if ws_path.is_some() && grpc_service_name.is_some() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} cannot combine ws-path and grpc-service-name until shared HTTP mux"
        )));
    }
    let users = parse_trojan_users(mapping, &name)?;
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
        reality,
        ws_path,
        grpc_service_name,
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
            ConfigError::InvalidInbound(format!("listener {name} user {index} is missing password"))
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

fn parse_vless_listener(
    mapping: &Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<VlessInboundConfig, ConfigError> {
    validate_mapping_keys(
        mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "users",
            "certificate",
            "private-key",
            "reality-config",
            "ws-path",
            "grpc-service-name",
        ],
        &format!("listener {index}"),
    )?;
    let name = mapping_string(mapping, "name")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {index} is missing name")))?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let listen_host = mapping_string(mapping, "listen").unwrap_or_else(|| {
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
    let certificate = mapping_string(mapping, "certificate").and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let private_key = mapping_string(mapping, "private-key").and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let reality = parse_reality_config(mapping, &name)?;
    match (
        certificate.is_some() && private_key.is_some(),
        reality.is_some(),
    ) {
        (true, true) => {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} cannot combine certificate/private-key with reality-config"
            )));
        }
        (false, false) => {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} requires certificate and private-key, or reality-config"
            )));
        }
        _ => {}
    }
    if certificate.is_some() ^ private_key.is_some() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires both certificate and private-key together"
        )));
    }
    let ws_path = mapping_string(mapping, "ws-path").and_then(|path| {
        let trimmed = path.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let grpc_service_name = mapping_string(mapping, "grpc-service-name").and_then(|name| {
        let trimmed = name.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    if ws_path.is_some() && grpc_service_name.is_some() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} cannot combine ws-path and grpc-service-name until shared HTTP mux"
        )));
    }
    let users = parse_vless_users(mapping, &name)?;
    if users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires at least one user uuid"
        )));
    }
    if reality.is_some()
        && users
            .iter()
            .any(|user| user.flow == Some(VlessFlow::XtlsRprxVision))
    {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} does not support xtls-rprx-vision with reality-config yet"
        )));
    }
    Ok(VlessInboundConfig {
        name,
        listen,
        users,
        certificate,
        private_key,
        reality,
        ws_path,
        grpc_service_name,
    })
}

fn parse_reality_config(
    mapping: &Mapping,
    name: &str,
) -> Result<Option<RealityInboundConfig>, ConfigError> {
    let Some(value) = mapping.get(Value::from("reality-config")) else {
        return Ok(None);
    };
    let Some(reality) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid reality-config"
        )));
    };
    validate_mapping_keys(
        reality,
        &[
            "dest",
            "private-key",
            "short-id",
            "server-names",
            "max-time-difference",
            "proxy",
        ],
        &format!("listener {name} reality-config"),
    )?;
    let dest = mapping_string(reality, "dest")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {name} reality-config is missing dest"))
        })?;
    let private_key_text = mapping_string(reality, "private-key")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} reality-config is missing private-key"
            ))
        })?;
    let private_key = decode_reality_private_key(&private_key_text, name)?;
    let short_ids = parse_reality_short_ids(reality, name)?;
    if short_ids.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} reality-config requires at least one short-id"
        )));
    }
    let server_names = parse_reality_server_names(reality, name)?;
    if server_names.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} reality-config requires at least one server-names entry"
        )));
    }
    let max_time_difference = reality
        .get(Value::from("max-time-difference"))
        .and_then(Value::as_u64)
        .map(std::time::Duration::from_micros);
    let proxy = mapping_string(reality, "proxy").and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    Ok(Some(RealityInboundConfig {
        dest,
        private_key,
        short_ids,
        server_names,
        max_time_difference,
        proxy,
    }))
}

fn decode_reality_private_key(text: &str, name: &str) -> Result<[u8; 32], ConfigError> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(text))
        .map_err(|_| {
            ConfigError::InvalidInbound(format!(
                "listener {name} reality-config private-key is not valid URL-safe base64"
            ))
        })?;
    decoded.try_into().map_err(|_| {
        ConfigError::InvalidInbound(format!(
            "listener {name} reality-config private-key must be 32 bytes"
        ))
    })
}

fn parse_reality_short_ids(mapping: &Mapping, name: &str) -> Result<Vec<[u8; 8]>, ConfigError> {
    let Some(value) = mapping.get(Value::from("short-id")) else {
        return Ok(Vec::new());
    };
    let texts = match value {
        Value::String(text) => vec![text.clone()],
        Value::Sequence(items) => {
            let mut texts = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let Some(text) = item.as_str() else {
                    return Err(ConfigError::InvalidInbound(format!(
                        "listener {name} reality-config short-id {index} is invalid"
                    )));
                };
                texts.push(text.to_owned());
            }
            texts
        }
        _ => {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} reality-config short-id is invalid"
            )));
        }
    };
    let mut short_ids = Vec::with_capacity(texts.len());
    for (index, text) in texts.into_iter().enumerate() {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            short_ids.push([0_u8; 8]);
            continue;
        }
        let decoded = hex::decode(trimmed).map_err(|_| {
            ConfigError::InvalidInbound(format!(
                "listener {name} reality-config short-id {index} is not valid hex"
            ))
        })?;
        if decoded.len() > 8 {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} reality-config short-id {index} must be at most 8 bytes"
            )));
        }
        let mut short_id = [0_u8; 8];
        short_id[..decoded.len()].copy_from_slice(&decoded);
        short_ids.push(short_id);
    }
    Ok(short_ids)
}

fn parse_reality_server_names(mapping: &Mapping, name: &str) -> Result<Vec<String>, ConfigError> {
    let Some(value) = mapping.get(Value::from("server-names")) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_sequence() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} reality-config server-names is invalid"
        )));
    };
    let mut names = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(text) = item.as_str() else {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} reality-config server-names[{index}] is invalid"
            )));
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} reality-config server-names[{index}] must not be empty"
            )));
        }
        names.push(trimmed.to_owned());
    }
    Ok(names)
}

fn parse_vless_users(mapping: &Mapping, name: &str) -> Result<Vec<VlessInboundUser>, ConfigError> {
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
            &["username", "uuid", "flow"],
            &format!("listener {name} user {index}"),
        )?;
        let uuid = mapping_string(user, "uuid").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {name} user {index} is missing uuid"))
        })?;
        if uuid.trim().is_empty() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} user {index} uuid must not be empty"
            )));
        }
        let username = mapping_string(user, "username").unwrap_or_else(|| uuid.clone());
        let flow = parse_vless_inbound_flow(user, name, index)?;
        parsed.push(VlessInboundUser {
            username,
            uuid,
            flow,
        });
    }
    Ok(parsed)
}

fn parse_vless_inbound_flow(
    user: &Mapping,
    name: &str,
    index: usize,
) -> Result<Option<VlessFlow>, ConfigError> {
    let Some(flow) = mapping_string(user, "flow") else {
        return Ok(None);
    };
    if flow.is_empty() {
        return Ok(None);
    }
    let truncated = if flow.len() >= 16 {
        &flow[..16]
    } else {
        flow.as_str()
    };
    if truncated == "xtls-rprx-vision" {
        Ok(Some(VlessFlow::XtlsRprxVision))
    } else {
        Err(ConfigError::InvalidInbound(format!(
            "listener {name} user {index} has unsupported flow: {flow}"
        )))
    }
}

fn parse_vmess_listener(
    mapping: &Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<VmessInboundConfig, ConfigError> {
    validate_mapping_keys(
        mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "users",
            "certificate",
            "private-key",
            "ws-path",
            "grpc-service-name",
        ],
        &format!("listener {index}"),
    )?;
    let name = mapping_string(mapping, "name")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {index} is missing name")))?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let listen_host = mapping_string(mapping, "listen").unwrap_or_else(|| {
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
    let certificate = mapping_string(mapping, "certificate").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing certificate"))
    })?;
    let private_key = mapping_string(mapping, "private-key").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing private-key"))
    })?;
    if certificate.trim().is_empty() || private_key.trim().is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires non-empty certificate and private-key"
        )));
    }
    let ws_path = mapping_string(mapping, "ws-path").and_then(|path| {
        let trimmed = path.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let grpc_service_name = mapping_string(mapping, "grpc-service-name").and_then(|name| {
        let trimmed = name.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    if ws_path.is_some() && grpc_service_name.is_some() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} cannot combine ws-path and grpc-service-name until shared HTTP mux"
        )));
    }
    let users = parse_vmess_users(mapping, &name)?;
    if users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires at least one user uuid"
        )));
    }
    Ok(VmessInboundConfig {
        name,
        listen,
        users,
        certificate,
        private_key,
        ws_path,
        grpc_service_name,
    })
}

fn parse_vmess_users(mapping: &Mapping, name: &str) -> Result<Vec<VmessInboundUser>, ConfigError> {
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
            &["username", "uuid", "alterId"],
            &format!("listener {name} user {index}"),
        )?;
        let uuid = mapping_string(user, "uuid").ok_or_else(|| {
            ConfigError::InvalidInbound(format!("listener {name} user {index} is missing uuid"))
        })?;
        if uuid.trim().is_empty() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} user {index} uuid must not be empty"
            )));
        }
        if let Some(alter_id) = user.get(Value::from("alterId")) {
            let alter_id = alter_id.as_i64().or_else(|| {
                alter_id
                    .as_u64()
                    .and_then(|value| i64::try_from(value).ok())
            });
            match alter_id {
                Some(0) => {}
                Some(other) => {
                    return Err(ConfigError::InvalidInbound(format!(
                        "listener {name} user {index} alterId {other} is not supported; only alterId 0 (AEAD)"
                    )));
                }
                None => {
                    return Err(ConfigError::InvalidInbound(format!(
                        "listener {name} user {index} has invalid alterId"
                    )));
                }
            }
        }
        let username = mapping_string(user, "username").unwrap_or_else(|| uuid.clone());
        parsed.push(VmessInboundUser { username, uuid });
    }
    Ok(parsed)
}

fn parse_hysteria2_listener(
    mapping: &Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<Hysteria2InboundConfig, ConfigError> {
    validate_mapping_keys(
        mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "users",
            "certificate",
            "private-key",
            "alpn",
            "obfs",
            "obfs-password",
        ],
        &format!("listener {index}"),
    )?;
    let name = mapping_string(mapping, "name")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {index} is missing name")))?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let listen_host = mapping_string(mapping, "listen").unwrap_or_else(|| {
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
    let certificate = mapping_string(mapping, "certificate").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing certificate"))
    })?;
    let private_key = mapping_string(mapping, "private-key").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing private-key"))
    })?;
    if certificate.trim().is_empty() || private_key.trim().is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires non-empty certificate and private-key"
        )));
    }
    let alpn = parse_hysteria2_alpn(mapping, &name)?;
    let obfs_password = parse_hysteria2_obfs(mapping, &name)?;
    let users = parse_hysteria2_users(mapping, &name)?;
    if users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires at least one user"
        )));
    }
    Ok(Hysteria2InboundConfig {
        name,
        listen,
        users,
        certificate,
        private_key,
        alpn,
        obfs_password,
    })
}

fn parse_hysteria2_alpn(mapping: &Mapping, name: &str) -> Result<Vec<String>, ConfigError> {
    let Some(value) = mapping.get(Value::from("alpn")) else {
        return Ok(Vec::new());
    };
    if let Some(single) = value.as_str() {
        let trimmed = single.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(vec![trimmed.to_owned()]);
    }
    let Some(items) = value.as_sequence() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid alpn configuration"
        )));
    };
    let mut parsed = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(proto) = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} alpn entry {index} is invalid"
            )));
        };
        parsed.push(proto.to_owned());
    }
    Ok(parsed)
}

fn parse_hysteria2_obfs(mapping: &Mapping, name: &str) -> Result<Option<String>, ConfigError> {
    let obfs = mapping_string(mapping, "obfs");
    let password = mapping_string(mapping, "obfs-password");
    match (obfs.as_deref(), password) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(ConfigError::InvalidInbound(format!(
            "listener {name} has obfs-password without obfs"
        ))),
        (Some(""), _) => Ok(None),
        (Some("salamander"), Some(password)) => {
            if password.len() < 4 {
                return Err(ConfigError::InvalidInbound(format!(
                    "listener {name} salamander obfs-password must be at least 4 bytes"
                )));
            }
            Ok(Some(password))
        }
        (Some("salamander"), None) => Err(ConfigError::InvalidInbound(format!(
            "listener {name} is missing obfs-password"
        ))),
        (Some("gecko"), _) => Err(ConfigError::InvalidInbound(format!(
            "listener {name} gecko obfs is not supported in IN-F first slice"
        ))),
        (Some(other), _) => Err(ConfigError::InvalidInbound(format!(
            "listener {name} has unsupported obfs type: {other}"
        ))),
    }
}

fn parse_hysteria2_users(
    mapping: &Mapping,
    name: &str,
) -> Result<Vec<Hysteria2InboundUser>, ConfigError> {
    let Some(value) = mapping.get(Value::from("users")) else {
        return Ok(Vec::new());
    };
    let Some(users) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid users configuration"
        )));
    };
    let mut parsed = Vec::with_capacity(users.len());
    for (username, password) in users {
        let username = username
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ConfigError::InvalidInbound(format!(
                    "listener {name} has invalid users username key"
                ))
            })?;
        let password = password.as_str().map(str::to_owned).ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} user {username} password must be a string"
            ))
        })?;
        if password.is_empty() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} user {username} password must not be empty"
            )));
        }
        parsed.push(Hysteria2InboundUser {
            username: username.to_owned(),
            password,
        });
    }
    Ok(parsed)
}

fn parse_tuic_listener(
    mapping: &Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<TuicInboundConfig, ConfigError> {
    validate_mapping_keys(
        mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "users",
            "certificate",
            "private-key",
            "alpn",
            "congestion-controller",
            "max-idle-time",
            "authentication-timeout",
            "max-udp-relay-packet-size",
        ],
        &format!("listener {index}"),
    )?;
    // Reject deferred / v4-only knobs explicitly when present.
    for deferred in [
        "token",
        "ech-key",
        "client-auth-type",
        "client-auth-cert",
        "cwnd",
        "bbr-profile",
        "mux-option",
    ] {
        if mapping.contains_key(Value::from(deferred)) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {index} field `{deferred}` is not supported in IN-F TUIC first slice"
            )));
        }
    }
    let name = mapping_string(mapping, "name")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {index} is missing name")))?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let listen_host = mapping_string(mapping, "listen").unwrap_or_else(|| {
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
    let certificate = mapping_string(mapping, "certificate").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing certificate"))
    })?;
    let private_key = mapping_string(mapping, "private-key").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing private-key"))
    })?;
    if certificate.trim().is_empty() || private_key.trim().is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires non-empty certificate and private-key"
        )));
    }
    let alpn = parse_hysteria2_alpn(mapping, &name)?;
    let congestion_controller = parse_tuic_congestion(mapping, &name)?;
    // Go listener/tuic/server.go replaces explicit 0 with the same defaults used
    // when the key is omitted (max-idle-time 15000ms, authentication-timeout 1000ms).
    let max_idle_time_ms = match mapping
        .get(Value::from("max-idle-time"))
        .and_then(Value::as_u64)
    {
        Some(0) | None => 15_000,
        Some(value) => value,
    };
    let authentication_timeout_ms = match mapping
        .get(Value::from("authentication-timeout"))
        .and_then(Value::as_u64)
    {
        Some(0) | None => 1_000,
        Some(value) => value,
    };
    let max_udp_relay_packet_size = mapping
        .get(Value::from("max-udp-relay-packet-size"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let users = parse_tuic_users(mapping, &name)?;
    if users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires at least one user"
        )));
    }
    Ok(TuicInboundConfig {
        name,
        listen,
        users,
        certificate,
        private_key,
        alpn,
        congestion_controller,
        max_idle_time_ms,
        authentication_timeout_ms,
        max_udp_relay_packet_size,
    })
}

fn parse_tuic_congestion(mapping: &Mapping, name: &str) -> Result<String, ConfigError> {
    let Some(raw) = mapping_string(mapping, "congestion-controller") else {
        return Ok("cubic".to_owned());
    };
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "cubic" => Ok("cubic".to_owned()),
        "bbr" => Ok("bbr".to_owned()),
        "new_reno" | "new-reno" => Ok("new_reno".to_owned()),
        "brutal" => Err(ConfigError::InvalidInbound(format!(
            "listener {name} brutal congestion is not supported in IN-F TUIC first slice"
        ))),
        other => Err(ConfigError::InvalidInbound(format!(
            "listener {name} has unsupported congestion-controller: {other}"
        ))),
    }
}

fn parse_tuic_users(mapping: &Mapping, name: &str) -> Result<Vec<TuicInboundUser>, ConfigError> {
    let Some(value) = mapping.get(Value::from("users")) else {
        return Ok(Vec::new());
    };
    let Some(users) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid users configuration"
        )));
    };
    let mut parsed = Vec::with_capacity(users.len());
    for (uuid_key, password) in users {
        let uuid = uuid_key
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ConfigError::InvalidInbound(format!("listener {name} has invalid users uuid key"))
            })?;
        if uuid::Uuid::parse_str(uuid).is_err() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} has invalid users uuid: {uuid}"
            )));
        }
        let password = password.as_str().map(str::to_owned).ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} user {uuid} password must be a string"
            ))
        })?;
        if password.is_empty() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} user {uuid} password must not be empty"
            )));
        }
        parsed.push(TuicInboundUser {
            uuid: uuid.to_owned(),
            password,
        });
    }
    Ok(parsed)
}

fn parse_anytls_listener(
    mapping: &Mapping,
    index: usize,
    allow_lan: bool,
    bind_address: &str,
    names: &mut std::collections::BTreeSet<String>,
) -> Result<AnyTlsInboundConfig, ConfigError> {
    validate_mapping_keys(
        mapping,
        &[
            "name",
            "type",
            "listen",
            "port",
            "users",
            "certificate",
            "private-key",
            "padding-scheme",
        ],
        &format!("listener {index}"),
    )?;
    for deferred in [
        "ech-key",
        "client-auth-type",
        "client-auth-cert",
        "shadow-tls",
        "res-tls",
        "jls-config",
        "allow-insecure",
    ] {
        if mapping.contains_key(Value::from(deferred)) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {index} field `{deferred}` is not supported in IN-G AnyTLS first slice"
            )));
        }
    }
    let name = mapping_string(mapping, "name")
        .ok_or_else(|| ConfigError::InvalidInbound(format!("listener {index} is missing name")))?;
    if !names.insert(name.clone()) {
        return Err(ConfigError::InvalidInbound(format!(
            "listener name is duplicated: {name}"
        )));
    }
    let listen_host = mapping_string(mapping, "listen").unwrap_or_else(|| {
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
    let certificate = mapping_string(mapping, "certificate").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing certificate"))
    })?;
    let private_key = mapping_string(mapping, "private-key").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("listener {name} is missing private-key"))
    })?;
    if certificate.trim().is_empty() || private_key.trim().is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires non-empty certificate and private-key"
        )));
    }
    let padding_scheme = mapping_string(mapping, "padding-scheme").and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let users = parse_anytls_users(mapping, &name)?;
    if users.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} requires at least one user"
        )));
    }
    Ok(AnyTlsInboundConfig {
        name,
        listen,
        users,
        certificate,
        private_key,
        padding_scheme,
    })
}

fn parse_anytls_users(
    mapping: &Mapping,
    name: &str,
) -> Result<Vec<AnyTlsInboundUser>, ConfigError> {
    let Some(value) = mapping.get(Value::from("users")) else {
        return Ok(Vec::new());
    };
    let Some(users) = value.as_mapping() else {
        return Err(ConfigError::InvalidInbound(format!(
            "listener {name} has invalid users configuration"
        )));
    };
    let mut parsed = Vec::with_capacity(users.len());
    for (username_key, password) in users {
        let username = username_key
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ConfigError::InvalidInbound(format!(
                    "listener {name} has invalid users username key"
                ))
            })?;
        let password = password.as_str().map(str::to_owned).ok_or_else(|| {
            ConfigError::InvalidInbound(format!(
                "listener {name} user {username} password must be a string"
            ))
        })?;
        if password.is_empty() {
            return Err(ConfigError::InvalidInbound(format!(
                "listener {name} user {username} password must not be empty"
            )));
        }
        parsed.push(AnyTlsInboundUser {
            username: username.to_owned(),
            password,
        });
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

pub(crate) fn validate_vless_listener_ports(
    listeners: &[VlessInboundConfig],
) -> Result<(), ConfigError> {
    let mut ports = std::collections::BTreeSet::new();
    for listener in listeners {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "vless listener address is duplicated: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_vmess_listener_ports(
    listeners: &[VmessInboundConfig],
) -> Result<(), ConfigError> {
    let mut ports = std::collections::BTreeSet::new();
    for listener in listeners {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "vmess listener address is duplicated: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_hysteria2_listener_ports(
    listeners: &[Hysteria2InboundConfig],
) -> Result<(), ConfigError> {
    let mut ports = std::collections::BTreeSet::new();
    for listener in listeners {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "hysteria2 listener address is duplicated: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_tuic_listener_ports(
    listeners: &[TuicInboundConfig],
) -> Result<(), ConfigError> {
    let mut ports = std::collections::BTreeSet::new();
    for listener in listeners {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "tuic listener address is duplicated: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_anytls_listener_ports(
    listeners: &[AnyTlsInboundConfig],
) -> Result<(), ConfigError> {
    let mut ports = std::collections::BTreeSet::new();
    for listener in listeners {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "anytls listener address is duplicated: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_named_listener_ports(
    shadowsocks: &[ShadowsocksInboundConfig],
    trojan: &[TrojanInboundConfig],
    vless: &[VlessInboundConfig],
    vmess: &[VmessInboundConfig],
    hysteria2: &[Hysteria2InboundConfig],
    tuic: &[TuicInboundConfig],
    anytls: &[AnyTlsInboundConfig],
) -> Result<(), ConfigError> {
    validate_shadowsocks_listener_ports(shadowsocks)?;
    validate_trojan_listener_ports(trojan)?;
    validate_vless_listener_ports(vless)?;
    validate_vmess_listener_ports(vmess)?;
    validate_hysteria2_listener_ports(hysteria2)?;
    validate_tuic_listener_ports(tuic)?;
    validate_anytls_listener_ports(anytls)?;
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
    for listener in vless {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener address is duplicated across inbound types: {}",
                listener.listen
            )));
        }
    }
    for listener in vmess {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener address is duplicated across inbound types: {}",
                listener.listen
            )));
        }
    }
    for listener in hysteria2 {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener address is duplicated across inbound types: {}",
                listener.listen
            )));
        }
    }
    for listener in tuic {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener address is duplicated across inbound types: {}",
                listener.listen
            )));
        }
    }
    for listener in anytls {
        if !ports.insert((listener.listen.ip(), listener.listen.port())) {
            return Err(ConfigError::InvalidInbound(format!(
                "listener address is duplicated across inbound types: {}",
                listener.listen
            )));
        }
    }
    Ok(())
}
