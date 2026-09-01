use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use md5::{Digest, Md5};
use rewrite_rules::RematchSpec;
use url::Url;

use crate::error::ConfigError;
use crate::load::resolve_controller_pem;
use crate::model::{
    GroupHealthConfig, LoadBalanceStrategy, ProviderHealthConfig, ProxyConfig, ProxyGroupConfig,
    ProxyGroupKind, ProxyKind, ProxyProviderConfig, ProxyProviderTransform, ProxyProviderVehicle,
    VmessPacketMode, VmessProxyConfig, VmessSecurity, VmessTransport,
};
use crate::raw::{
    ProviderEtagCache, RawProviderHealthCheck, RawProxy, RawProxyGroup, RawProxyProvider,
    RawProxyProviderFile,
};
use rewrite_model::{ShadowsocksPluginConfig, V2rayEchConfig};

const SHADOWSOCKS_SIP004_AEAD_CIPHERS: [&str; 3] =
    ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];
const SHADOWSOCKS_LEGACY_STREAM_CIPHERS: [&str; 8] = [
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
];
const SHADOWSOCKS_EXTRA_AEAD_CIPHERS: [&str; 5] = [
    "xchacha20-ietf-poly1305",
    "aes-128-ccm",
    "aes-256-ccm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
];
const SHADOWSOCKS_2022_CIPHERS: [&str; 4] = [
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305",
];

pub(crate) fn supported_shadowsocks_cipher(cipher: &str) -> bool {
    SHADOWSOCKS_SIP004_AEAD_CIPHERS.contains(&cipher)
        || SHADOWSOCKS_LEGACY_STREAM_CIPHERS.contains(&cipher)
        || SHADOWSOCKS_EXTRA_AEAD_CIPHERS.contains(&cipher)
        || SHADOWSOCKS_2022_CIPHERS.contains(&cipher)
}

pub(crate) fn parse_proxies(
    proxies: Vec<RawProxy>,
    allow_http_tls: bool,
    home_directory: Option<&Path>,
) -> Result<(Vec<RematchSpec>, Vec<ProxyConfig>), ConfigError> {
    let mut rematches = Vec::new();
    let mut outbounds = Vec::new();
    let mut names = BTreeSet::new();
    for mut proxy in proxies {
        let has_transport_fields = proxy_has_transport_fields(&proxy);
        let name = proxy
            .name
            .take()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ConfigError::UnsupportedProxy("missing name".to_owned()))?;
        if !names.insert(name.clone())
            || matches!(
                name.as_str(),
                "DIRECT"
                    | "REJECT"
                    | "REJECT-DROP"
                    | "COMPATIBLE"
                    | "PASS"
                    | "PASS-RULE"
                    | "GLOBAL"
            )
        {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        match proxy.kind.as_deref() {
            Some("rematch") => {
                if has_transport_fields || !proxy.extra.is_empty() {
                    return Err(ConfigError::UnsupportedProxy(name));
                }
                let rematch = RematchSpec {
                    name: name.clone(),
                    target_rematch_name: proxy.target_rematch_name,
                    target_sub_rule: proxy.target_sub_rule,
                };
                if rematch.target_rematch_name.is_none() && rematch.target_sub_rule.is_none() {
                    return Err(ConfigError::UnsupportedProxy(name));
                }
                rematches.push(rematch);
                outbounds.push(simple_proxy(name, ProxyKind::Rematch));
            }
            Some(kind @ ("direct" | "reject" | "dns")) => {
                if proxy.target_rematch_name.is_some()
                    || proxy.target_sub_rule.is_some()
                    || has_transport_fields
                    || !proxy.extra.is_empty()
                {
                    return Err(ConfigError::UnsupportedProxy(name));
                }
                let kind = match kind {
                    "direct" => ProxyKind::Direct,
                    "reject" => ProxyKind::Reject,
                    "dns" => ProxyKind::Dns,
                    _ => unreachable!("matched simple proxy kind"),
                };
                outbounds.push(simple_proxy(name, kind));
            }
            Some(kind @ ("http" | "socks5")) => {
                let kind = if kind == "http" {
                    ProxyKind::Http
                } else {
                    ProxyKind::Socks5
                };
                outbounds.push(parse_remote_proxy(
                    name,
                    kind,
                    proxy,
                    allow_http_tls,
                    home_directory,
                )?);
            }
            Some("ss") => outbounds.push(parse_shadowsocks_proxy(name, proxy)?),
            Some("vmess") => outbounds.push(parse_vmess_proxy(name, proxy)?),
            _ => return Err(ConfigError::UnsupportedProxy(name)),
        }
    }
    Ok((rematches, outbounds))
}

fn parse_remote_proxy(
    name: String,
    kind: ProxyKind,
    proxy: RawProxy,
    allow_tls: bool,
    home_directory: Option<&Path>,
) -> Result<ProxyConfig, ConfigError> {
    let is_http = kind == ProxyKind::Http;
    let has_tls_options = proxy.tls.is_some()
        || proxy.sni.is_some()
        || proxy.skip_cert_verify.is_some()
        || proxy.name_cert_verify.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some();
    if proxy.target_rematch_name.is_some()
        || proxy.target_sub_rule.is_some()
        || (!allow_tls && has_tls_options)
        || proxy.cipher.is_some()
        || proxy.uuid.is_some()
        || proxy.alter_id.is_some()
        || proxy.network.is_some()
        || proxy.global_padding.is_some()
        || proxy.authenticated_length.is_some()
        || proxy.packet_addr.is_some()
        || proxy.xudp.is_some()
        || proxy.packet_encoding.is_some()
        || proxy.ws_opts.is_some()
        || proxy.http_opts.is_some()
        || proxy.h2_opts.is_some()
        || proxy.grpc_opts.is_some()
        || proxy.udp_over_tcp.is_some()
        || proxy.udp_over_tcp_version.is_some()
        || proxy.plugin.is_some()
        || proxy.plugin_opts.is_some()
        || (!is_http && proxy.sni.is_some())
        || (!is_http && proxy.headers.is_some())
        || (is_http && proxy.udp.is_some())
        || !proxy.extra.is_empty()
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    let server = proxy
        .server
        .filter(|server| !server.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let port = proxy
        .port
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let tls = proxy.tls.unwrap_or(false);
    if tls
        && (proxy.certificate.is_some() != proxy.private_key.is_some()
            || proxy.fingerprint.as_deref().is_some_and(|fingerprint| {
                let normalized = fingerprint.trim().replace(':', "");
                normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
            }))
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    Ok(ProxyConfig {
        name,
        kind,
        server,
        port,
        username: proxy.username,
        password: proxy.password,
        cipher: None,
        tls,
        sni: proxy.sni.filter(|sni| !sni.is_empty()),
        skip_cert_verify: proxy.skip_cert_verify.unwrap_or(false),
        name_cert_verify: proxy.name_cert_verify.filter(|name| !name.is_empty()),
        fingerprint: proxy.fingerprint.filter(|value| !value.is_empty()),
        certificate: proxy
            .certificate
            .filter(|value| !value.is_empty())
            .map(|value| resolve_controller_pem(value, home_directory))
            .transpose()?,
        private_key: proxy
            .private_key
            .filter(|value| !value.is_empty())
            .map(|value| resolve_controller_pem(value, home_directory))
            .transpose()?,
        client_fingerprint: proxy.client_fingerprint.filter(|value| !value.is_empty()),
        udp: proxy.udp.unwrap_or(false),
        udp_over_tcp: false,
        udp_over_tcp_version: 1,
        shadowsocks_plugin: None,
        vmess: None,
        headers: proxy.headers.unwrap_or_default(),
    })
}

fn parse_shadowsocks_proxy(name: String, proxy: RawProxy) -> Result<ProxyConfig, ConfigError> {
    if proxy.target_rematch_name.is_some()
        || proxy.target_sub_rule.is_some()
        || proxy.username.is_some()
        || proxy.uuid.is_some()
        || proxy.alter_id.is_some()
        || proxy.network.is_some()
        || proxy.global_padding.is_some()
        || proxy.authenticated_length.is_some()
        || proxy.packet_addr.is_some()
        || proxy.xudp.is_some()
        || proxy.packet_encoding.is_some()
        || proxy.ws_opts.is_some()
        || proxy.http_opts.is_some()
        || proxy.h2_opts.is_some()
        || proxy.grpc_opts.is_some()
        || proxy.tls.is_some()
        || proxy.sni.is_some()
        || proxy.skip_cert_verify.is_some()
        || proxy.name_cert_verify.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some()
        || proxy.headers.is_some()
        || !proxy.extra.is_empty()
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    let shadowsocks_plugin = parse_shadowsocks_plugin(&name, &proxy)?;
    if shadowsocks_plugin.is_some() && proxy.udp_over_tcp.unwrap_or(false) {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    let server = proxy
        .server
        .filter(|server| !server.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let port = proxy
        .port
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let password = proxy
        .password
        .filter(|password| !password.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let cipher = proxy
        .cipher
        .filter(|cipher| supported_shadowsocks_cipher(cipher))
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    validate_shadowsocks_key(&name, &cipher, &password, proxy.udp.unwrap_or(false))?;
    let client_fingerprint = proxy.client_fingerprint.filter(|value| !value.is_empty());
    if let Some(ShadowsocksPluginConfig::ShadowTls { version, .. }) = &shadowsocks_plugin {
        validate_shadow_tls_client_fingerprint(&name, client_fingerprint.as_deref(), *version)?;
    }
    let udp_over_tcp_version = match proxy.udp_over_tcp_version.unwrap_or(0) {
        0 | 1 => 1,
        2 => 2,
        _ => return Err(ConfigError::UnsupportedProxy(name)),
    };
    Ok(ProxyConfig {
        name,
        kind: ProxyKind::Shadowsocks,
        server,
        port,
        username: None,
        password: Some(password),
        cipher: Some(cipher),
        tls: false,
        sni: None,
        skip_cert_verify: false,
        name_cert_verify: None,
        fingerprint: None,
        certificate: None,
        private_key: None,
        client_fingerprint,
        udp: proxy.udp.unwrap_or(false),
        udp_over_tcp: proxy.udp_over_tcp.unwrap_or(false),
        udp_over_tcp_version,
        shadowsocks_plugin,
        vmess: None,
        headers: BTreeMap::new(),
    })
}

fn parse_vmess_proxy(name: String, proxy: RawProxy) -> Result<ProxyConfig, ConfigError> {
    let network = proxy.network.as_deref().unwrap_or("tcp");
    let tls = proxy.tls.unwrap_or(false);
    let has_tls_options = proxy.sni.is_some()
        || proxy.skip_cert_verify.is_some()
        || proxy.name_cert_verify.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some();
    if proxy.target_rematch_name.is_some()
        || proxy.target_sub_rule.is_some()
        || proxy.username.is_some()
        || proxy.password.is_some()
        || proxy.udp_over_tcp.is_some()
        || proxy.udp_over_tcp_version.is_some()
        || proxy.plugin.is_some()
        || proxy.plugin_opts.is_some()
        || proxy.client_fingerprint.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some()
        || proxy.headers.is_some()
        || proxy.alter_id.unwrap_or_default() < 0
        || !matches!(network, "tcp" | "ws" | "http" | "h2" | "grpc")
        || (!tls && has_tls_options)
        || (network != "ws" && proxy.ws_opts.is_some())
        || (network != "http" && proxy.http_opts.is_some())
        || (network != "h2" && proxy.h2_opts.is_some())
        || (network != "grpc" && proxy.grpc_opts.is_some())
        || (proxy.udp.unwrap_or(false) && (tls || network != "tcp"))
        || !proxy.extra.is_empty()
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    let (security, cipher) = parse_vmess_security(proxy.cipher.as_deref(), &name)?;
    let packet_mode = parse_vmess_packet_mode(&proxy, &name)?;
    let transport = parse_vmess_transport(
        network,
        proxy.ws_opts.as_ref(),
        proxy.http_opts.as_ref(),
        proxy.h2_opts.as_ref(),
        proxy.grpc_opts.as_ref(),
        &name,
    )?;
    let server = proxy
        .server
        .filter(|server| !server.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let port = proxy
        .port
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let uuid = proxy
        .uuid
        .as_deref()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .map(|value| *value.as_bytes())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    Ok(ProxyConfig {
        name,
        kind: ProxyKind::Vmess,
        server,
        port,
        username: None,
        password: None,
        cipher: Some(cipher),
        tls,
        sni: proxy.sni.filter(|sni| !sni.is_empty()),
        skip_cert_verify: proxy.skip_cert_verify.unwrap_or(false),
        name_cert_verify: proxy.name_cert_verify.filter(|name| !name.is_empty()),
        fingerprint: None,
        certificate: None,
        private_key: None,
        client_fingerprint: None,
        udp: proxy.udp.unwrap_or(false),
        udp_over_tcp: false,
        udp_over_tcp_version: 1,
        shadowsocks_plugin: None,
        vmess: Some(VmessProxyConfig {
            uuid,
            alter_id: proxy.alter_id.unwrap_or_default(),
            security,
            packet_mode,
            transport,
            global_padding: proxy.global_padding.unwrap_or(false),
            authenticated_length: proxy.authenticated_length.unwrap_or(false),
        }),
        headers: BTreeMap::new(),
    })
}

fn parse_vmess_transport(
    network: &str,
    websocket: Option<&crate::raw::RawVmessWebSocketOptions>,
    http: Option<&crate::raw::RawVmessHttpOptions>,
    http2: Option<&crate::raw::RawVmessHttp2Options>,
    grpc: Option<&crate::raw::RawVmessGrpcOptions>,
    name: &str,
) -> Result<VmessTransport, ConfigError> {
    if network == "tcp" {
        return Ok(VmessTransport::Tcp);
    }
    if network == "http" {
        let options = http.cloned().unwrap_or_default();
        if !options.extra.is_empty() {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
        let method = options
            .method
            .filter(|method| !method.is_empty())
            .unwrap_or_else(|| "GET".to_owned());
        if http::Method::from_bytes(method.as_bytes()).is_err() {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
        let mut paths = options.path.unwrap_or_default();
        if paths.is_empty() {
            paths.push("/".to_owned());
        }
        if paths.iter().any(|path| !path.starts_with('/')) {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
        let headers = options.headers.unwrap_or_default();
        if headers.iter().any(|(header, values)| {
            http::header::HeaderName::from_bytes(header.as_bytes()).is_err()
                || values
                    .iter()
                    .any(|value| http::header::HeaderValue::from_str(value).is_err())
        }) {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
        return Ok(VmessTransport::Http {
            method,
            paths,
            headers,
        });
    }
    if network == "h2" {
        let options = http2.cloned().unwrap_or_default();
        if !options.extra.is_empty() {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
        let mut hosts = options.host.unwrap_or_default();
        if hosts.is_empty() {
            hosts.push("www.example.com".to_owned());
        }
        let path = options
            .path
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| "/".to_owned());
        if hosts.iter().any(|host| {
            host.is_empty() || http::uri::Authority::from_maybe_shared(host.clone()).is_err()
        }) || !path.starts_with('/')
        {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
        return Ok(VmessTransport::Http2 { hosts, path });
    }
    if network == "grpc" {
        return parse_vmess_grpc_transport(grpc, name);
    }
    let options = websocket.cloned().unwrap_or_default();
    if !options.extra.is_empty() {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let max_early_data = options
        .max_early_data
        .map(usize::try_from)
        .transpose()
        .map_err(|_| ConfigError::UnsupportedProxy(name.to_owned()))?
        .unwrap_or_default();
    let early_data_header_name = options
        .early_data_header_name
        .filter(|name| !name.is_empty());
    let http_upgrade = options.v2ray_http_upgrade.unwrap_or(false);
    let http_upgrade_fast_open = options.v2ray_http_upgrade_fast_open.unwrap_or(false);
    let path = options
        .path
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "/".to_owned());
    if !path.starts_with('/') {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    Ok(VmessTransport::WebSocket {
        path,
        headers: options.headers.unwrap_or_default(),
        max_early_data,
        early_data_header_name,
        http_upgrade,
        http_upgrade_fast_open,
    })
}

fn parse_vmess_grpc_transport(
    grpc: Option<&crate::raw::RawVmessGrpcOptions>,
    name: &str,
) -> Result<VmessTransport, ConfigError> {
    let options = grpc.cloned().unwrap_or_default();
    if !options.extra.is_empty()
        || options.ping_interval.unwrap_or_default() != 0
        || options.max_connections.unwrap_or_default() != 0
        || options.min_streams.unwrap_or_default() != 0
        || options.max_streams.unwrap_or_default() != 0
    {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let service_name = options
        .grpc_service_name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "GunService".to_owned());
    let user_agent = options
        .grpc_user_agent
        .filter(|agent| !agent.is_empty())
        .unwrap_or_else(|| "grpc-go/1.36.0".to_owned());
    let service_path = if service_name.starts_with('/') {
        service_name.clone()
    } else {
        format!("/{service_name}/Tun")
    };
    if service_path.parse::<http::uri::PathAndQuery>().is_err()
        || http::header::HeaderValue::from_str(&user_agent).is_err()
    {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    Ok(VmessTransport::Grpc {
        service_name,
        user_agent,
    })
}

fn parse_vmess_security(
    configured: Option<&str>,
    name: &str,
) -> Result<(VmessSecurity, String), ConfigError> {
    let security = match configured.map(str::to_ascii_lowercase) {
        Some(cipher) if cipher == "auto" => VmessSecurity::Auto,
        Some(cipher) if matches!(cipher.as_str(), "none" | "zero") => VmessSecurity::None,
        Some(cipher) if cipher == "aes-128-cfb" => VmessSecurity::Aes128Cfb,
        Some(cipher) if cipher == "aes-128-gcm" => VmessSecurity::Aes128Gcm,
        Some(cipher) if cipher == "chacha20-poly1305" => VmessSecurity::ChaCha20Poly1305,
        _ => return Err(ConfigError::UnsupportedProxy(name.to_owned())),
    };
    let cipher = match security {
        VmessSecurity::Auto => "auto",
        VmessSecurity::None => configured
            .filter(|cipher| cipher.eq_ignore_ascii_case("zero"))
            .map_or("none", |_| "zero"),
        VmessSecurity::Aes128Cfb => "aes-128-cfb",
        VmessSecurity::Aes128Gcm => "aes-128-gcm",
        VmessSecurity::ChaCha20Poly1305 => "chacha20-poly1305",
    };
    Ok((security, cipher.to_owned()))
}

fn parse_vmess_packet_mode(proxy: &RawProxy, name: &str) -> Result<VmessPacketMode, ConfigError> {
    let encoded_packet_mode = match proxy.packet_encoding.as_deref() {
        None => None,
        Some("packetaddr" | "packet") => Some(VmessPacketMode::PacketAddr),
        Some("xudp") => Some(VmessPacketMode::Xudp),
        Some(_) => return Err(ConfigError::UnsupportedProxy(name.to_owned())),
    };
    Ok(
        if proxy.xudp.unwrap_or(false) || encoded_packet_mode == Some(VmessPacketMode::Xudp) {
            VmessPacketMode::Xudp
        } else if proxy.packet_addr.unwrap_or(false)
            || encoded_packet_mode == Some(VmessPacketMode::PacketAddr)
        {
            VmessPacketMode::PacketAddr
        } else {
            VmessPacketMode::Standard
        },
    )
}

fn validate_shadow_tls_client_fingerprint(
    proxy_name: &str,
    fingerprint: Option<&str>,
    version: u8,
) -> Result<(), ConfigError> {
    let Some(raw) = fingerprint.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if raw.eq_ignore_ascii_case("none") {
        return Ok(());
    }
    if version == 1 {
        return Err(ConfigError::UnsupportedProxy(proxy_name.to_owned()));
    }
    if raw.eq_ignore_ascii_case("chrome") {
        return Ok(());
    }
    Err(ConfigError::UnsupportedProxy(proxy_name.to_owned()))
}

pub(crate) fn shadowsocks_2022_cipher(cipher: &str) -> bool {
    SHADOWSOCKS_2022_CIPHERS.contains(&cipher)
}

pub(crate) fn validate_shadowsocks_inbound_key(
    cipher: &str,
    password: &str,
) -> Result<(), ConfigError> {
    validate_shadowsocks_key("ss-config", cipher, password, false).map_err(|error| match error {
        ConfigError::UnsupportedProxy(_) => ConfigError::InvalidInbound(format!(
            "invalid shadowsocks inbound key for cipher {cipher}"
        )),
        other => other,
    })
}

fn validate_shadowsocks_key(
    name: &str,
    cipher: &str,
    password: &str,
    udp: bool,
) -> Result<(), ConfigError> {
    let expected_key_length = match cipher {
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-poly1305"
        | "2022-blake3-chacha8-poly1305" => Some(32),
        _ => None,
    };
    if let Some(expected_key_length) = expected_key_length {
        let keys = password.split(':').collect::<Vec<_>>();
        let maximum_keys = if matches!(
            cipher,
            "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha8-poly1305"
        ) {
            1
        } else {
            2
        };
        if keys.is_empty()
            || keys.len() > maximum_keys
            || keys.iter().any(|key| {
                STANDARD
                    .decode(key)
                    .ok()
                    .is_none_or(|key| key.len() != expected_key_length)
            })
        {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
    }
    if expected_key_length.is_some() && udp {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    Ok(())
}

fn parse_shadowsocks_plugin(
    name: &str,
    proxy: &RawProxy,
) -> Result<Option<ShadowsocksPluginConfig>, ConfigError> {
    Ok(match proxy.plugin.as_deref() {
        None | Some("") if proxy.plugin_opts.is_none() => None,
        Some("obfs") => {
            let options = proxy
                .plugin_opts
                .as_ref()
                .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
            if options
                .keys()
                .any(|key| !matches!(key.as_str(), "mode" | "host"))
                || !matches!(plugin_string(options, "mode"), Some("http" | "tls"))
            {
                return Err(ConfigError::UnsupportedProxy(name.to_owned()));
            }
            let host = options
                .get("host")
                .and_then(serde_yaml_ng::Value::as_str)
                .filter(|host| !host.is_empty())
                .map_or_else(|| "bing.com".to_owned(), str::to_owned);
            Some(match plugin_string(options, "mode") {
                Some("http") => ShadowsocksPluginConfig::SimpleObfsHttp { host },
                Some("tls") => ShadowsocksPluginConfig::SimpleObfsTls { host },
                _ => unreachable!("mode validated above"),
            })
        }
        Some("v2ray-plugin") => {
            let options = proxy
                .plugin_opts
                .as_ref()
                .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
            Some(parse_v2ray_plugin(name, options)?)
        }
        Some("shadow-tls") => {
            let options = proxy
                .plugin_opts
                .as_ref()
                .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
            Some(parse_shadow_tls_plugin(name, options)?)
        }
        _ => return Err(ConfigError::UnsupportedProxy(name.to_owned())),
    })
}

fn parse_shadow_tls_plugin(
    name: &str,
    options: &BTreeMap<String, serde_yaml_ng::Value>,
) -> Result<ShadowsocksPluginConfig, ConfigError> {
    let host = plugin_string(options, "host")
        .filter(|host| !host.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?
        .to_owned();
    let password = plugin_string(options, "password")
        .unwrap_or_default()
        .to_owned();
    let version = match options.get("version") {
        None => 2,
        Some(value) => {
            plugin_u8(value).ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?
        }
    };
    if options.contains_key("skip-cert-verify")
        && plugin_bool(options, "skip-cert-verify").is_none()
    {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let alpn = match options.get("alpn") {
        None => vec!["h2".to_owned(), "http/1.1".to_owned()],
        Some(serde_yaml_ng::Value::Sequence(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .ok_or(())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|()| ConfigError::UnsupportedProxy(name.to_owned()))?,
        Some(_) => return Err(ConfigError::UnsupportedProxy(name.to_owned())),
    };
    let verification_name = plugin_string(options, "name-cert-verify")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let certificate_fingerprint = plugin_string(options, "fingerprint")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let certificate = plugin_string(options, "certificate")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let private_key = plugin_string(options, "private-key")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if certificate.is_some() != private_key.is_some() {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    Ok(ShadowsocksPluginConfig::ShadowTls {
        host,
        password,
        version,
        skip_certificate_verification: plugin_bool(options, "skip-cert-verify").unwrap_or(false),
        verification_name,
        certificate_fingerprint,
        certificate,
        private_key,
        alpn,
    })
}

#[derive(Default)]
struct V2rayTlsOptions {
    verification_name: Option<String>,
    certificate_fingerprint: Option<String>,
    certificate: Option<String>,
    private_key: Option<String>,
    ech: Option<V2rayEchConfig>,
}

fn parse_v2ray_plugin(
    name: &str,
    options: &BTreeMap<String, serde_yaml_ng::Value>,
) -> Result<ShadowsocksPluginConfig, ConfigError> {
    if plugin_string(options, "mode") != Some("websocket") {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    for key in [
        "mux",
        "tls",
        "skip-cert-verify",
        "v2ray-http-upgrade",
        "v2ray-http-upgrade-fast-open",
    ] {
        if options.contains_key(key) && plugin_bool(options, key).is_none() {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
    }
    let host = plugin_string(options, "host")
        .filter(|host| !host.is_empty())
        .unwrap_or("bing.com")
        .to_owned();
    let path = plugin_string(options, "path")
        .filter(|path| !path.is_empty())
        .unwrap_or("/");
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let headers = plugin_headers(options, "headers")
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
    let tls = plugin_bool(options, "tls").unwrap_or(false);
    let tls_options = if tls {
        parse_v2ray_tls_options(name, options)?
    } else {
        V2rayTlsOptions::default()
    };
    Ok(ShadowsocksPluginConfig::V2rayWebSocket {
        host,
        path,
        headers,
        tls,
        skip_certificate_verification: plugin_bool(options, "skip-cert-verify").unwrap_or(false),
        verification_name: tls_options.verification_name,
        certificate_fingerprint: tls_options.certificate_fingerprint,
        certificate: tls_options.certificate,
        private_key: tls_options.private_key,
        ech: tls_options.ech,
        mux: plugin_bool(options, "mux").unwrap_or(true),
        http_upgrade: plugin_bool(options, "v2ray-http-upgrade").unwrap_or(false),
        http_upgrade_fast_open: plugin_bool(options, "v2ray-http-upgrade-fast-open")
            .unwrap_or(false),
    })
}

fn parse_v2ray_tls_options(
    name: &str,
    options: &BTreeMap<String, serde_yaml_ng::Value>,
) -> Result<V2rayTlsOptions, ConfigError> {
    let verification_name = plugin_string(options, "name-cert-verify")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let certificate_fingerprint = plugin_string(options, "fingerprint")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if certificate_fingerprint
        .as_deref()
        .is_some_and(|fingerprint| {
            let normalized = fingerprint.trim().replace(':', "");
            normalized.len() != 64 || hex::decode(normalized).is_err()
        })
    {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let certificate = plugin_string(options, "certificate")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let private_key = plugin_string(options, "private-key")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if certificate.is_some() != private_key.is_some() {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let ech =
        parse_v2ray_ech(options).map_err(|()| ConfigError::UnsupportedProxy(name.to_owned()))?;
    Ok(V2rayTlsOptions {
        verification_name,
        certificate_fingerprint,
        certificate,
        private_key,
        ech,
    })
}

fn plugin_string<'a>(
    options: &'a BTreeMap<String, serde_yaml_ng::Value>,
    key: &str,
) -> Option<&'a str> {
    options.get(key).and_then(serde_yaml_ng::Value::as_str)
}

fn plugin_bool(options: &BTreeMap<String, serde_yaml_ng::Value>, key: &str) -> Option<bool> {
    options.get(key).and_then(|value| match value {
        serde_yaml_ng::Value::Bool(value) => Some(*value),
        serde_yaml_ng::Value::String(value) => value.parse().ok(),
        _ => None,
    })
}

fn plugin_u8(value: &serde_yaml_ng::Value) -> Option<u8> {
    match value {
        serde_yaml_ng::Value::Number(number) => {
            number.as_u64().and_then(|value| u8::try_from(value).ok())
        }
        serde_yaml_ng::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn plugin_headers(
    options: &BTreeMap<String, serde_yaml_ng::Value>,
    key: &str,
) -> Option<BTreeMap<String, String>> {
    let Some(value) = options.get(key) else {
        return Some(BTreeMap::new());
    };
    let mapping = value.as_mapping()?;
    mapping
        .iter()
        .map(|(key, value)| Some((key.as_str()?.to_owned(), value.as_str()?.to_owned())))
        .collect()
}

fn parse_v2ray_ech(
    options: &BTreeMap<String, serde_yaml_ng::Value>,
) -> Result<Option<V2rayEchConfig>, ()> {
    let Some(value) = options.get("ech-opts") else {
        return Ok(None);
    };
    let mapping = value.as_mapping().ok_or(())?;
    let get = |key: &str| mapping.get(serde_yaml_ng::Value::String(key.to_owned()));
    let enabled = match get("enable") {
        None => false,
        Some(serde_yaml_ng::Value::Bool(enabled)) => *enabled,
        _ => return Err(()),
    };
    if !enabled {
        return Ok(None);
    }
    let config = get("config").and_then(serde_yaml_ng::Value::as_str);
    if let Some(config) = config.filter(|config| !config.is_empty()) {
        return STANDARD
            .decode(config)
            .map_err(|_| ())
            .map(V2rayEchConfig::Inline)
            .map(Some);
    }
    let query_server_name = get("query-server-name")
        .and_then(serde_yaml_ng::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Ok(Some(V2rayEchConfig::Dns { query_server_name }))
}

fn proxy_has_transport_fields(proxy: &RawProxy) -> bool {
    proxy.server.is_some()
        || proxy.port.is_some()
        || proxy.username.is_some()
        || proxy.password.is_some()
        || proxy.cipher.is_some()
        || proxy.uuid.is_some()
        || proxy.alter_id.is_some()
        || proxy.network.is_some()
        || proxy.global_padding.is_some()
        || proxy.authenticated_length.is_some()
        || proxy.packet_addr.is_some()
        || proxy.xudp.is_some()
        || proxy.packet_encoding.is_some()
        || proxy.ws_opts.is_some()
        || proxy.http_opts.is_some()
        || proxy.h2_opts.is_some()
        || proxy.grpc_opts.is_some()
        || proxy.tls.is_some()
        || proxy.udp.is_some()
        || proxy.udp_over_tcp.is_some()
        || proxy.udp_over_tcp_version.is_some()
        || proxy.plugin.is_some()
        || proxy.plugin_opts.is_some()
        || proxy.sni.is_some()
        || proxy.skip_cert_verify.is_some()
        || proxy.name_cert_verify.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some()
        || proxy.headers.is_some()
}

fn simple_proxy(name: String, kind: ProxyKind) -> ProxyConfig {
    ProxyConfig {
        name,
        kind,
        server: String::new(),
        port: 0,
        username: None,
        password: None,
        cipher: None,
        tls: false,
        sni: None,
        skip_cert_verify: false,
        name_cert_verify: None,
        fingerprint: None,
        certificate: None,
        private_key: None,
        client_fingerprint: None,
        udp: true,
        udp_over_tcp: false,
        udp_over_tcp_version: 1,
        shadowsocks_plugin: None,
        vmess: None,
        headers: BTreeMap::new(),
    }
}

pub(crate) fn parse_proxy_groups(
    groups: Vec<RawProxyGroup>,
    proxies: &[ProxyConfig],
    providers: &[ProxyProviderConfig],
) -> Result<Vec<ProxyGroupConfig>, ConfigError> {
    let mut proxy_names: BTreeSet<_> = proxies
        .iter()
        .chain(
            providers
                .iter()
                .flat_map(|provider| provider.proxies.iter()),
        )
        .map(|proxy| proxy.name.clone())
        .collect();
    let top_level_names: BTreeSet<_> = proxies.iter().map(|proxy| proxy.name.clone()).collect();
    let mut all_proxies: Vec<_> = proxies.iter().map(|proxy| proxy.name.clone()).collect();
    all_proxies.sort();
    let all_providers: Vec<_> = providers
        .iter()
        .map(|provider| provider.name.clone())
        .collect();
    let mut group_names = BTreeSet::new();
    for group in &groups {
        let name = group
            .name
            .as_deref()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ConfigError::UnsupportedProxy("missing group name".to_owned()))?;
        if !matches!(
            group.kind.as_deref(),
            Some("select" | "fallback" | "url-test" | "load-balance")
        ) || !group.extra.is_empty()
            || !group_names.insert(name.to_owned())
            || proxy_names.contains(name)
            || (name != "GLOBAL" && is_reserved_proxy_name(name))
        {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
    }
    validate_proxy_group_cycles(&groups, &group_names)?;
    let group_types: BTreeMap<_, _> = groups
        .iter()
        .filter_map(|group| {
            let name = group.name.as_ref()?;
            let kind = match group.kind.as_deref()? {
                "select" => "Selector",
                "fallback" => "Fallback",
                "url-test" => "URLTest",
                "load-balance" => "LoadBalance",
                _ => return None,
            };
            Some((name.clone(), kind.to_owned()))
        })
        .collect();
    proxy_names.extend(group_names.iter().cloned());
    let proxy_types = proxy_member_types(proxies, providers, &group_types);
    let catalog = ProxyGroupCatalog {
        proxy_names: &proxy_names,
        top_level_names: &top_level_names,
        all_proxies: &all_proxies,
        all_providers: &all_providers,
        providers,
        proxy_types: &proxy_types,
    };

    let mut parsed = Vec::new();
    for group in groups {
        let name = group
            .name
            .as_ref()
            .filter(|name| !name.is_empty())
            .cloned()
            .ok_or_else(|| ConfigError::UnsupportedProxy("missing group name".to_owned()))?;
        parsed.push(parse_proxy_group(group, name, &catalog)?);
    }
    Ok(parsed)
}

fn validate_proxy_group_cycles(
    groups: &[RawProxyGroup],
    group_names: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    let mapping: BTreeMap<_, _> = groups
        .iter()
        .filter_map(|group| group.name.as_deref().map(|name| (name, group)))
        .collect();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for name in group_names {
        visit_proxy_group(name, &mapping, group_names, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_proxy_group<'a>(
    name: &'a str,
    groups: &BTreeMap<&'a str, &'a RawProxyGroup>,
    group_names: &BTreeSet<String>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), ConfigError> {
    if visited.contains(name) {
        return Ok(());
    }
    if !visiting.insert(name) {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let group = groups
        .get(name)
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
    for dependency in group.proxies.iter().flatten() {
        if group_names.contains(dependency.as_str()) {
            visit_proxy_group(dependency, groups, group_names, visiting, visited)?;
        }
    }
    visiting.remove(name);
    visited.insert(name);
    Ok(())
}

fn is_reserved_proxy_name(name: &str) -> bool {
    matches!(
        name,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS" | "PASS-RULE" | "GLOBAL"
    )
}

struct ProxyGroupCatalog<'a> {
    proxy_names: &'a BTreeSet<String>,
    top_level_names: &'a BTreeSet<String>,
    all_proxies: &'a [String],
    all_providers: &'a [String],
    providers: &'a [ProxyProviderConfig],
    proxy_types: &'a BTreeMap<String, String>,
}

fn parse_proxy_group(
    group: RawProxyGroup,
    name: String,
    catalog: &ProxyGroupCatalog<'_>,
) -> Result<ProxyGroupConfig, ConfigError> {
    let kind = parse_proxy_group_kind(group.kind.as_deref(), &name)?;
    let load_balance_strategy =
        parse_load_balance_strategy(kind, group.strategy.as_deref(), &name)?;
    let health = normalize_group_health(kind, &group);
    let filter = group.filter.filter(|value| !value.is_empty());
    let exclude_filter = group.exclude_filter.filter(|value| !value.is_empty());
    let exclude_types: Vec<_> = group
        .exclude_type
        .filter(|value| !value.is_empty())
        .into_iter()
        .flat_map(|value| value.split('|').map(str::to_owned).collect::<Vec<String>>())
        .collect();
    let filter_regexes = compile_group_regexes(filter.as_deref(), &name)?;
    compile_group_regexes(exclude_filter.as_deref(), &name)?;
    let empty_fallback = group
        .empty_fallback
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "COMPATIBLE".to_owned());
    if !catalog.top_level_names.contains(empty_fallback.as_str())
        && !is_group_builtin(&empty_fallback)
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }

    let include_all = group.include_all.unwrap_or(false);
    let include_all_proxies = include_all || group.include_all_proxies.unwrap_or(false);
    let include_all_providers = include_all || group.include_all_providers.unwrap_or(false);
    let mut compatible_proxies = group.proxies.unwrap_or_default();
    if include_all_proxies {
        if filter_regexes.is_empty() {
            compatible_proxies.extend(catalog.all_proxies.iter().cloned());
        } else {
            for proxy in catalog.all_proxies {
                for pattern in &filter_regexes {
                    if group_regex_matches(pattern, proxy) {
                        compatible_proxies.push(proxy.clone());
                    }
                }
            }
        }
    }
    let provider_names = if include_all_providers {
        catalog.all_providers.to_vec()
    } else {
        group.providers.unwrap_or_default()
    };
    for provider_name in &provider_names {
        catalog
            .providers
            .iter()
            .find(|provider| provider.name == *provider_name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    }
    if compatible_proxies.is_empty() && provider_names.is_empty() {
        compatible_proxies.push(empty_fallback.clone());
    }
    if compatible_proxies
        .iter()
        .any(|member| !catalog.proxy_names.contains(member.as_str()) && !is_group_builtin(member))
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    let mut parsed = ProxyGroupConfig {
        name,
        kind,
        proxies: Vec::new(),
        compatible_proxies,
        providers: provider_names,
        filter,
        exclude_filter,
        exclude_types,
        empty_fallback,
        default_selected: group.default_selected,
        test_url: normalize_group_test_url(group.url),
        expected_status: normalize_group_expected_status(group.expected_status),
        hidden: group.hidden.unwrap_or(false),
        icon: group.icon.unwrap_or_default(),
        disable_udp: group.disable_udp.unwrap_or(false),
        tolerance: group.tolerance.unwrap_or(0),
        health,
        load_balance_strategy,
    };
    parsed.proxies = expand_proxy_group(&parsed, catalog.providers, catalog.proxy_types)?;
    if parsed
        .proxies
        .iter()
        .any(|member| !catalog.proxy_names.contains(member.as_str()) && !is_group_builtin(member))
        || (parsed.kind == ProxyGroupKind::Select
            && parsed
                .default_selected
                .as_ref()
                .is_some_and(|default| !parsed.proxies.contains(default))
            && !parsed.providers.iter().any(|name| {
                catalog.providers.iter().any(|provider| {
                    provider.name == *name && provider.vehicle == ProxyProviderVehicle::Http
                })
            }))
    {
        return Err(ConfigError::UnsupportedProxy(parsed.name));
    }
    Ok(parsed)
}

fn parse_proxy_group_kind(kind: Option<&str>, name: &str) -> Result<ProxyGroupKind, ConfigError> {
    match kind {
        Some("select") => Ok(ProxyGroupKind::Select),
        Some("fallback") => Ok(ProxyGroupKind::Fallback),
        Some("url-test") => Ok(ProxyGroupKind::UrlTest),
        Some("load-balance") => Ok(ProxyGroupKind::LoadBalance),
        _ => Err(ConfigError::UnsupportedProxy(name.to_owned())),
    }
}

fn parse_load_balance_strategy(
    kind: ProxyGroupKind,
    strategy: Option<&str>,
    name: &str,
) -> Result<Option<LoadBalanceStrategy>, ConfigError> {
    match (kind, strategy) {
        (ProxyGroupKind::LoadBalance, None | Some("consistent-hashing")) => {
            Ok(Some(LoadBalanceStrategy::ConsistentHashing))
        }
        (ProxyGroupKind::LoadBalance, Some("round-robin")) => {
            Ok(Some(LoadBalanceStrategy::RoundRobin))
        }
        (ProxyGroupKind::LoadBalance, Some("sticky-sessions")) => {
            Ok(Some(LoadBalanceStrategy::StickySessions))
        }
        (_, Some(_)) => Err(ConfigError::UnsupportedProxy(name.to_owned())),
        (_, None) => Ok(None),
    }
}

fn normalize_group_health(kind: ProxyGroupKind, group: &RawProxyGroup) -> GroupHealthConfig {
    GroupHealthConfig {
        interval: match (kind, group.interval.unwrap_or(0)) {
            (ProxyGroupKind::Select, interval) | (_, interval @ 1..) => interval,
            (_, 0) => 300,
        },
        timeout: match group.timeout.unwrap_or(0) {
            0 => 5000,
            timeout => timeout,
        },
        lazy: group.lazy.unwrap_or(true),
        max_failed_times: match group.max_failed_times.unwrap_or(0) {
            0 => 5,
            max_failed_times => max_failed_times,
        },
    }
}

fn normalize_group_test_url(value: Option<String>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_owned())
}

fn normalize_group_expected_status(value: Option<String>) -> String {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "*".to_owned())
}

fn is_group_builtin(name: &str) -> bool {
    matches!(
        name,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS" | "PASS-RULE"
    )
}

fn compile_group_regexes(
    value: Option<&str>,
    group_name: &str,
) -> Result<Vec<fancy_regex::Regex>, ConfigError> {
    value
        .into_iter()
        .flat_map(|value| value.split('`'))
        .map(|pattern| {
            fancy_regex::Regex::new(pattern)
                .map_err(|_| ConfigError::UnsupportedProxy(group_name.to_owned()))
        })
        .collect()
}

fn group_regex_matches(pattern: &fancy_regex::Regex, name: &str) -> bool {
    pattern.is_match(name).unwrap_or(false)
}

pub(crate) fn proxy_member_types(
    proxies: &[ProxyConfig],
    providers: &[ProxyProviderConfig],
    group_types: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut types: BTreeMap<_, _> = [
        ("DIRECT", "Direct"),
        ("REJECT", "Reject"),
        ("REJECT-DROP", "RejectDrop"),
        ("COMPATIBLE", "Compatible"),
        ("PASS", "Pass"),
        ("PASS-RULE", "Pass"),
    ]
    .into_iter()
    .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
    .collect();
    for proxy in proxies.iter().chain(
        providers
            .iter()
            .flat_map(|provider| provider.proxies.iter()),
    ) {
        let kind = match proxy.kind {
            ProxyKind::Http => "Http",
            ProxyKind::Socks5 => "Socks5",
            ProxyKind::Shadowsocks => "Shadowsocks",
            ProxyKind::Vmess => "Vmess",
            ProxyKind::Direct => "Direct",
            ProxyKind::Reject => "Reject",
            ProxyKind::Dns => "Dns",
            ProxyKind::Rematch => "Rematch",
        };
        types.insert(proxy.name.clone(), kind.to_owned());
    }
    types.extend(group_types.clone());
    types
}

pub(crate) fn expand_proxy_group(
    group: &ProxyGroupConfig,
    providers: &[ProxyProviderConfig],
    proxy_types: &BTreeMap<String, String>,
) -> Result<Vec<String>, ConfigError> {
    let filter_regexes = compile_group_regexes(group.filter.as_deref(), &group.name)?;
    let exclude_regexes = compile_group_regexes(group.exclude_filter.as_deref(), &group.name)?;
    let mut members = group.compatible_proxies.clone();
    let mut component_count = usize::from(!group.compatible_proxies.is_empty());

    for provider_name in &group.providers {
        let provider = providers
            .iter()
            .find(|provider| provider.name == *provider_name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(group.name.clone()))?;
        component_count += 1;
        if filter_regexes.is_empty() {
            members.extend(provider.proxies.iter().map(|proxy| proxy.name.clone()));
            continue;
        }
        let mut provider_members = BTreeSet::new();
        for pattern in &filter_regexes {
            for proxy in &provider.proxies {
                if group_regex_matches(pattern, &proxy.name) {
                    provider_members.insert(proxy.name.clone());
                }
            }
        }
        for pattern in &filter_regexes {
            for proxy in &provider.proxies {
                if group_regex_matches(pattern, &proxy.name) && provider_members.remove(&proxy.name)
                {
                    members.push(proxy.name.clone());
                }
            }
        }
    }

    if component_count > 1 && filter_regexes.len() > 1 {
        let original = std::mem::take(&mut members);
        let mut remaining: BTreeSet<_> = original.iter().cloned().collect();
        for pattern in &filter_regexes {
            for member in &original {
                if group_regex_matches(pattern, member) && remaining.remove(member) {
                    members.push(member.clone());
                }
            }
        }
        for member in original {
            if remaining.remove(&member) {
                members.push(member);
            }
        }
    }

    members.retain(|member| {
        !exclude_regexes
            .iter()
            .any(|pattern| group_regex_matches(pattern, member))
    });
    members.retain(|member| {
        proxy_types.get(member).is_none_or(|kind| {
            !group
                .exclude_types
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(kind))
        })
    });
    if members.is_empty() {
        members.push(group.empty_fallback.clone());
    }
    Ok(members)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_proxy_providers(
    providers: BTreeMap<String, RawProxyProvider>,
    config_directory: Option<&Path>,
    top_level: &[ProxyConfig],
) -> Result<Vec<ProxyProviderConfig>, ConfigError> {
    let mut names: BTreeSet<_> = top_level.iter().map(|proxy| proxy.name.clone()).collect();
    let mut parsed = Vec::new();
    for (name, provider) in providers {
        if name.is_empty() || !provider.extra.is_empty() {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        let transform = parse_proxy_provider_transform(&name, &provider)?;
        let health_check = parse_provider_health_check(&name, provider.health_check.as_ref())?;
        let (vehicle, url, path, cache_modified, etag, proxies) = match provider.kind.as_deref() {
            Some("inline") if provider.url.is_none() && provider.path.is_none() => (
                ProxyProviderVehicle::Inline,
                None,
                PathBuf::new(),
                Some(SystemTime::now()),
                None,
                parse_proxy_provider_records(
                    &name,
                    provider.payload.clone().unwrap_or_default(),
                    &transform,
                    config_directory,
                )?,
            ),
            Some("file") if provider.url.is_none() => {
                let directory =
                    config_directory.ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                let configured_path = provider
                    .path
                    .filter(|path| !path.is_empty())
                    .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                let path = directory.join(configured_path);
                (
                    ProxyProviderVehicle::File,
                    None,
                    path.clone(),
                    None,
                    None,
                    load_proxy_provider_file(&name, &path, &transform, config_directory)?,
                )
            }
            Some("http") => {
                let directory =
                    config_directory.ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                let url = provider
                    .url
                    .filter(|url| !url.is_empty())
                    .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                let parsed_url =
                    Url::parse(&url).map_err(|_| ConfigError::UnsupportedProxy(name.clone()))?;
                if !matches!(parsed_url.scheme(), "http" | "https")
                    || parsed_url.host_str().is_none()
                {
                    return Err(ConfigError::UnsupportedProxy(name));
                }
                let path = provider.path.filter(|path| !path.is_empty()).map_or_else(
                    || {
                        directory
                            .join("proxies")
                            .join(format!("{:x}", Md5::digest(url.as_bytes())))
                    },
                    |path| directory.join(path),
                );
                let (cache_modified, etag, cached) =
                    load_proxy_provider_file(&name, &path, &transform, config_directory)
                        .map(|proxies| {
                            let modified = std::fs::metadata(&path)
                                .and_then(|metadata| metadata.modified())
                                .ok();
                            let etag = load_provider_etag(&path, &url);
                            (modified, etag, proxies)
                        })
                        .unwrap_or_default();
                (
                    ProxyProviderVehicle::Http,
                    Some(url),
                    path,
                    cache_modified,
                    etag,
                    cached,
                )
            }
            _ => return Err(ConfigError::UnsupportedProxy(name)),
        };
        if proxies
            .iter()
            .any(|proxy| !names.insert(proxy.name.clone()))
        {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        parsed.push(ProxyProviderConfig {
            name,
            vehicle,
            path,
            url,
            interval: provider.interval.unwrap_or(0),
            headers: provider.header.unwrap_or_default(),
            size_limit: provider.size_limit.unwrap_or(0),
            etag,
            cache_modified,
            proxies,
            health_check,
            transform,
        });
    }
    Ok(parsed)
}

pub(crate) fn load_proxy_provider_file(
    name: &str,
    path: &Path,
    transform: &ProxyProviderTransform,
    home_directory: Option<&Path>,
) -> Result<Vec<ProxyConfig>, ConfigError> {
    let source = std::fs::read_to_string(path)?;
    parse_proxy_provider_source(name, &source, transform, home_directory)
}

pub(crate) fn load_provider_etag(path: &Path, url: &str) -> Option<String> {
    let payload = std::fs::read(path).ok()?;
    let cache = std::fs::read(provider_etag_path(path)).ok()?;
    let cache = serde_yaml_ng::from_slice::<ProviderEtagCache>(&cache).ok()?;
    (cache.url == url && cache.digest == format!("{:x}", Md5::digest(&payload)))
        .then_some(cache.etag)
}

/// Stores or clears durable HTTP provider `ETag` metadata tied to URL and bytes.
///
/// # Errors
///
/// Returns an I/O error when the sidecar cannot be atomically replaced.
pub fn persist_provider_etag(
    path: &Path,
    url: &str,
    payload: &[u8],
    etag: Option<&str>,
) -> std::io::Result<()> {
    let sidecar = provider_etag_path(path);
    let Some(etag) = etag.filter(|etag| !etag.is_empty()) else {
        match std::fs::remove_file(sidecar) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    };
    let source = serde_yaml_ng::to_string(&ProviderEtagCache {
        url: url.to_owned(),
        digest: format!("{:x}", Md5::digest(payload)),
        etag: etag.to_owned(),
    })
    .map_err(std::io::Error::other)?;
    let temporary = sidecar.with_extension("etag.tmp");
    std::fs::write(&temporary, source)?;
    std::fs::rename(temporary, sidecar)
}

fn provider_etag_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".etag");
    PathBuf::from(value)
}

pub(crate) fn parse_proxy_provider_source(
    name: &str,
    source: &str,
    transform: &ProxyProviderTransform,
    home_directory: Option<&Path>,
) -> Result<Vec<ProxyConfig>, ConfigError> {
    let file = serde_yaml_ng::from_str::<RawProxyProviderFile>(source)?;
    if !file.extra.is_empty() {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    parse_proxy_provider_records(
        name,
        file.proxies.unwrap_or_default(),
        transform,
        home_directory,
    )
}

fn parse_proxy_provider_records(
    name: &str,
    mut records: Vec<RawProxy>,
    transform: &ProxyProviderTransform,
    home_directory: Option<&Path>,
) -> Result<Vec<ProxyConfig>, ConfigError> {
    let filters = transform
        .filters
        .iter()
        .map(|pattern| fancy_regex::Regex::new(pattern))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ConfigError::UnsupportedProxy(name.to_owned()))?;
    let excludes = transform
        .exclude_filters
        .iter()
        .map(|pattern| fancy_regex::Regex::new(pattern))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ConfigError::UnsupportedProxy(name.to_owned()))?;
    records.retain(|record| {
        let Some(member_name) = record.name.as_deref() else {
            return false;
        };
        if record.kind.as_deref().is_some_and(|kind| {
            transform
                .exclude_types
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(kind))
        }) {
            return false;
        }
        if excludes
            .iter()
            .any(|pattern| group_regex_matches(pattern, member_name))
        {
            return false;
        }
        filters.is_empty()
            || filters
                .iter()
                .any(|pattern| group_regex_matches(pattern, member_name))
    });
    for record in &mut records {
        let Some(mut member_name) = record.name.take() else {
            continue;
        };
        for (pattern, target) in &transform.name_replacements {
            let pattern = regex::Regex::new(pattern)
                .map_err(|_| ConfigError::UnsupportedProxy(name.to_owned()))?;
            member_name = pattern.replace_all(&member_name, target).into_owned();
        }
        member_name = format!(
            "{}{}{}",
            transform.additional_prefix, member_name, transform.additional_suffix
        );
        record.name = Some(member_name);
    }
    let (rematches, proxies) = parse_proxies(records, true, home_directory)?;
    if !rematches.is_empty() || proxies.is_empty() {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    Ok(proxies)
}

fn parse_proxy_provider_transform(
    name: &str,
    provider: &RawProxyProvider,
) -> Result<ProxyProviderTransform, ConfigError> {
    let split = |value: Option<&String>| {
        value
            .into_iter()
            .flat_map(|value| value.split('`'))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let filters = split(provider.filter.as_ref());
    let exclude_filters = split(provider.exclude_filter.as_ref());
    let exclude_types = provider
        .exclude_type
        .as_deref()
        .into_iter()
        .flat_map(|value| value.split('|'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for pattern in filters.iter().chain(&exclude_filters) {
        fancy_regex::Regex::new(pattern)
            .map_err(|_| ConfigError::UnsupportedProxy(name.to_owned()))?;
    }
    let overrides = provider.overrides.as_ref();
    if overrides.is_some_and(|overrides| !overrides.extra.is_empty()) {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let mut name_replacements = Vec::new();
    for replacement in overrides
        .and_then(|overrides| overrides.proxy_name.as_ref())
        .into_iter()
        .flatten()
    {
        if !replacement.extra.is_empty() {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
        regex::Regex::new(&replacement.pattern)
            .map_err(|_| ConfigError::UnsupportedProxy(name.to_owned()))?;
        name_replacements.push((replacement.pattern.clone(), replacement.target.clone()));
    }
    Ok(ProxyProviderTransform {
        filters,
        exclude_filters,
        exclude_types,
        additional_prefix: overrides
            .and_then(|overrides| overrides.additional_prefix.clone())
            .unwrap_or_default(),
        additional_suffix: overrides
            .and_then(|overrides| overrides.additional_suffix.clone())
            .unwrap_or_default(),
        name_replacements,
    })
}

fn parse_provider_health_check(
    name: &str,
    raw: Option<&RawProviderHealthCheck>,
) -> Result<ProviderHealthConfig, ConfigError> {
    if raw.is_some_and(|raw| !raw.extra.is_empty()) {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let enabled = raw.and_then(|raw| raw.enable).unwrap_or(false);
    let url = raw
        .and_then(|raw| raw.url.clone())
        .unwrap_or_default()
        .trim()
        .to_owned();
    if enabled && !url.is_empty() {
        let parsed =
            Url::parse(&url).map_err(|_| ConfigError::UnsupportedProxy(name.to_owned()))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
    }
    Ok(ProviderHealthConfig {
        enabled: enabled && !url.is_empty(),
        url,
        expected_status: raw
            .and_then(|raw| raw.expected_status.clone())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "*".to_owned()),
        interval: if enabled {
            raw.and_then(|raw| raw.interval).unwrap_or(300).max(1)
        } else {
            0
        },
        timeout: raw.and_then(|raw| raw.timeout).unwrap_or(5_000).max(1),
        lazy: raw.and_then(|raw| raw.lazy).unwrap_or(true),
    })
}
