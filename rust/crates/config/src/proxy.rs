use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use md5::{Digest, Md5};
use rewrite_rules::RematchSpec;
use url::Url;

use crate::error::ConfigError;
use crate::load::resolve_controller_pem;
use crate::model::{
    GroupHealthConfig, LoadBalanceStrategy, ProviderHealthConfig, ProxyConfig, ProxyGroupConfig,
    ProxyGroupKind, ProxyKind, ProxyProviderConfig, ProxyProviderTransform, ProxyProviderVehicle,
};
use crate::raw::{
    ProviderEtagCache, RawProviderHealthCheck, RawProxy, RawProxyGroup, RawProxyProvider,
    RawProxyProviderFile,
};

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
            Some("ss") => {
                outbounds.push(parse_shadowsocks_proxy(name, proxy)?);
            }
            Some("ssr") => {
                outbounds.push(parse_shadowsocksr_proxy(name, proxy)?);
            }
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
        udp: proxy.udp.unwrap_or(false),
        headers: proxy.headers.unwrap_or_default(),
        cipher: None,
        plugin: None,
        udp_over_tcp: false,
        obfs: None,
        obfs_param: None,
        protocol: None,
        protocol_param: None,
    })
}

fn parse_shadowsocks_proxy(name: String, proxy: RawProxy) -> Result<ProxyConfig, ConfigError> {
    if proxy.target_rematch_name.is_some()
        || proxy.target_sub_rule.is_some()
        || proxy.username.is_some()
        || proxy.tls.is_some()
        || proxy.sni.is_some()
        || proxy.skip_cert_verify.is_some()
        || proxy.name_cert_verify.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some()
        || proxy.headers.is_some()
        || proxy.obfs.is_some()
        || proxy.obfs_param.is_some()
        || proxy.protocol.is_some()
        || proxy.protocol_param.is_some()
        || proxy.plugin.is_some()
        || proxy.udp_over_tcp.is_some()
        || proxy.udp_over_tcp_version.is_some()
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
    let password = proxy
        .password
        .filter(|password| !password.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let cipher = proxy
        .cipher
        .filter(|cipher| !cipher.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    if !is_supported_shadowsocks_cipher(&cipher) {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    Ok(ProxyConfig {
        name,
        kind: ProxyKind::Shadowsocks,
        server,
        port,
        username: None,
        password: Some(password),
        tls: false,
        sni: None,
        skip_cert_verify: false,
        name_cert_verify: None,
        fingerprint: None,
        certificate: None,
        private_key: None,
        udp: proxy.udp.unwrap_or(false),
        headers: BTreeMap::new(),
        cipher: Some(cipher),
        plugin: None,
        udp_over_tcp: false,
        obfs: None,
        obfs_param: None,
        protocol: None,
        protocol_param: None,
    })
}

fn parse_shadowsocksr_proxy(name: String, proxy: RawProxy) -> Result<ProxyConfig, ConfigError> {
    if proxy.target_rematch_name.is_some()
        || proxy.target_sub_rule.is_some()
        || proxy.username.is_some()
        || proxy.tls.is_some()
        || proxy.sni.is_some()
        || proxy.skip_cert_verify.is_some()
        || proxy.name_cert_verify.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some()
        || proxy.headers.is_some()
        || proxy.plugin.is_some()
        || proxy.udp_over_tcp.is_some()
        || proxy.udp_over_tcp_version.is_some()
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
    let password = proxy
        .password
        .filter(|password| !password.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let mut cipher = proxy
        .cipher
        .filter(|cipher| !cipher.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    if cipher.eq_ignore_ascii_case("none") {
        "dummy".clone_into(&mut cipher);
    }
    if !is_supported_shadowsocksr_cipher(&cipher) {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    let obfs = proxy
        .obfs
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    let protocol = proxy
        .protocol
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    if !is_supported_shadowsocksr_obfs(&obfs) || !is_supported_shadowsocksr_protocol(&protocol) {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    Ok(ProxyConfig {
        name,
        kind: ProxyKind::ShadowsocksR,
        server,
        port,
        username: None,
        password: Some(password),
        tls: false,
        sni: None,
        skip_cert_verify: false,
        name_cert_verify: None,
        fingerprint: None,
        certificate: None,
        private_key: None,
        udp: proxy.udp.unwrap_or(false),
        headers: BTreeMap::new(),
        cipher: Some(cipher),
        plugin: None,
        udp_over_tcp: false,
        obfs: Some(obfs),
        obfs_param: proxy.obfs_param,
        protocol: Some(protocol),
        protocol_param: proxy.protocol_param,
    })
}

fn is_supported_shadowsocks_cipher(cipher: &str) -> bool {
    matches!(
        cipher.to_ascii_lowercase().as_str(),
        "aes-128-gcm"
            | "aes-192-gcm"
            | "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "xchacha20-ietf-poly1305"
            | "aes-128-cfb"
            | "aes-192-cfb"
            | "aes-256-cfb"
            | "aes-128-ctr"
            | "aes-192-ctr"
            | "aes-256-ctr"
            | "rc4-md5"
            | "chacha20-ietf"
            | "chacha20"
            | "xchacha20"
    )
}

fn is_supported_shadowsocksr_cipher(cipher: &str) -> bool {
    matches!(
        cipher.to_ascii_lowercase().as_str(),
        "dummy"
            | "aes-128-cfb"
            | "aes-192-cfb"
            | "aes-256-cfb"
            | "aes-128-ctr"
            | "aes-192-ctr"
            | "aes-256-ctr"
            | "rc4-md5"
            | "chacha20-ietf"
            | "chacha20"
            | "xchacha20"
    )
}

fn is_supported_shadowsocksr_obfs(obfs: &str) -> bool {
    matches!(
        obfs,
        "plain"
            | "random_head"
            | "http_simple"
            | "http_post"
            | "tls1.2_ticket_auth"
            | "tls1.2_ticket_fastauth"
    )
}

fn is_supported_shadowsocksr_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        "origin"
            | "auth_sha1_v4"
            | "auth_aes128_md5"
            | "auth_aes128_sha1"
            | "auth_chain_a"
            | "auth_chain_b"
    )
}

fn proxy_has_transport_fields(proxy: &RawProxy) -> bool {
    proxy.server.is_some()
        || proxy.port.is_some()
        || proxy.username.is_some()
        || proxy.password.is_some()
        || proxy.tls.is_some()
        || proxy.udp.is_some()
        || proxy.sni.is_some()
        || proxy.skip_cert_verify.is_some()
        || proxy.name_cert_verify.is_some()
        || proxy.fingerprint.is_some()
        || proxy.certificate.is_some()
        || proxy.private_key.is_some()
        || proxy.headers.is_some()
        || proxy.cipher.is_some()
        || proxy.plugin.is_some()
        || proxy.udp_over_tcp.is_some()
        || proxy.udp_over_tcp_version.is_some()
        || proxy.obfs.is_some()
        || proxy.obfs_param.is_some()
        || proxy.protocol.is_some()
        || proxy.protocol_param.is_some()
}

fn simple_proxy(name: String, kind: ProxyKind) -> ProxyConfig {
    ProxyConfig {
        name,
        kind,
        server: String::new(),
        port: 0,
        username: None,
        password: None,
        tls: false,
        sni: None,
        skip_cert_verify: false,
        name_cert_verify: None,
        fingerprint: None,
        certificate: None,
        private_key: None,
        udp: true,
        headers: BTreeMap::new(),
        cipher: None,
        plugin: None,
        udp_over_tcp: false,
        obfs: None,
        obfs_param: None,
        protocol: None,
        protocol_param: None,
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
            ProxyKind::ShadowsocksR => "ShadowsocksR",
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
