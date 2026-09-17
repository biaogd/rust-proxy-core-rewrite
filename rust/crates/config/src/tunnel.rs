//! Top-level `tunnels:` static inbound parsing (CFG-10 / IN-05).

use std::net::{IpAddr, SocketAddr};

use rewrite_model::{Destination, Host};
use serde_yaml_ng::{Mapping, Value};

use crate::error::ConfigError;
use crate::model::{TunnelInboundConfig, TunnelNetwork};

/// Parses Go `tunnels:` (one-liner or mapping). Expands each entry into one
/// config per network (`tcp` / `udp`).
pub(crate) fn parse_tunnels(
    raw: Option<Vec<Value>>,
    proxy_names: &std::collections::BTreeSet<String>,
) -> Result<Vec<TunnelInboundConfig>, ConfigError> {
    let Some(entries) = raw else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (index, value) in entries.into_iter().enumerate() {
        out.extend(parse_tunnel_entry(value, index, proxy_names)?);
    }
    Ok(out)
}

fn parse_tunnel_entry(
    value: Value,
    index: usize,
    proxy_names: &std::collections::BTreeSet<String>,
) -> Result<Vec<TunnelInboundConfig>, ConfigError> {
    match value {
        Value::String(line) => parse_tunnel_one_liner(&line, index, proxy_names),
        Value::Mapping(mapping) => parse_tunnel_mapping(mapping, index, proxy_names),
        _ => Err(ConfigError::InvalidInbound(format!(
            "tunnel {index} must be a string or mapping"
        ))),
    }
}

fn parse_tunnel_one_liner(
    line: &str,
    index: usize,
    proxy_names: &std::collections::BTreeSet<String>,
) -> Result<Vec<TunnelInboundConfig>, ConfigError> {
    let parts: Vec<_> = line.split(',').map(str::trim).collect();
    if parts.len() != 3 && parts.len() != 4 {
        return Err(ConfigError::InvalidInbound(format!(
            "invalid tunnel config {line}"
        )));
    }
    let networks = parse_networks(parts[0], index)?;
    let listen = parse_listen_addr(parts[1], index)?;
    let target = parse_target(parts[2], index)?;
    let proxy = parts.get(3).map(|value| (*value).to_owned()).unwrap_or_default();
    validate_proxy(&proxy, proxy_names, index)?;
    Ok(expand(networks, listen, target, proxy))
}

fn parse_tunnel_mapping(
    mapping: Mapping,
    index: usize,
    proxy_names: &std::collections::BTreeSet<String>,
) -> Result<Vec<TunnelInboundConfig>, ConfigError> {
    let network_value = mapping
        .get(Value::String("network".to_owned()))
        .ok_or_else(|| ConfigError::InvalidInbound(format!("tunnel {index} missing network")))?;
    let networks = match network_value {
        Value::String(value) => parse_networks(value, index)?,
        Value::Sequence(values) => {
            let mut networks = Vec::new();
            for value in values {
                let Some(name) = value.as_str() else {
                    return Err(ConfigError::InvalidInbound(format!(
                        "tunnel {index} network entries must be strings"
                    )));
                };
                networks.extend(parse_networks(name, index)?);
            }
            dedupe_networks(networks)
        }
        _ => {
            return Err(ConfigError::InvalidInbound(format!(
                "tunnel {index} network must be a string or sequence"
            )));
        }
    };
    let address = mapping_string(&mapping, "address").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("tunnel {index} missing address"))
    })?;
    let target_raw = mapping_string(&mapping, "target").ok_or_else(|| {
        ConfigError::InvalidInbound(format!("tunnel {index} missing target"))
    })?;
    let proxy = mapping_string(&mapping, "proxy").unwrap_or_default();
    let listen = parse_listen_addr(&address, index)?;
    let target = parse_target(&target_raw, index)?;
    validate_proxy(&proxy, proxy_names, index)?;
    Ok(expand(networks, listen, target, proxy))
}

fn expand(
    networks: Vec<TunnelNetwork>,
    listen: SocketAddr,
    target: Destination,
    proxy: String,
) -> Vec<TunnelInboundConfig> {
    networks
        .into_iter()
        .map(|network| TunnelInboundConfig {
            listen,
            target: target.clone(),
            network,
            proxy: proxy.clone(),
        })
        .collect()
}

fn parse_networks(value: &str, index: usize) -> Result<Vec<TunnelNetwork>, ConfigError> {
    let mut networks = Vec::new();
    for part in value.split('/') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part {
            "tcp" => networks.push(TunnelNetwork::Tcp),
            "udp" => networks.push(TunnelNetwork::Udp),
            other => {
                return Err(ConfigError::InvalidInbound(format!(
                    "invalid tunnel network {other} (tunnel {index})"
                )));
            }
        }
    }
    if networks.is_empty() {
        return Err(ConfigError::InvalidInbound(format!(
            "tunnel {index} has empty network"
        )));
    }
    Ok(dedupe_networks(networks))
}

fn dedupe_networks(networks: Vec<TunnelNetwork>) -> Vec<TunnelNetwork> {
    let mut out = Vec::new();
    for network in networks {
        if !out.contains(&network) {
            out.push(network);
        }
    }
    out
}

fn parse_listen_addr(value: &str, index: usize) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::InvalidInbound(format!(
            "invalid tunnel address {value} (tunnel {index})"
        ))
    })
}

fn parse_target(value: &str, index: usize) -> Result<Destination, ConfigError> {
    let (host, port) = split_host_port(value).ok_or_else(|| {
        ConfigError::InvalidInbound(format!(
            "invalid tunnel target {value} (tunnel {index})"
        ))
    })?;
    Ok(Destination { host, port })
}

fn split_host_port(value: &str) -> Option<(Host, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let ip: IpAddr = host.parse().ok()?;
        let port: u16 = port.parse().ok()?;
        return Some((Host::Ip(ip), port));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.contains(':') {
        // Unbracketed IPv6 is invalid for host:port.
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        Some((Host::Ip(ip), port))
    } else if host.is_empty() {
        None
    } else {
        Some((Host::Domain(host.to_owned()), port))
    }
}

fn validate_proxy(
    proxy: &str,
    proxy_names: &std::collections::BTreeSet<String>,
    index: usize,
) -> Result<(), ConfigError> {
    if proxy.is_empty() {
        return Ok(());
    }
    if proxy_names.contains(proxy) || matches!(proxy, "DIRECT" | "REJECT" | "REJECT-DROP") {
        return Ok(());
    }
    Err(ConfigError::InvalidInbound(format!(
        "tunnel proxy {proxy} not found (tunnel {index})"
    )))
}

fn mapping_string(mapping: &Mapping, key: &str) -> Option<String> {
    mapping
        .get(Value::String(key.to_owned()))
        .and_then(Value::as_str)
        .map(str::to_owned)
}
