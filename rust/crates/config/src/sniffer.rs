//! Top-level `sniffer:` parsing (CFG-16 / RUN-04).

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::ConfigError;
use crate::model::{
    SniffProtocol, SnifferConfig, SnifferDomainMatcher, SnifferProtocolConfig,
};
use crate::raw::{RawSniffer, RawSniffingConfig};

/// Parses Go `sniffer:` with defaults matching `DefaultRawConfig`.
pub(crate) fn parse_sniffer(raw: Option<RawSniffer>) -> Result<SnifferConfig, ConfigError> {
    let Some(raw) = raw else {
        return Ok(SnifferConfig::disabled());
    };
    if let Some(key) = raw.extra.keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("sniffer.{key}")));
    }

    let enable = raw.enable.unwrap_or(false);
    let override_destination = raw.override_destination.unwrap_or(true);
    let force_dns_mapping = raw.force_dns_mapping.unwrap_or(true);
    let parse_pure_ip = raw.parse_pure_ip.unwrap_or(true);

    let mut protocols = BTreeMap::new();
    if let Some(sniff) = raw.sniff {
        for (name, entry) in sniff {
            let protocol = parse_protocol_name(&name)?;
            protocols.insert(protocol, parse_protocol_entry(entry, override_destination)?);
        }
    } else if enable {
        let global_ports = parse_port_list(raw.port_whitelist.unwrap_or_default())?;
        for name in raw.sniffing.unwrap_or_default() {
            let protocol = parse_protocol_name(&name)?;
            protocols.insert(
                protocol,
                SnifferProtocolConfig {
                    ports: global_ports.clone(),
                    override_destination,
                },
            );
        }
    }

    Ok(SnifferConfig {
        enable,
        force_dns_mapping,
        parse_pure_ip,
        protocols,
        force_domain: parse_domain_matchers(raw.force_domain.unwrap_or_default(), "force-domain")?,
        skip_domain: parse_domain_matchers(raw.skip_domain.unwrap_or_default(), "skip-domain")?,
        skip_src_address: parse_ip_matchers(
            raw.skip_src_address.unwrap_or_default(),
            "skip-src-address",
        )?,
        skip_dst_address: parse_ip_matchers(
            raw.skip_dst_address.unwrap_or_default(),
            "skip-dst-address",
        )?,
    })
}

fn parse_protocol_name(name: &str) -> Result<SniffProtocol, ConfigError> {
    match name.to_ascii_uppercase().as_str() {
        "TLS" => Ok(SniffProtocol::Tls),
        "HTTP" => Ok(SniffProtocol::Http),
        "QUIC" => Ok(SniffProtocol::Quic),
        other => Err(ConfigError::InvalidInbound(format!(
            "not find the sniffer[{other}]"
        ))),
    }
}

fn parse_protocol_entry(
    entry: RawSniffingConfig,
    global_override: bool,
) -> Result<SnifferProtocolConfig, ConfigError> {
    let ports = parse_port_list(entry.ports.unwrap_or_default())?;
    Ok(SnifferProtocolConfig {
        ports,
        override_destination: entry.override_destination.unwrap_or(global_override),
    })
}

fn parse_port_list(values: Vec<String>) -> Result<Vec<(u16, u16)>, ConfigError> {
    let mut ranges = Vec::new();
    for value in values {
        ranges.push(parse_port_range(&value)?);
    }
    Ok(ranges)
}

fn parse_port_range(value: &str) -> Result<(u16, u16), ConfigError> {
    let value = value.trim();
    if let Some((start, end)) = value.split_once('-') {
        let start: u16 = start.trim().parse().map_err(|_| {
            ConfigError::InvalidInbound(format!("invalid sniffer port range {value}"))
        })?;
        let end: u16 = end.trim().parse().map_err(|_| {
            ConfigError::InvalidInbound(format!("invalid sniffer port range {value}"))
        })?;
        if start == 0 || end == 0 || start > end {
            return Err(ConfigError::InvalidInbound(format!(
                "invalid sniffer port range {value}"
            )));
        }
        return Ok((start, end));
    }
    let port: u16 = value
        .parse()
        .map_err(|_| ConfigError::InvalidInbound(format!("invalid sniffer port {value}")))?;
    if port == 0 {
        return Err(ConfigError::InvalidInbound(format!(
            "invalid sniffer port {value}"
        )));
    }
    Ok((port, port))
}

fn parse_domain_matchers(
    values: Vec<String>,
    field: &str,
) -> Result<Vec<SnifferDomainMatcher>, ConfigError> {
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("rule-set:") || lower.starts_with("geosite:") {
            return Err(ConfigError::UnsupportedKey(format!(
                "sniffer.{field} provider refs"
            )));
        }
        if let Some(suffix) = lower.strip_prefix("+.") {
            if suffix.is_empty() {
                return Err(ConfigError::InvalidInbound(format!(
                    "invalid sniffer.{field} entry {trimmed}"
                )));
            }
            out.push(SnifferDomainMatcher::Suffix(suffix.to_owned()));
        } else if lower.contains('*') {
            out.push(SnifferDomainMatcher::Wildcard(lower));
        } else {
            out.push(SnifferDomainMatcher::Exact(lower));
        }
    }
    Ok(out)
}

fn parse_ip_matchers(values: Vec<String>, field: &str) -> Result<Vec<IpNet>, ConfigError> {
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("geoip:") || lower.starts_with("rule-set:") {
            return Err(ConfigError::UnsupportedKey(format!(
                "sniffer.{field} provider refs"
            )));
        }
        if let Ok(net) = trimmed.parse::<IpNet>() {
            out.push(net);
            continue;
        }
        if let Ok(addr) = trimmed.parse::<IpAddr>() {
            out.push(IpNet::from(addr));
            continue;
        }
        return Err(ConfigError::InvalidInbound(format!(
            "error in {field}, invalid address {trimmed}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_absent() {
        let config = parse_sniffer(None).expect("absent");
        assert!(!config.enable);
        assert!(config.protocols.is_empty());
    }

    #[test]
    fn parses_sniff_map_with_ports() {
        let raw = RawSniffer {
            enable: Some(true),
            override_destination: Some(false),
            sniff: Some(BTreeMap::from([(
                "TLS".to_owned(),
                RawSniffingConfig {
                    ports: Some(vec!["443".to_owned(), "8443".to_owned()]),
                    override_destination: Some(true),
                },
            )])),
            ..RawSniffer::default()
        };
        let config = parse_sniffer(Some(raw)).expect("sniff map");
        assert!(config.enable);
        let tls = config.protocols.get(&SniffProtocol::Tls).expect("tls");
        assert!(tls.override_destination);
        assert_eq!(tls.ports, vec![(443, 443), (8443, 8443)]);
        assert!(config.force_dns_mapping);
        assert!(config.parse_pure_ip);
    }
}
