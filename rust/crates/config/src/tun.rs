use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use crate::error::ConfigError;
use crate::model::{DnsConfig, TunConfig, TunStack};
use crate::raw::RawTun;

const DEFAULT_INET4: &str = "198.18.0.1/30";
const DEFAULT_DNS_HIJACK: &str = "0.0.0.0:53";

pub(crate) fn parse_tun(
    raw: Option<RawTun>,
    dns: Option<&DnsConfig>,
    ipv6: bool,
) -> Result<Option<TunConfig>, ConfigError> {
    let Some(mut raw) = raw else {
        return Ok(None);
    };
    if let Some(key) = raw.extra.keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("tun.{key}")));
    }

    let enable = raw.enable.unwrap_or(false);
    let stack = parse_stack(raw.stack.take())?;
    reject_deferred_fields(&raw)?;

    if raw.file_descriptor.unwrap_or(0) != 0 {
        return Err(ConfigError::UnsupportedRuntime(
            "tun.file-descriptor is reserved for later mobile/host-handle gates".to_owned(),
        ));
    }

    let mut inet4_address = parse_prefixes(raw.inet4_address.take(), "tun.inet4-address")?;
    if inet4_address.is_empty() {
        inet4_address.push(default_inet4_prefix(dns)?);
    }
    let inet6_address = parse_prefixes(raw.inet6_address.take(), "tun.inet6-address")?;
    if !ipv6 && !inet6_address.is_empty() {
        return Err(ConfigError::UnsupportedRuntime(
            "tun.inet6-address requires ipv6: true; refusing a silent IPv6 leak".to_owned(),
        ));
    }
    let route_address = parse_prefixes(raw.route_address.take(), "tun.route-address")?;
    let route_exclude_address = parse_prefixes(
        raw.route_exclude_address.take(),
        "tun.route-exclude-address",
    )?;
    let inet4_route_address =
        parse_prefixes(raw.inet4_route_address.take(), "tun.inet4-route-address")?;
    let inet6_route_address =
        parse_prefixes(raw.inet6_route_address.take(), "tun.inet6-route-address")?;
    let inet4_route_exclude_address = parse_prefixes(
        raw.inet4_route_exclude_address.take(),
        "tun.inet4-route-exclude-address",
    )?;
    let inet6_route_exclude_address = parse_prefixes(
        raw.inet6_route_exclude_address.take(),
        "tun.inet6-route-exclude-address",
    )?;

    let dns_hijack = match raw.dns_hijack.take() {
        Some(values) if !values.is_empty() => values,
        _ => vec![DEFAULT_DNS_HIJACK.to_owned()],
    };
    for value in &dns_hijack {
        validate_dns_hijack(value)?;
    }

    let mtu = raw.mtu.unwrap_or(0);
    if mtu < 0 {
        return Err(ConfigError::InvalidTun(format!(
            "tun.mtu out of range: {mtu}"
        )));
    }

    let file_descriptor = raw.file_descriptor.unwrap_or(0);
    if file_descriptor < 0 {
        return Err(ConfigError::InvalidTun(format!(
            "tun.file-descriptor out of range: {file_descriptor}"
        )));
    }

    Ok(Some(TunConfig {
        enable,
        device: raw.device.unwrap_or_default(),
        stack,
        dns_hijack,
        auto_route: raw.auto_route.unwrap_or(false),
        auto_detect_interface: raw.auto_detect_interface.unwrap_or(false),
        mtu: u32::try_from(mtu)
            .map_err(|_| ConfigError::InvalidTun(format!("tun.mtu out of range: {mtu}")))?,
        inet4_address,
        inet6_address,
        route_address,
        route_exclude_address,
        inet4_route_address,
        inet6_route_address,
        inet4_route_exclude_address,
        inet6_route_exclude_address,
        strict_route: raw.strict_route.unwrap_or(false),
        endpoint_independent_nat: raw.endpoint_independent_nat.unwrap_or(false),
        udp_timeout: raw.udp_timeout.unwrap_or(0),
        file_descriptor,
        disable_icmp_forwarding: raw.disable_icmp_forwarding.unwrap_or(false),
    }))
}

fn parse_stack(raw: Option<String>) -> Result<TunStack, ConfigError> {
    let Some(value) = raw.filter(|value| !value.trim().is_empty()) else {
        // Disabled TUN may omit stack; enabled TUN defaults to the Rust stack.
        return Ok(TunStack::Smoltcp);
    };
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "smoltcp" => Ok(TunStack::Smoltcp),
        "system" | "gvisor" | "mixed" => Err(ConfigError::UnsupportedRuntime(format!(
            "tun.stack `{value}` is a Go stack name; Rust accepts only `smoltcp` and does not remap system/gvisor/mixed"
        ))),
        _ => Err(ConfigError::InvalidTun(format!(
            "invalid tun stack: {value}"
        ))),
    }
}

#[allow(clippy::too_many_lines)]
fn reject_deferred_fields(raw: &RawTun) -> Result<(), ConfigError> {
    let deferred = [
        (raw.gso == Some(true), "tun.gso"),
        (
            raw.gso_max_size.is_some_and(|value| value != 0),
            "tun.gso-max-size",
        ),
        (raw.auto_redirect == Some(true), "tun.auto-redirect"),
        (
            raw.auto_redirect_input_mark.is_some_and(|value| value != 0),
            "tun.auto-redirect-input-mark",
        ),
        (
            raw.auto_redirect_output_mark
                .is_some_and(|value| value != 0),
            "tun.auto-redirect-output-mark",
        ),
        (
            raw.route_address_set
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.route-address-set",
        ),
        (
            raw.route_exclude_address_set
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.route-exclude-address-set",
        ),
        (
            raw.include_uid
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.include-uid",
        ),
        (
            raw.exclude_uid
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-uid",
        ),
        (
            raw.include_uid_range
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.include-uid-range",
        ),
        (
            raw.exclude_uid_range
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-uid-range",
        ),
        (
            raw.include_package
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.include-package",
        ),
        (
            raw.exclude_package
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-package",
        ),
        (
            raw.include_android_user
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.include-android-user",
        ),
        (
            raw.include_interface
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.include-interface",
        ),
        (
            raw.exclude_interface
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-interface",
        ),
        (
            raw.include_mac_address
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.include-mac-address",
        ),
        (
            raw.exclude_mac_address
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-mac-address",
        ),
        (
            raw.exclude_src_port
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-src-port",
        ),
        (
            raw.exclude_dst_port
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-dst-port",
        ),
        (
            raw.exclude_src_port_range
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-src-port-range",
        ),
        (
            raw.exclude_dst_port_range
                .as_ref()
                .is_some_and(|values| !values.is_empty()),
            "tun.exclude-dst-port-range",
        ),
        (raw.recvmsgx == Some(true), "tun.recvmsgx"),
        (raw.sendmsgx == Some(true), "tun.sendmsgx"),
        (raw.strict_route == Some(true), "tun.strict-route"),
        (
            raw.endpoint_independent_nat == Some(true),
            "tun.endpoint-independent-nat",
        ),
        (
            raw.udp_timeout.is_some_and(|value| value != 0),
            "tun.udp-timeout",
        ),
        (
            raw.disable_icmp_forwarding == Some(true),
            "tun.disable-icmp-forwarding",
        ),
    ];
    if let Some((_, field)) = deferred.into_iter().find(|(active, _)| *active) {
        return Err(ConfigError::UnsupportedRuntime(format!(
            "{field} is outside the Phase 8A TUN surface"
        )));
    }
    Ok(())
}

fn default_inet4_prefix(dns: Option<&DnsConfig>) -> Result<IpNet, ConfigError> {
    if let Some(range) = dns
        .and_then(|config| config.fake_ip.as_ref())
        .and_then(|fake| fake.ipv4_range)
    {
        let truncated = IpNet::new(range.network(), 30).map_err(|error| {
            ConfigError::InvalidTun(format!("derived tun inet4-address invalid: {error}"))
        })?;
        // Prefer the configured fake-IP base address when it sits in the /30.
        let preferred = IpNet::new(range.addr(), 30).unwrap_or(truncated);
        return Ok(preferred);
    }
    IpNet::from_str(DEFAULT_INET4)
        .map_err(|error| ConfigError::InvalidTun(format!("default tun inet4-address: {error}")))
}

fn parse_prefixes(values: Option<Vec<String>>, field: &str) -> Result<Vec<IpNet>, ConfigError> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    values
        .into_iter()
        .map(|value| {
            IpNet::from_str(value.trim()).map_err(|error| {
                ConfigError::InvalidTun(format!("{field} `{value}` invalid: {error}"))
            })
        })
        .collect()
}

fn validate_dns_hijack(value: &str) -> Result<(), ConfigError> {
    if value.eq_ignore_ascii_case("any") || value == "::" {
        return Ok(());
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        let _ = address;
        return Ok(());
    }
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(());
    }
    // Go accepts host:port forms such as 0.0.0.0:53 even when the host is not a
    // unicast destination; keep the same permissive parse for the 8A surface.
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && port.parse::<u16>().is_ok()
    {
        return Ok(());
    }
    Err(ConfigError::InvalidTun(format!(
        "invalid tun.dns-hijack entry: {value}"
    )))
}
