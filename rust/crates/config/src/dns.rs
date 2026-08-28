use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ipnet::IpNet;
use md5::{Digest, Md5};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use prost::Message;
use regex::Regex;
use rewrite_rules::{ProviderBehavior, ProviderDefinition};
use serde_yaml_ng::{Mapping, Value};
use url::Url;

use crate::error::ConfigError;
use crate::model::{
    DnsCacheAlgorithm, DnsClassicEndpoint, DnsClassicUpstream, DnsConfig, DnsDirectConfig,
    DnsFallbackConfig, DnsGeoIpFilter, DnsMainKind, DnsMode, DnsPolicy, DnsPolicyMatcher,
    DnsQueryOptions, DnsResolverClient, DnsTlsConfig, DnsTransport, DnsUpstream, DohProtocol,
    EcsConfig, FakeIpConfig, FakeIpFilterMode, FakeIpRule, FakeIpRuleAction, FakeIpRuleMatcher,
    GeositeDomain, GeositeDomainKind, HostEntry, HostTable, RuleProviderConfig, RuleProviderFormat,
    RuleProviderVehicle, RuleSetDomain, RuleSetDomainKind, SyntheticRcode,
};
use crate::proxy::load_provider_etag;
use crate::raw::{RawDns, RawHostValue, RawRuleProvider, RawRuleProviderFile};

pub(crate) fn parse_dns(
    raw: Option<RawDns>,
    trust_certificates: &[String],
    rule_providers: &BTreeMap<String, RuleProviderConfig>,
    config_directory: Option<&Path>,
    geodata_mode: bool,
) -> Result<Option<DnsConfig>, ConfigError> {
    let Some(mut raw) = raw else {
        return Ok(None);
    };
    if !raw.enable.unwrap_or(false) {
        return Ok(None);
    }
    if let Some(key) = raw.extra.keys().next() {
        return Err(ConfigError::InvalidDns(format!(
            "unsupported field dns.{key}"
        )));
    }
    let ipv6 = raw.ipv6.unwrap_or(false);
    let ipv6_timeout = match raw.ipv6_timeout.unwrap_or(100) {
        value if value < 0 => {
            return Err(ConfigError::InvalidDns(
                "dns.ipv6-timeout must be non-negative".to_owned(),
            ));
        }
        0 => std::time::Duration::from_millis(100),
        value => std::time::Duration::from_millis(
            u64::try_from(value).expect("positive IPv6 timeout fits u64"),
        ),
    };
    let (cache_algorithm, cache_max_size) = parse_dns_cache(&raw)?;
    let use_hosts = raw.use_hosts.unwrap_or(true);
    let use_system_hosts = raw.use_system_hosts.unwrap_or(true);
    let mode = match raw.enhanced_mode.as_deref().unwrap_or("redir-host") {
        "redir-host" => DnsMode::RedirHost,
        "fake-ip" => DnsMode::FakeIp,
        _ => {
            return Err(ConfigError::InvalidDns(
                "dns.enhanced-mode must be redir-host or fake-ip".to_owned(),
            ));
        }
    };

    let fake_ip = parse_fake_ip_config(&mut raw, mode, rule_providers, config_directory)?;

    let listen_text = raw
        .listen
        .take()
        .ok_or_else(|| ConfigError::InvalidDns("dns.listen is required".to_owned()))?;
    let listen = parse_loopback_dns_addr(&listen_text, "dns.listen")?;
    let resolver_sets =
        parse_dns_resolver_sets(&mut raw, trust_certificates, config_directory, geodata_mode)?;
    let policies = parse_dns_policies(
        raw.nameserver_policy.take().unwrap_or_default(),
        "dns.nameserver-policy",
        &resolver_sets.default_nameservers,
        raw.prefer_h3.unwrap_or(false),
        trust_certificates,
        rule_providers,
        config_directory,
    )?;
    let proxy_policies = parse_dns_policies(
        raw.proxy_server_nameserver_policy
            .take()
            .unwrap_or_default(),
        "dns.proxy-server-nameserver-policy",
        &resolver_sets.default_nameservers,
        raw.prefer_h3.unwrap_or(false),
        trust_certificates,
        rule_providers,
        config_directory,
    )?;
    if !proxy_policies.is_empty() && resolver_sets.proxy_resolvers.is_empty() {
        return Err(ConfigError::InvalidDns(
            "disallow empty dns.proxy-server-nameserver when proxy-server-nameserver-policy is set"
                .to_owned(),
        ));
    }
    let main = resolver_sets.main;
    Ok(Some(DnsConfig {
        listen,
        upstream: main.upstream,
        transport: main.transport,
        main_kind: main.main_kind,
        classic_upstreams: main.classic_upstreams,
        main_resolvers: resolver_sets.main_resolvers,
        default_resolvers: resolver_sets.default_resolvers,
        proxy_resolvers: resolver_sets.proxy_resolvers,
        ipv6,
        ipv6_timeout,
        cache_algorithm,
        cache_max_size,
        use_hosts,
        use_system_hosts,
        mode,
        fake_ip,
        policies,
        proxy_policies,
        fallback: resolver_sets.fallback,
        direct: resolver_sets.direct,
        tls: main.tls,
        query_options: main.query_options,
    }))
}

fn parse_dns_cache(raw: &RawDns) -> Result<(DnsCacheAlgorithm, usize), ConfigError> {
    let algorithm = match raw.cache_algorithm.as_deref() {
        Some("arc") => DnsCacheAlgorithm::Arc,
        _ => DnsCacheAlgorithm::Lru,
    };
    let max_size = match raw.cache_max_size.unwrap_or(0) {
        0 => 4096,
        value if value > 0 => usize::try_from(value)
            .map_err(|_| ConfigError::InvalidDns("dns.cache-max-size is too large".to_owned()))?,
        _ => usize::MAX,
    };
    Ok((algorithm, max_size))
}

struct ParsedDnsResolverSets {
    main: ParsedMainNameservers,
    main_resolvers: Vec<DnsResolverClient>,
    default_resolvers: Vec<DnsResolverClient>,
    default_nameservers: Vec<String>,
    proxy_resolvers: Vec<DnsResolverClient>,
    fallback: Option<DnsFallbackConfig>,
    direct: Option<DnsDirectConfig>,
}

fn parse_dns_resolver_sets(
    raw: &mut RawDns,
    trust_certificates: &[String],
    config_directory: Option<&Path>,
    geodata_mode: bool,
) -> Result<ParsedDnsResolverSets, ConfigError> {
    let nameservers = raw.nameserver.take().unwrap_or_default();
    if nameservers.is_empty() {
        return Err(ConfigError::InvalidDns(
            "at least one dns.nameserver is required".to_owned(),
        ));
    }
    let defaults = raw.default_nameserver.take().unwrap_or_default();
    let prefer_h3 = raw.prefer_h3.unwrap_or(false);
    let main_resolvers =
        parse_resolver_clients(&nameservers, &defaults, prefer_h3, trust_certificates)?;
    let all_classic = nameservers
        .iter()
        .all(|server| server.starts_with("udp://") || server.starts_with("tcp://"));
    let legacy_main = if nameservers.len() == 1 || all_classic {
        &nameservers[..]
    } else {
        &nameservers[..1]
    };
    let main = parse_main_nameservers(legacy_main, &defaults, prefer_h3, trust_certificates)?;
    let default_resolvers = parse_resolver_clients(&defaults, &[], prefer_h3, trust_certificates)?;
    validate_default_resolvers(&default_resolvers)?;
    let fallback = parse_fallback(
        raw,
        &defaults,
        trust_certificates,
        config_directory,
        geodata_mode,
    )?;
    let direct_resolvers = parse_resolver_clients(
        &raw.direct_nameserver.take().unwrap_or_default(),
        &defaults,
        prefer_h3,
        trust_certificates,
    )?;
    let direct = (!direct_resolvers.is_empty()).then_some(DnsDirectConfig {
        resolvers: direct_resolvers,
        follow_policy: raw.direct_nameserver_follow_policy.unwrap_or(false),
    });
    let proxy_resolvers = parse_resolver_clients(
        &raw.proxy_server_nameserver.take().unwrap_or_default(),
        &defaults,
        prefer_h3,
        trust_certificates,
    )?;
    Ok(ParsedDnsResolverSets {
        main,
        main_resolvers,
        default_resolvers,
        default_nameservers: defaults,
        proxy_resolvers,
        fallback,
        direct,
    })
}

fn validate_default_resolvers(resolvers: &[DnsResolverClient]) -> Result<(), ConfigError> {
    let invalid = resolvers.iter().any(|resolver| {
        !matches!(
            resolver,
            DnsResolverClient::System
                | DnsResolverClient::Classic(DnsClassicUpstream {
                    endpoint: DnsClassicEndpoint::Socket(_),
                    ..
                })
                | DnsResolverClient::Network { .. }
        )
    });
    if invalid {
        return Err(ConfigError::InvalidDns(
            "dns.default-nameserver must use pure-IP network endpoints or system".to_owned(),
        ));
    }
    Ok(())
}

struct ParsedMainNameservers {
    transport: DnsTransport,
    upstream: SocketAddr,
    main_kind: DnsMainKind,
    classic_upstreams: Vec<DnsClassicUpstream>,
    tls: Option<DnsTlsConfig>,
    query_options: DnsQueryOptions,
}

fn parse_resolver_clients(
    servers: &[String],
    default_nameservers: &[String],
    prefer_h3: bool,
    trust_certificates: &[String],
) -> Result<Vec<DnsResolverClient>, ConfigError> {
    let mut clients = Vec::new();
    for server in servers {
        let parsed = parse_main_nameservers(
            std::slice::from_ref(server),
            default_nameservers,
            prefer_h3,
            trust_certificates,
        )?;
        let mut parsed_clients = if parsed.classic_upstreams.is_empty() {
            vec![match parsed.main_kind {
                DnsMainKind::Configured => DnsResolverClient::Network {
                    upstream: DnsUpstream {
                        address: parsed.upstream,
                        transport: parsed.transport,
                    },
                    tls: parsed.tls,
                    query_options: parsed.query_options,
                },
                DnsMainKind::System => DnsResolverClient::System,
                DnsMainKind::Dhcp(interface) => DnsResolverClient::Dhcp(interface),
                DnsMainKind::Rcode(rcode) => DnsResolverClient::Rcode(rcode),
                DnsMainKind::Tailscale(name) => DnsResolverClient::Tailscale(name),
            }]
        } else {
            parsed
                .classic_upstreams
                .into_iter()
                .map(DnsResolverClient::Classic)
                .collect::<Vec<_>>()
        };
        for client in parsed_clients.drain(..) {
            if !clients.contains(&client) {
                clients.push(client);
            }
        }
    }
    Ok(clients)
}

fn parse_main_nameservers(
    nameservers: &[String],
    default_nameservers: &[String],
    prefer_h3: bool,
    trust_certificates: &[String],
) -> Result<ParsedMainNameservers, ConfigError> {
    if let Some(parsed) = parse_special_main_nameserver(nameservers)? {
        return Ok(parsed);
    }
    let all_classic = nameservers
        .iter()
        .all(|server| server.starts_with("udp://") || server.starts_with("tcp://"));
    if all_classic {
        let bootstrap = parse_optional_dns_upstream(
            default_nameservers.get(..1).unwrap_or_default(),
            "dns.default-nameserver",
            "Phase 4F2 domain classic upstream",
        )?;
        let classic_upstreams = parse_classic_main_upstreams(nameservers, bootstrap)?;
        let first = classic_upstreams
            .first()
            .expect("nonempty classic nameserver list");
        let upstream = match &first.endpoint {
            DnsClassicEndpoint::Socket(address) => *address,
            DnsClassicEndpoint::Domain { bootstrap, .. } => bootstrap.address,
        };
        return Ok(ParsedMainNameservers {
            transport: first.transport,
            upstream,
            main_kind: DnsMainKind::Configured,
            classic_upstreams,
            tls: None,
            query_options: DnsQueryOptions::default(),
        });
    }
    if nameservers.len() != 1 {
        return Err(ConfigError::InvalidDns(
            "Phase 4F2 permits multiple dns.nameserver entries only when all are classic UDP/TCP"
                .to_owned(),
        ));
    }
    let parsed = parse_dns_upstream(&nameservers[0], "dns.nameserver")?;
    let query_options = parse_dns_query_options(&nameservers[0]);
    let (transport, upstream, tls) =
        parse_main_dns_tls(parsed, prefer_h3, default_nameservers, trust_certificates)?;
    Ok(ParsedMainNameservers {
        transport,
        upstream,
        main_kind: DnsMainKind::Configured,
        classic_upstreams: Vec::new(),
        tls,
        query_options,
    })
}

fn parse_special_main_nameserver(
    nameservers: &[String],
) -> Result<Option<ParsedMainNameservers>, ConfigError> {
    let [nameserver] = nameservers else {
        return Ok(None);
    };
    let main_kind = if matches!(
        nameserver.as_str(),
        "system" | "system://" | "dhcp://system"
    ) {
        DnsMainKind::System
    } else if let Some(interface) = nameserver.strip_prefix("dhcp://") {
        DnsMainKind::Dhcp(interface.to_owned())
    } else if let Some(name) = nameserver.strip_prefix("rcode://") {
        let rcode = SyntheticRcode::parse(name)
            .ok_or_else(|| ConfigError::InvalidDns(format!("unsupported RCode type: {name}")))?;
        DnsMainKind::Rcode(rcode)
    } else if let Some(name) = nameserver
        .strip_prefix("tailscale://")
        .or_else(|| nameserver.strip_prefix("ts://"))
    {
        if name.is_empty() {
            return Err(ConfigError::InvalidDns(
                "missing Tailscale proxy name".to_owned(),
            ));
        }
        DnsMainKind::Tailscale(name.to_owned())
    } else {
        return Ok(None);
    };
    Ok(Some(ParsedMainNameservers {
        transport: DnsTransport::Udp,
        upstream: "0.0.0.0:53".parse().expect("special DNS client sentinel"),
        main_kind,
        classic_upstreams: Vec::new(),
        tls: None,
        query_options: DnsQueryOptions::default(),
    }))
}

fn parse_classic_main_upstreams(
    servers: &[String],
    bootstrap: Option<DnsUpstream>,
) -> Result<Vec<DnsClassicUpstream>, ConfigError> {
    let mut upstreams = Vec::new();
    for server in servers {
        let url = Url::parse(server).map_err(|_| {
            ConfigError::InvalidDns("dns.nameserver classic URL is invalid".to_owned())
        })?;
        let transport = match url.scheme() {
            "udp" => DnsTransport::Udp,
            "tcp" => DnsTransport::Tcp,
            _ => {
                return Err(ConfigError::InvalidDns(
                    "Phase 4F2 accepts only UDP/TCP classic upstreams".to_owned(),
                ));
            }
        };
        if url.cannot_be_a_base()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(ConfigError::InvalidDns(
                "Phase 4F6 classic upstream must contain only host, port and wrapper fragment"
                    .to_owned(),
            ));
        }
        validate_classic_wrapper_fragment(url.fragment())?;
        let host = url.host_str().ok_or_else(|| {
            ConfigError::InvalidDns("Phase 4F2 classic upstream host is required".to_owned())
        })?;
        let port = url.port().unwrap_or(53);
        if port == 0 {
            return Err(ConfigError::InvalidDns(
                "Phase 4F2 classic upstream port must be nonzero".to_owned(),
            ));
        }
        let endpoint = if let Ok(address) = host.parse::<IpAddr>() {
            DnsClassicEndpoint::Socket(SocketAddr::new(address, port))
        } else {
            let valid = host.len() <= 253
                && host
                    .split('.')
                    .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii());
            if !valid {
                return Err(ConfigError::InvalidDns(
                    "Phase 4F2 classic upstream domain is invalid".to_owned(),
                ));
            }
            let bootstrap = bootstrap.ok_or_else(|| {
                ConfigError::InvalidDns(
                    "Phase 4F2 domain classic upstream requires one dns.default-nameserver"
                        .to_owned(),
                )
            })?;
            DnsClassicEndpoint::Domain {
                host: host.to_lowercase(),
                port,
                bootstrap,
            }
        };
        let upstream = DnsClassicUpstream {
            endpoint,
            transport,
            query_options: parse_dns_query_options(server),
        };
        if !upstreams.contains(&upstream) {
            upstreams.push(upstream);
        }
    }
    Ok(upstreams)
}

fn validate_classic_wrapper_fragment(fragment: Option<&str>) -> Result<(), ConfigError> {
    let Some(fragment) = fragment else {
        return Ok(());
    };
    for parameter in fragment
        .split('&')
        .filter(|parameter| !parameter.is_empty())
    {
        let Some((name, _)) = parameter.split_once('=') else {
            return Err(ConfigError::InvalidDns(
                "Phase 4F6 does not accept classic DNS proxy routing fragments".to_owned(),
            ));
        };
        if !is_dns_wrapper_parameter(name) {
            return Err(ConfigError::InvalidDns(format!(
                "unsupported classic DNS wrapper parameter: {name}"
            )));
        }
    }
    Ok(())
}

fn is_dns_wrapper_parameter(name: &str) -> bool {
    matches!(
        name,
        "ecs" | "ecs-override" | "disable-ipv4" | "disable-ipv6"
    ) || name.starts_with("disable-qtype-")
}

fn parse_dns_query_options(value: &str) -> DnsQueryOptions {
    if !value.starts_with("udp://")
        && !value.starts_with("tcp://")
        && !value.starts_with("tls://")
        && !value.starts_with("https://")
        && !value.starts_with("quic://")
    {
        return DnsQueryOptions::default();
    }
    let parameters: BTreeMap<_, _> = value
        .split_once('#')
        .map_or("", |(_, fragment)| fragment)
        .split('&')
        .filter_map(|parameter| parameter.split_once('='))
        .collect();
    let ecs = parameters
        .get("ecs")
        .filter(|value| !value.is_empty())
        .and_then(|value| parse_ecs_config(value, parameters.get("ecs-override") == Some(&"true")));
    let mut disabled_types = Vec::new();
    if parameters.get("disable-ipv4") == Some(&"true") {
        disabled_types.push(1);
    }
    if parameters.get("disable-ipv6") == Some(&"true") {
        disabled_types.push(28);
    }
    for (name, value) in &parameters {
        if *value != "true" {
            continue;
        }
        if let Some(record_type) = name.strip_prefix("disable-qtype-")
            && let Ok(record_type) = record_type.parse::<u16>()
            && is_supported_disabled_qtype(record_type)
        {
            disabled_types.push(record_type);
        }
    }
    disabled_types.sort_unstable();
    disabled_types.dedup();
    DnsQueryOptions {
        ecs,
        disabled_types,
    }
}

fn parse_ecs_config(value: &str, override_existing: bool) -> Option<EcsConfig> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address = address.parse::<IpAddr>().ok()?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix
        .map(str::parse::<u8>)
        .transpose()
        .ok()?
        .unwrap_or(maximum);
    if prefix > maximum {
        return None;
    }
    Some(EcsConfig {
        address,
        prefix,
        override_existing,
    })
}

fn is_supported_disabled_qtype(record_type: u16) -> bool {
    matches!(
        record_type,
        1..=10
            | 12..=21
            | 23..=33
            | 35..=37
            | 39
            | 41..=53
            | 55..=65
            | 99..=102
            | 104..=109
            | 128
            | 249..=250
            | 255..=258
            | 260..=261
            | 32768..=32769
    )
}

fn parse_main_dns_tls(
    parsed: ParsedDnsUpstream,
    prefer_h3: bool,
    default_nameservers: &[String],
    trust_certificates: &[String],
) -> Result<(DnsTransport, SocketAddr, Option<DnsTlsConfig>), ConfigError> {
    let domain_endpoint = parsed.endpoint_host.is_some();
    let bootstrap = parse_optional_dns_upstream(
        default_nameservers.get(..1).unwrap_or_default(),
        "dns.default-nameserver",
        "Phase 4E9",
    )?;
    if domain_endpoint && bootstrap.is_none() {
        return Err(ConfigError::InvalidDns(
            "Phase 4E9 domain DoT requires exactly one classic loopback dns.default-nameserver"
                .to_owned(),
        ));
    }
    if bootstrap.is_some_and(|upstream| {
        !matches!(upstream.transport, DnsTransport::Udp | DnsTransport::Tcp)
    }) {
        return Err(ConfigError::InvalidDns(
            "Phase 4E9 dns.default-nameserver must use classic UDP or TCP".to_owned(),
        ));
    }
    let doh_protocol = if parsed.doh_h3_only {
        DohProtocol::Http3Only
    } else if prefer_h3 && parsed.doh_path.is_some() {
        DohProtocol::PreferHttp3
    } else {
        DohProtocol::Http
    };
    let tls = parsed
        .server_name
        .map(|server_name| {
            Ok::<_, ConfigError>(DnsTlsConfig {
                server_name,
                tls_server_name: parsed
                    .tls_server_name
                    .expect("verified TLS upstream has a TLS server name"),
                skip_certificate_verification: parsed.skip_certificate_verification,
                trust_certificates: trust_certificates.to_vec(),
                doh_path: parsed.doh_path,
                doh_basic_credentials: parsed.doh_basic_credentials,
                endpoint_host: parsed.endpoint_host,
                bootstrap,
                doh_protocol,
            })
        })
        .transpose()?;
    if domain_endpoint && tls.is_none() {
        return Err(ConfigError::InvalidDns(
            "Phase 4E9 domain DoT requires verified TLS".to_owned(),
        ));
    }
    Ok((parsed.transport, parsed.address, tls))
}

fn parse_optional_dns_upstream(
    servers: &[String],
    field: &str,
    phase: &str,
) -> Result<Option<DnsUpstream>, ConfigError> {
    if servers.is_empty() {
        return Ok(None);
    }
    if servers.len() != 1 {
        return Err(ConfigError::InvalidDns(format!(
            "{phase} requires exactly one {field} upstream"
        )));
    }
    let parsed = parse_dns_upstream(&servers[0], field)?;
    debug_assert!(parsed.server_name.is_none());
    debug_assert!(parsed.doh_path.is_none());
    debug_assert!(parsed.doh_basic_credentials.is_none());
    debug_assert!(parsed.endpoint_host.is_none());
    Ok(Some(DnsUpstream {
        address: parsed.address,
        transport: parsed.transport,
    }))
}

fn parse_fallback(
    raw: &mut RawDns,
    default_nameservers: &[String],
    trust_certificates: &[String],
    config_directory: Option<&Path>,
    geodata_mode: bool,
) -> Result<Option<DnsFallbackConfig>, ConfigError> {
    let servers = raw.fallback.take().unwrap_or_default();
    if servers.is_empty() && raw.fallback_filter.is_none() {
        return Ok(None);
    }
    let filter = raw.fallback_filter.take().unwrap_or_default();
    if let Some(key) = filter.extra.into_keys().next() {
        return Err(ConfigError::InvalidDns(format!(
            "unsupported field dns.fallback-filter.{key}"
        )));
    }
    let geoip = filter
        .geoip
        .unwrap_or(true)
        .then(|| {
            if !geodata_mode {
                return Err(ConfigError::InvalidDns(
                    "Phase 4F9 GeoIP fallback requires geodata-mode: true".to_owned(),
                ));
            }
            load_geoip_filter(
                filter.geoip_code.as_deref().unwrap_or("CN"),
                config_directory,
            )
        })
        .transpose()?;
    let domains = filter
        .domain
        .unwrap_or_default()
        .into_iter()
        .map(|pattern| normalize_policy_pattern(&pattern))
        .collect::<Result<Vec<_>, _>>()?;
    let ipcidr = filter
        .ipcidr
        .unwrap_or_default()
        .into_iter()
        .map(|network| {
            network.parse::<IpNet>().map_err(|_| {
                ConfigError::InvalidDns(format!(
                    "invalid dns.fallback-filter.ipcidr entry {network}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let geosites = filter
        .geosite
        .unwrap_or_default()
        .into_iter()
        .map(|name| load_geosite_matcher(&name, config_directory))
        .collect::<Result<Vec<_>, _>>()?;
    if servers.is_empty() {
        return Ok(None);
    }
    let resolvers = parse_resolver_clients(
        &servers,
        default_nameservers,
        raw.prefer_h3.unwrap_or(false),
        trust_certificates,
    )?;
    Ok(Some(DnsFallbackConfig {
        resolvers,
        domains,
        geosites,
        ipcidr,
        geoip,
        lazy: raw.fallback_lazy_query.unwrap_or(false),
    }))
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_rule_providers(
    raw: BTreeMap<String, RawRuleProvider>,
    provider_directory: Option<&Path>,
) -> Result<BTreeMap<String, RuleProviderConfig>, ConfigError> {
    raw.into_iter()
        .map(|(name, provider)| {
            if name.is_empty() || !provider.extra.is_empty() || provider.proxy.is_some() {
                return Err(ConfigError::UnsupportedProxy(name));
            }
            let behavior = match provider.behavior.as_deref() {
                Some("domain") => ProviderBehavior::Domain,
                Some("classical") => ProviderBehavior::Classical,
                Some("ipcidr") => ProviderBehavior::IpCidr,
                _ => return Err(ConfigError::UnsupportedProxy(name)),
            };
            let format = match provider.format.as_deref() {
                None | Some("yaml") => RuleProviderFormat::Yaml,
                Some("text") => RuleProviderFormat::Text,
                Some("mrs") => RuleProviderFormat::Mrs,
                _ => return Err(ConfigError::UnsupportedProxy(name)),
            };
            let fallback = provider.payload.unwrap_or_default();
            let (vehicle, path, url, cache_modified, etag, payload) = match provider.kind.as_deref()
            {
                Some("inline") if provider.path.is_none() && provider.url.is_none() => (
                    RuleProviderVehicle::Inline,
                    PathBuf::new(),
                    None,
                    Some(SystemTime::now()),
                    None,
                    fallback,
                ),
                Some("file") if provider.url.is_none() => {
                    let directory = provider_directory
                        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                    let path = provider
                        .path
                        .filter(|path| !path.is_empty())
                        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                    let path = directory.join(path);
                    let payload = load_rule_provider_file(&path, format, behavior)?;
                    let modified = std::fs::metadata(&path)
                        .and_then(|metadata| metadata.modified())
                        .ok();
                    (
                        RuleProviderVehicle::File,
                        path,
                        None,
                        modified,
                        None,
                        payload,
                    )
                }
                Some("http") => {
                    let directory = provider_directory
                        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                    let url = provider
                        .url
                        .filter(|url| !url.is_empty())
                        .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                    let parsed = Url::parse(&url)
                        .map_err(|_| ConfigError::UnsupportedProxy(name.clone()))?;
                    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                        return Err(ConfigError::UnsupportedProxy(name));
                    }
                    let path = provider.path.filter(|path| !path.is_empty()).map_or_else(
                        || {
                            directory
                                .join("rules")
                                .join(format!("{:x}", Md5::digest(url.as_bytes())))
                        },
                        |path| directory.join(path),
                    );
                    let (modified, etag, cached) = load_rule_provider_file(&path, format, behavior)
                        .map(|payload| {
                            let modified = std::fs::metadata(&path)
                                .and_then(|metadata| metadata.modified())
                                .ok();
                            let etag = load_provider_etag(&path, &url);
                            (modified, etag, payload)
                        })
                        .unwrap_or((None, None, fallback));
                    (
                        RuleProviderVehicle::Http,
                        path,
                        Some(url),
                        modified,
                        etag,
                        cached,
                    )
                }
                _ => return Err(ConfigError::UnsupportedProxy(name)),
            };
            let domains = payload
                .iter()
                .filter_map(|entry| parse_rule_provider_domain(behavior, entry).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            Ok((
                name.clone(),
                RuleProviderConfig {
                    name,
                    behavior,
                    vehicle,
                    format,
                    path,
                    url,
                    interval: provider.interval.unwrap_or(0),
                    headers: provider.header.unwrap_or_default(),
                    size_limit: provider.size_limit.unwrap_or(0),
                    cache_modified,
                    etag,
                    payload,
                    domains,
                },
            ))
        })
        .collect()
}

pub(crate) fn load_rule_provider_file(
    path: &Path,
    format: RuleProviderFormat,
    behavior: ProviderBehavior,
) -> Result<Vec<String>, ConfigError> {
    let source = std::fs::read(path)?;
    parse_rule_provider_source(&source, format, behavior)
}

pub(crate) fn parse_rule_provider_source(
    source: &[u8],
    format: RuleProviderFormat,
    behavior: ProviderBehavior,
) -> Result<Vec<String>, ConfigError> {
    match format {
        RuleProviderFormat::Yaml => {
            let file = serde_yaml_ng::from_slice::<RawRuleProviderFile>(source)?;
            if !file.extra.is_empty() {
                return Err(ConfigError::UnsupportedProxy(
                    "rule provider YAML".to_owned(),
                ));
            }
            Ok(file.rules.or(file.payload).unwrap_or_default())
        }
        RuleProviderFormat::Text => {
            let source = std::str::from_utf8(source)
                .map_err(|_| ConfigError::UnsupportedProxy("rule provider text".to_owned()))?;
            Ok(source
                .lines()
                .map(str::trim)
                .filter(|line| {
                    !line.is_empty() && !line.starts_with('#') && !line.starts_with("//")
                })
                .map(str::to_owned)
                .collect())
        }
        RuleProviderFormat::Mrs => {
            let text = match behavior {
                ProviderBehavior::Domain => rewrite_ruleset::domain_mrs_to_text(source),
                ProviderBehavior::IpCidr => rewrite_ruleset::ipcidr_mrs_to_text(source),
                ProviderBehavior::Classical => {
                    return Err(ConfigError::UnsupportedProxy(
                        "classical MRS rule provider".to_owned(),
                    ));
                }
            }
            .map_err(|_| ConfigError::UnsupportedProxy("rule provider MRS".to_owned()))?;
            parse_rule_provider_source(&text, RuleProviderFormat::Text, behavior)
        }
    }
}

pub(crate) fn parse_rule_provider_domain(
    behavior: ProviderBehavior,
    entry: &str,
) -> Result<Option<RuleSetDomain>, ConfigError> {
    match behavior {
        ProviderBehavior::Domain => Ok(Some(RuleSetDomain {
            kind: RuleSetDomainKind::Trie,
            value: normalize_policy_pattern(entry)?,
        })),
        ProviderBehavior::IpCidr => Ok(None),
        ProviderBehavior::Classical => {
            let mut fields = entry.split(',');
            let kind = fields.next().unwrap_or_default().to_ascii_uppercase();
            let payload = fields.next().unwrap_or_default();
            if fields.next().is_some() || payload.is_empty() {
                return Ok(None);
            }
            match kind.as_str() {
                "DOMAIN" | "DOMAIN-WILDCARD" => Ok(Some(RuleSetDomain {
                    kind: RuleSetDomainKind::Trie,
                    value: normalize_policy_pattern(payload)?,
                })),
                "DOMAIN-SUFFIX" => Ok(Some(RuleSetDomain {
                    kind: RuleSetDomainKind::Trie,
                    value: normalize_policy_pattern(&format!("+.{payload}"))?,
                })),
                "DOMAIN-KEYWORD" => Ok(Some(RuleSetDomain {
                    kind: RuleSetDomainKind::Keyword,
                    value: payload.to_ascii_lowercase(),
                })),
                _ => Ok(None),
            }
        }
    }
}

fn parse_dns_policies(
    raw: Mapping,
    field: &str,
    default_nameservers: &[String],
    prefer_h3: bool,
    trust_certificates: &[String],
    rule_providers: &BTreeMap<String, RuleProviderConfig>,
    config_directory: Option<&Path>,
) -> Result<Vec<DnsPolicy>, ConfigError> {
    let mut policies = Vec::new();
    for (key, value) in raw {
        let key = key
            .as_str()
            .ok_or_else(|| ConfigError::InvalidDns(format!("{field} keys must be strings")))?;
        let servers = parse_policy_servers(&value, field)?;
        let resolvers =
            parse_resolver_clients(&servers, default_nameservers, prefer_h3, trust_certificates)?;
        if resolvers.is_empty() {
            return Err(ConfigError::InvalidDns(format!(
                "{field} {key} requires at least one upstream"
            )));
        }
        for matcher in expand_policy_matchers(key, rule_providers, config_directory)? {
            policies.push(DnsPolicy {
                matcher,
                resolvers: resolvers.clone(),
            });
        }
    }
    Ok(policies)
}

fn parse_policy_servers(value: &Value, field: &str) -> Result<Vec<String>, ConfigError> {
    match value {
        Value::String(server) => Ok(vec![server.clone()]),
        Value::Sequence(servers) => servers
            .iter()
            .map(|server| {
                server.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    ConfigError::InvalidDns(format!("{field} upstreams must be strings"))
                })
            })
            .collect(),
        _ => Err(ConfigError::InvalidDns(format!(
            "{field} values must be a string or string list"
        ))),
    }
}

fn expand_policy_matchers(
    key: &str,
    rule_providers: &BTreeMap<String, RuleProviderConfig>,
    config_directory: Option<&Path>,
) -> Result<Vec<DnsPolicyMatcher>, ConfigError> {
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("geosite:") {
        return key[8..]
            .split(',')
            .map(|name| load_geosite_matcher(name, config_directory))
            .collect();
    }
    if lower.starts_with("rule-set:") {
        return key[9..]
            .split(',')
            .map(|name| {
                let provider = rule_providers.get(name).ok_or_else(|| {
                    ConfigError::InvalidDns(format!("not found rule-set: {name}"))
                })?;
                if provider.behavior == ProviderBehavior::IpCidr {
                    return Err(ConfigError::InvalidDns(format!(
                        "rule provider type error for {name}: expected domain"
                    )));
                }
                Ok(DnsPolicyMatcher::RuleSet {
                    name: name.to_owned(),
                    domains: provider.domains.clone(),
                })
            })
            .collect();
    }
    key.split(',')
        .map(|pattern| normalize_policy_pattern(pattern).map(DnsPolicyMatcher::Domain))
        .collect()
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoSiteListWire {
    #[prost(message, repeated, tag = "1")]
    pub(crate) entries: Vec<GeoSiteWire>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoSiteWire {
    #[prost(string, tag = "1")]
    pub(crate) country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub(crate) domains: Vec<GeoSiteDomainWire>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoSiteDomainWire {
    #[prost(enumeration = "GeoSiteDomainTypeWire", tag = "1")]
    pub(crate) kind: i32,
    #[prost(string, tag = "2")]
    pub(crate) value: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoIpListWire {
    #[prost(message, repeated, tag = "1")]
    pub(crate) entries: Vec<GeoIpWire>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoIpWire {
    #[prost(string, tag = "1")]
    pub(crate) country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub(crate) networks: Vec<GeoIpCidrWire>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoIpCidrWire {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) address: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) prefix: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum GeoSiteDomainTypeWire {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

pub(crate) fn extend_geodata_rule_providers(
    rules: &[String],
    sub_rules: &BTreeMap<String, Vec<String>>,
    directory: Option<&Path>,
    geodata_mode: bool,
    providers: &mut BTreeMap<String, ProviderDefinition>,
) -> Result<(), ConfigError> {
    let declarations = rules
        .iter()
        .chain(sub_rules.values().flatten())
        .filter_map(|rule| {
            let fields = rule.split(',').map(str::trim).collect::<Vec<_>>();
            let kind = fields.first()?.to_ascii_uppercase();
            matches!(kind.as_str(), "GEOSITE" | "GEOIP" | "SRC-GEOIP")
                .then(|| (kind, fields.get(1).copied().unwrap_or_default().to_owned()))
        })
        .collect::<BTreeSet<_>>();
    for (kind, payload) in declarations {
        let definition = match kind.as_str() {
            "GEOSITE" => load_geosite_rule_provider(&payload, directory)?,
            "GEOIP" | "SRC-GEOIP" if payload.eq_ignore_ascii_case("lan") => ProviderDefinition {
                behavior: ProviderBehavior::IpCidr,
                payload: [
                    "0.0.0.0/8",
                    "10.0.0.0/8",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "224.0.0.0/4",
                    "::/128",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10",
                    "ff00::/8",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            },
            "GEOIP" | "SRC-GEOIP" if geodata_mode => load_geoip_rule_provider(&payload, directory)?,
            _ => continue,
        };
        providers.insert(
            rewrite_rules::geodata_provider_key(&kind, &payload),
            definition,
        );
    }
    Ok(())
}

fn load_geosite_rule_provider(
    name: &str,
    directory: Option<&Path>,
) -> Result<ProviderDefinition, ConfigError> {
    let DnsPolicyMatcher::Geosite { domains, .. } = load_geosite_matcher(name, directory)? else {
        unreachable!("GeoSite loader always returns a GeoSite matcher")
    };
    let payload = domains
        .into_iter()
        .map(|domain| {
            let kind = match domain.kind {
                GeositeDomainKind::Plain => "DOMAIN-KEYWORD",
                GeositeDomainKind::Regex => "DOMAIN-REGEX",
                GeositeDomainKind::Domain => "DOMAIN-SUFFIX",
                GeositeDomainKind::Full => "DOMAIN",
            };
            format!("{kind},{}", domain.value)
        })
        .collect();
    Ok(ProviderDefinition {
        behavior: ProviderBehavior::Classical,
        payload,
    })
}

fn load_geoip_rule_provider(
    code: &str,
    directory: Option<&Path>,
) -> Result<ProviderDefinition, ConfigError> {
    let filter = load_geoip_filter(code, directory)?;
    Ok(ProviderDefinition {
        behavior: ProviderBehavior::IpCidr,
        payload: filter
            .networks
            .into_iter()
            .map(|network| network.to_string())
            .collect(),
    })
}

fn load_geoip_filter(
    code: &str,
    config_directory: Option<&Path>,
) -> Result<DnsGeoIpFilter, ConfigError> {
    let (inverted, code) = code
        .strip_prefix('!')
        .map_or((false, code), |code| (true, code));
    if code.is_empty() {
        return Err(ConfigError::InvalidDns(
            "dns.fallback-filter.geoip-code must be non-empty".to_owned(),
        ));
    }
    if code.eq_ignore_ascii_case("lan") && !inverted {
        return Ok(DnsGeoIpFilter {
            code: "lan".to_owned(),
            networks: Vec::new(),
            inverted: false,
        });
    }
    let directory = config_directory.ok_or_else(|| {
        ConfigError::InvalidDns(
            "GeoIP fallback filter requires file-backed configuration beside GeoIP.dat".to_owned(),
        )
    })?;
    let data = std::fs::read(directory.join("GeoIP.dat"))
        .map_err(|error| ConfigError::InvalidDns(format!("cannot read GeoIP.dat: {error}")))?;
    let list = GeoIpListWire::decode(data.as_slice())
        .map_err(|error| ConfigError::InvalidDns(format!("cannot decode GeoIP.dat: {error}")))?;
    let entry = list
        .entries
        .into_iter()
        .find(|entry| entry.country_code.eq_ignore_ascii_case(code))
        .ok_or_else(|| ConfigError::InvalidDns(format!("GeoIP country {code} not found")))?;
    let networks = entry
        .networks
        .into_iter()
        .map(|network| {
            let address = match network.address.as_slice() {
                octets @ [_, _, _, _] => {
                    IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
                }
                octets if octets.len() == 16 => {
                    let octets: [u8; 16] = octets.try_into().map_err(|_| {
                        ConfigError::InvalidDns("invalid IPv6 GeoIP network".to_owned())
                    })?;
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => {
                    return Err(ConfigError::InvalidDns(
                        "GeoIP network address must contain 4 or 16 bytes".to_owned(),
                    ));
                }
            };
            let prefix = u8::try_from(network.prefix).map_err(|_| {
                ConfigError::InvalidDns(format!("invalid GeoIP prefix {}", network.prefix))
            })?;
            IpNet::new(address, prefix)
                .map_err(|error| ConfigError::InvalidDns(format!("invalid GeoIP network: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DnsGeoIpFilter {
        code: code.to_ascii_lowercase(),
        networks,
        inverted,
    })
}

fn load_geosite_matcher(
    name: &str,
    config_directory: Option<&Path>,
) -> Result<DnsPolicyMatcher, ConfigError> {
    if name.is_empty() || name.contains('@') {
        return Err(ConfigError::InvalidDns(
            "Phase 4F8 geosite names must be non-empty and cannot use attributes".to_owned(),
        ));
    }
    let directory = config_directory.ok_or_else(|| {
        ConfigError::InvalidDns(
            "geosite policy requires file-backed configuration beside GeoSite.dat".to_owned(),
        )
    })?;
    let data = std::fs::read(directory.join("GeoSite.dat"))
        .map_err(|error| ConfigError::InvalidDns(format!("cannot read GeoSite.dat: {error}")))?;
    let list = GeoSiteListWire::decode(data.as_slice())
        .map_err(|error| ConfigError::InvalidDns(format!("cannot decode GeoSite.dat: {error}")))?;
    let site = list
        .entries
        .into_iter()
        .find(|site| site.country_code.eq_ignore_ascii_case(name))
        .ok_or_else(|| ConfigError::InvalidDns(format!("geosite list {name} not found")))?;
    let domains = site
        .domains
        .into_iter()
        .map(|domain| {
            let kind = match GeoSiteDomainTypeWire::try_from(domain.kind) {
                Ok(GeoSiteDomainTypeWire::Plain) => GeositeDomainKind::Plain,
                Ok(GeoSiteDomainTypeWire::Regex) => {
                    Regex::new(&domain.value).map_err(|error| {
                        ConfigError::InvalidDns(format!(
                            "invalid geosite regular expression {}: {error}",
                            domain.value
                        ))
                    })?;
                    GeositeDomainKind::Regex
                }
                Ok(GeoSiteDomainTypeWire::Domain) => GeositeDomainKind::Domain,
                Ok(GeoSiteDomainTypeWire::Full) => GeositeDomainKind::Full,
                Err(_) => {
                    return Err(ConfigError::InvalidDns(format!(
                        "unsupported geosite domain type {}",
                        domain.kind
                    )));
                }
            };
            Ok(GeositeDomain {
                kind,
                value: domain.value,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    Ok(DnsPolicyMatcher::Geosite {
        name: name.to_owned(),
        domains,
    })
}

fn normalize_policy_pattern(value: &str) -> Result<String, ConfigError> {
    let value = value.to_ascii_lowercase();
    let labels: Vec<_> = value.split('.').collect();
    let valid = !value.is_empty()
        && !value.ends_with('.')
        && labels.iter().enumerate().all(|(index, label)| {
            !label.is_empty()
                && label.len() <= 63
                && match *label {
                    "*" => true,
                    "+" => index == 0 && labels.len() > 1,
                    _ => {
                        !label.starts_with('-')
                            && !label.ends_with('-')
                            && label
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    }
                }
        });
    if !valid {
        return Err(ConfigError::InvalidDns(
            "dns.nameserver-policy pattern is outside the Phase 4D1 domain subset".to_owned(),
        ));
    }
    Ok(value)
}

struct ParsedDnsUpstream {
    transport: DnsTransport,
    address: SocketAddr,
    server_name: Option<String>,
    tls_server_name: Option<String>,
    skip_certificate_verification: bool,
    doh_path: Option<String>,
    doh_basic_credentials: Option<String>,
    endpoint_host: Option<String>,
    doh_h3_only: bool,
}

fn parse_dns_upstream(value: &str, field: &str) -> Result<ParsedDnsUpstream, ConfigError> {
    if let Some(address) = value.strip_prefix("udp://") {
        return Ok(ParsedDnsUpstream {
            transport: DnsTransport::Udp,
            address: parse_dns_socket_addr(address, field)?,
            server_name: None,
            tls_server_name: None,
            skip_certificate_verification: false,
            doh_path: None,
            doh_basic_credentials: None,
            endpoint_host: None,
            doh_h3_only: false,
        });
    }
    if let Some(address) = value.strip_prefix("tcp://") {
        return Ok(ParsedDnsUpstream {
            transport: DnsTransport::Tcp,
            address: parse_dns_socket_addr(address, field)?,
            server_name: None,
            tls_server_name: None,
            skip_certificate_verification: false,
            doh_path: None,
            doh_basic_credentials: None,
            endpoint_host: None,
            doh_h3_only: false,
        });
    }
    if let Some(value) = value.strip_prefix("tls://") {
        return parse_tls_dns_upstream(value, field);
    }
    if value.starts_with("http://") {
        return parse_http_dns_upstream(value, field, false);
    }
    if value.starts_with("https://") {
        return parse_http_dns_upstream(value, field, true);
    }
    if let Some(value) = value.strip_prefix("quic://") {
        return parse_quic_dns_upstream(value, field);
    }
    Err(ConfigError::InvalidDns(format!(
        "{field} must use a declared UDP, TCP or Phase 4E encrypted upstream"
    )))
}

fn parse_quic_dns_upstream(value: &str, field: &str) -> Result<ParsedDnsUpstream, ConfigError> {
    if field != "dns.nameserver" {
        return Err(ConfigError::InvalidDns(
            "Phase 4E17 permits quic:// only for dns.nameserver".to_owned(),
        ));
    }
    let (endpoint, fragment) = value.split_once('#').unwrap_or((value, ""));
    let mut verification_name = None;
    for parameter in fragment
        .split('&')
        .filter(|parameter| !parameter.is_empty())
    {
        let Some((name, value)) = parameter.split_once('=') else {
            return Err(ConfigError::InvalidDns(
                "Phase 4E17 does not permit DoQ proxy-name fragments".to_owned(),
            ));
        };
        if is_dns_wrapper_parameter(name) {
            continue;
        }
        if name != "name-cert-verify" || value.is_empty() || verification_name.is_some() {
            return Err(ConfigError::InvalidDns(format!(
                "Phase 4E17 does not permit DoQ parameter {name}"
            )));
        }
        verification_name = Some(normalize_tls_server_name(value)?);
    }
    let server_name = verification_name.ok_or_else(|| {
        ConfigError::InvalidDns(
            "Phase 4E17 requires an explicit DoQ name-cert-verify parameter".to_owned(),
        )
    })?;
    let address = parse_loopback_dns_addr(endpoint, field)?;
    Ok(ParsedDnsUpstream {
        transport: DnsTransport::QuicVerifiedReuse,
        address,
        server_name: Some(server_name),
        tls_server_name: Some(address.ip().to_string()),
        skip_certificate_verification: false,
        doh_path: None,
        doh_basic_credentials: None,
        endpoint_host: None,
        doh_h3_only: false,
    })
}

fn parse_tls_dns_upstream(value: &str, field: &str) -> Result<ParsedDnsUpstream, ConfigError> {
    if field != "dns.nameserver" {
        return Err(ConfigError::InvalidDns(
            "Phase 4E permits tls:// only for dns.nameserver".to_owned(),
        ));
    }
    let (endpoint, fragment) = value.split_once('#').unwrap_or((value, ""));
    let mut parameters = BTreeMap::new();
    for parameter in fragment
        .split('&')
        .filter(|parameter| !parameter.is_empty())
    {
        let Some((name, value)) = parameter.split_once('=') else {
            return Err(ConfigError::InvalidDns(
                "Phase 4E10 does not yet permit DoT proxy-name fragments".to_owned(),
            ));
        };
        if !matches!(
            name,
            "skip-cert-verify" | "name-cert-verify" | "disable-reuse"
        ) && !is_dns_wrapper_parameter(name)
        {
            return Err(ConfigError::InvalidDns(format!(
                "Phase 4E10 does not yet permit DoT parameter {name}"
            )));
        }
        parameters.insert(name, value);
    }
    let (address, endpoint_host) = parse_tls_endpoint(endpoint)?;
    let tls_server_name = endpoint_host
        .clone()
        .unwrap_or_else(|| address.ip().to_string());
    let disable_reuse = parameters.get("disable-reuse") == Some(&"true");
    let name_override = parameters
        .get("name-cert-verify")
        .copied()
        .filter(|name| !name.is_empty())
        .map(normalize_tls_server_name)
        .transpose()?;
    let skip_verification =
        parameters.get("skip-cert-verify") == Some(&"true") && name_override.is_none();
    let (transport, server_name) = if skip_verification {
        let transport = if disable_reuse {
            DnsTransport::TlsInsecureNoReuse
        } else {
            DnsTransport::TlsInsecureReuse
        };
        (transport, None)
    } else {
        let server_name = name_override.unwrap_or_else(|| {
            endpoint_host
                .clone()
                .unwrap_or_else(|| address.ip().to_string())
        });
        let transport = if disable_reuse {
            DnsTransport::TlsVerifiedNoReuse
        } else {
            DnsTransport::TlsVerifiedReuse
        };
        (transport, Some(server_name))
    };
    if endpoint_host.is_some() && server_name.is_none() {
        return Err(ConfigError::InvalidDns(
            "Phase 4E10 domain DoT still requires certificate verification".to_owned(),
        ));
    }
    Ok(ParsedDnsUpstream {
        transport,
        address,
        server_name,
        tls_server_name: Some(tls_server_name),
        skip_certificate_verification: false,
        doh_path: None,
        doh_basic_credentials: None,
        endpoint_host,
        doh_h3_only: false,
    })
}

fn parse_tls_endpoint(value: &str) -> Result<(SocketAddr, Option<String>), ConfigError> {
    let url = Url::parse(&format!("tls://{value}"))
        .map_err(|_| ConfigError::InvalidDns("invalid Phase 4E9 DoT endpoint".to_owned()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::InvalidDns("invalid Phase 4E9 DoT endpoint".to_owned()))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ConfigError::InvalidDns(
            "Phase 4E9 DoT endpoint permits only host and optional port".to_owned(),
        ));
    }
    let port = url.port().unwrap_or(853);
    if let Ok(address) = host.parse::<IpAddr>() {
        if !address.is_loopback() {
            return Err(ConfigError::InvalidDns(
                "Phase 4E9 IP-literal DoT endpoint must be loopback".to_owned(),
            ));
        }
        return Ok((SocketAddr::new(address, port), None));
    }
    let endpoint_host = normalize_tls_server_name(host)?;
    Ok((SocketAddr::from(([0, 0, 0, 0], port)), Some(endpoint_host)))
}

fn parse_http_dns_upstream(
    value: &str,
    field: &str,
    tls: bool,
) -> Result<ParsedDnsUpstream, ConfigError> {
    if field != "dns.nameserver" {
        return Err(ConfigError::InvalidDns(
            "Phase 4E permits HTTP DoH only for dns.nameserver".to_owned(),
        ));
    }
    let url = Url::parse(value)
        .map_err(|_| ConfigError::InvalidDns("invalid Phase 4E5 DoH URL".to_owned()))?;
    if !tls {
        let doh_path = if matches!(url.path(), "" | "/") {
            Some("/".to_owned())
        } else {
            normalize_doh_path(url.path())
        };
        if url.host_str() != Some("127.0.0.1")
            || doh_path.is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ConfigError::InvalidDns(
                "Phase 4E12 requires a loopback plaintext HTTP DoH URL without query, fragment or userinfo"
                    .to_owned(),
            ));
        }
        let address = SocketAddr::from(([127, 0, 0, 1], url.port().unwrap_or(80)));
        return Ok(ParsedDnsUpstream {
            transport: DnsTransport::HttpReuse,
            address,
            server_name: Some(String::new()),
            tls_server_name: Some(String::new()),
            skip_certificate_verification: false,
            doh_path,
            doh_basic_credentials: None,
            endpoint_host: None,
            doh_h3_only: false,
        });
    }
    parse_https_dns_upstream(&url)
}

fn parse_https_dns_upstream(url: &Url) -> Result<ParsedDnsUpstream, ConfigError> {
    let doh_path = if matches!(url.path(), "" | "/") {
        Some("/".to_owned())
    } else {
        normalize_doh_path(url.path())
    };
    if doh_path.is_none() {
        return Err(ConfigError::InvalidDns(
            "Phase 4E14 requires an HTTPS DoH URL with a supported absolute path".to_owned(),
        ));
    }
    if url.username().contains('%')
        || url
            .password()
            .is_some_and(|password| password.contains('%'))
    {
        return Err(ConfigError::InvalidDns(
            "Phase 4E13 does not yet permit percent-encoded HTTPS userinfo".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::InvalidDns("invalid Phase 4E14 DoH host".to_owned()))?;
    let port = url.port().unwrap_or(443);
    let (address, endpoint_host, tls_server_name) = if let Ok(address) = host.parse::<IpAddr>() {
        if address != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(ConfigError::InvalidDns(
                "Phase 4E14 IP-literal HTTPS DoH endpoint must be 127.0.0.1".to_owned(),
            ));
        }
        (SocketAddr::new(address, port), None, address.to_string())
    } else {
        let endpoint_host = normalize_tls_server_name(host)?;
        (
            SocketAddr::from(([0, 0, 0, 0], port)),
            Some(endpoint_host.clone()),
            endpoint_host,
        )
    };
    let mut parameters = BTreeMap::new();
    for parameter in url
        .fragment()
        .unwrap_or_default()
        .split('&')
        .filter(|parameter| !parameter.is_empty())
    {
        let Some((name, value)) = parameter.split_once('=') else {
            return Err(ConfigError::InvalidDns(
                "Phase 4E14 does not yet permit DoH proxy-name fragments".to_owned(),
            ));
        };
        if !matches!(name, "skip-cert-verify" | "name-cert-verify" | "h3")
            && !is_dns_wrapper_parameter(name)
        {
            return Err(ConfigError::InvalidDns(format!(
                "Phase 4E16 does not yet permit DoH parameter {name}"
            )));
        }
        parameters.insert(name, value);
    }
    let name_override = parameters
        .get("name-cert-verify")
        .copied()
        .filter(|name| !name.is_empty())
        .map(normalize_tls_server_name)
        .transpose()?;
    let skip_certificate_verification =
        parameters.get("skip-cert-verify") == Some(&"true") && name_override.is_none();
    let server_name = name_override.unwrap_or_else(|| tls_server_name.clone());
    let doh_basic_credentials = (!url.username().is_empty() || url.password().is_some())
        .then(|| format!("{}:{}", url.username(), url.password().unwrap_or_default()));
    let doh_h3_only = parameters.get("h3") == Some(&"true");
    Ok(ParsedDnsUpstream {
        transport: DnsTransport::HttpsVerifiedReuse,
        address,
        server_name: Some(server_name),
        tls_server_name: Some(tls_server_name),
        skip_certificate_verification,
        doh_path,
        doh_basic_credentials,
        endpoint_host,
        doh_h3_only,
    })
}

fn normalize_doh_path(path: &str) -> Option<String> {
    let suffix = path.strip_prefix('/')?;
    if suffix.is_empty() {
        return None;
    }
    let mut normalized = String::with_capacity(path.len());
    normalized.push('/');
    for (index, segment) in suffix.split('/').enumerate() {
        if segment.is_empty() {
            return None;
        }
        if index > 0 {
            normalized.push('/');
        }
        let bytes = segment.as_bytes();
        let mut offset = 0;
        while offset < bytes.len() {
            let byte = bytes[offset];
            if is_unreserved_path_byte(byte) {
                normalized.push(char::from(byte));
                offset += 1;
                continue;
            }
            if byte != b'%' || offset + 2 >= bytes.len() {
                return None;
            }
            let decoded = (hex_value(bytes[offset + 1])? << 4) | hex_value(bytes[offset + 2])?;
            if !is_unreserved_path_byte(decoded) {
                return None;
            }
            normalized.push(char::from(decoded));
            offset += 3;
        }
    }
    Some(normalized)
}

fn is_unreserved_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn normalize_tls_server_name(value: &str) -> Result<String, ConfigError> {
    let value = value.to_ascii_lowercase();
    let labels: Vec<_> = value.split('.').collect();
    let valid = !value.is_empty()
        && !value.ends_with('.')
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(ConfigError::InvalidDns(
            "name-cert-verify must be a DNS hostname in Phase 4E2".to_owned(),
        ));
    }
    Ok(value)
}

fn parse_fake_ip_config(
    raw: &mut RawDns,
    mode: DnsMode,
    rule_providers: &BTreeMap<String, RuleProviderConfig>,
    config_directory: Option<&Path>,
) -> Result<Option<FakeIpConfig>, ConfigError> {
    if mode != DnsMode::FakeIp {
        return Ok(None);
    }
    let ipv4_range = parse_fake_ip_range(
        raw.fake_ip_range.as_deref().unwrap_or("198.18.0.1/16"),
        false,
        "dns.fake-ip-range",
    )?;
    let ipv6_range = raw
        .fake_ip_range6
        .as_deref()
        .map(|value| parse_fake_ip_range(value, true, "dns.fake-ip-range6"))
        .transpose()?
        .flatten();
    if ipv4_range.is_none() && ipv6_range.is_none() {
        return Err(ConfigError::InvalidDns(
            "fake-ip mode requires an IPv4 or IPv6 range".to_owned(),
        ));
    }
    let filter_mode = match raw
        .fake_ip_filter_mode
        .as_deref()
        .unwrap_or("blacklist")
        .to_ascii_lowercase()
        .as_str()
    {
        "blacklist" => FakeIpFilterMode::Blacklist,
        "whitelist" => FakeIpFilterMode::Whitelist,
        "rule" => FakeIpFilterMode::Rule,
        _ => {
            return Err(ConfigError::InvalidDns(
                "invalid dns.fake-ip-filter-mode".to_owned(),
            ));
        }
    };
    let filter = raw.fake_ip_filter.take().unwrap_or_else(|| {
        vec![
            "dns.msftnsci.com".to_owned(),
            "www.msftnsci.com".to_owned(),
            "www.msftconnecttest.com".to_owned(),
        ]
    });
    let (filter, rules) = if filter_mode == FakeIpFilterMode::Rule {
        (
            Vec::new(),
            parse_fake_ip_rules(&filter, rule_providers, config_directory)?,
        )
    } else {
        (
            parse_fake_ip_matchers(&filter, rule_providers, config_directory)?,
            Vec::new(),
        )
    };
    let ttl = u32::try_from(raw.fake_ip_ttl.unwrap_or(1).max(1)).unwrap_or(u32::MAX);
    Ok(Some(FakeIpConfig {
        ipv4_range,
        ipv6_range,
        filter,
        rules,
        filter_mode,
        ttl,
    }))
}

fn parse_fake_ip_matchers(
    entries: &[String],
    providers: &BTreeMap<String, RuleProviderConfig>,
    config_directory: Option<&Path>,
) -> Result<Vec<DnsPolicyMatcher>, ConfigError> {
    let mut matchers = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        expand_policy_matchers(entry, providers, config_directory)
            .map_err(|error| {
                ConfigError::InvalidDns(format!("dns.fake-ip-filter[{index}] {error}"))
            })
            .map(|expanded| matchers.extend(expanded))?;
    }
    Ok(matchers)
}

fn parse_fake_ip_rules(
    entries: &[String],
    providers: &BTreeMap<String, RuleProviderConfig>,
    config_directory: Option<&Path>,
) -> Result<Vec<FakeIpRule>, ConfigError> {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_fake_ip_rule(index, entry, providers, config_directory))
        .collect()
}

fn parse_fake_ip_rule(
    index: usize,
    entry: &str,
    providers: &BTreeMap<String, RuleProviderConfig>,
    config_directory: Option<&Path>,
) -> Result<FakeIpRule, ConfigError> {
    let fields = entry.split(',').map(str::trim).collect::<Vec<_>>();
    let kind = fields
        .first()
        .copied()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let action_index = match kind.as_str() {
        "MATCH" => 1,
        "DOMAIN-REGEX" => fields.len().saturating_sub(1),
        _ => 2,
    };
    let action = fields
        .get(action_index)
        .copied()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let action = match action.as_str() {
        "fake-ip" => FakeIpRuleAction::FakeIp,
        "real-ip" => FakeIpRuleAction::RealIp,
        _ => {
            return Err(ConfigError::InvalidDns(format!(
                "dns.fake-ip-filter[{index}] [{entry}] error: invalid action '{action}', must be 'fake-ip' or 'real-ip'"
            )));
        }
    };
    let payload = if kind == "DOMAIN-REGEX" && fields.len() >= 3 {
        fields[1..fields.len() - 1].join(",")
    } else {
        fields.get(1).copied().unwrap_or_default().to_owned()
    };
    let matcher = match kind.as_str() {
        "MATCH" if fields.len() == 2 => FakeIpRuleMatcher::Match,
        "DOMAIN" if fields.len() >= 3 => {
            FakeIpRuleMatcher::Domain(normalize_host_name(&payload, "dns.fake-ip-filter")?)
        }
        "DOMAIN-SUFFIX" if fields.len() >= 3 => {
            FakeIpRuleMatcher::DomainSuffix(normalize_host_name(&payload, "dns.fake-ip-filter")?)
        }
        "DOMAIN-KEYWORD" if fields.len() >= 3 && !payload.is_empty() => {
            FakeIpRuleMatcher::DomainKeyword(payload.to_ascii_lowercase())
        }
        "DOMAIN-REGEX" if fields.len() >= 3 => {
            regex::Regex::new(&payload).map_err(|error| {
                ConfigError::InvalidDns(format!(
                    "dns.fake-ip-filter[{index}] [{entry}] error: {error}"
                ))
            })?;
            FakeIpRuleMatcher::DomainRegex(payload)
        }
        "DOMAIN-WILDCARD" if fields.len() >= 3 && !payload.is_empty() => {
            FakeIpRuleMatcher::DomainWildcard(payload.to_ascii_lowercase())
        }
        "GEOSITE" if fields.len() >= 3 => {
            let DnsPolicyMatcher::Geosite { name, domains } =
                load_geosite_matcher(&payload, config_directory)?
            else {
                unreachable!("GeoSite loader always returns a GeoSite matcher")
            };
            FakeIpRuleMatcher::Geosite { name, domains }
        }
        "RULE-SET" if fields.len() >= 3 => {
            let provider = providers.get(&payload).ok_or_else(|| {
                ConfigError::InvalidDns(format!(
                    "dns.fake-ip-filter[{index}] [{entry}] error: rule-set '{payload}' not found"
                ))
            })?;
            if provider.behavior == ProviderBehavior::IpCidr {
                return Err(ConfigError::InvalidDns(format!(
                    "dns.fake-ip-filter[{index}] [{entry}] error: rule-set behavior is ipcidr, must be domain or classical"
                )));
            }
            FakeIpRuleMatcher::RuleSet {
                name: payload,
                domains: provider.domains.clone(),
            }
        }
        _ => {
            return Err(ConfigError::InvalidDns(format!(
                "dns.fake-ip-filter[{index}] [{entry}] error: rule type '{kind}' not supported, only domain-based rules allowed"
            )));
        }
    };
    Ok(FakeIpRule { matcher, action })
}

fn parse_fake_ip_range(value: &str, ipv6: bool, field: &str) -> Result<Option<IpNet>, ConfigError> {
    if value.is_empty() {
        return Ok(None);
    }
    let network: IpNet = value
        .parse()
        .map_err(|_| ConfigError::InvalidDns(format!("invalid {field}")))?;
    if network.addr().is_ipv6() != ipv6 {
        return Err(ConfigError::InvalidDns(format!(
            "{field} has the wrong address family"
        )));
    }
    let host_bits = if ipv6 { 128 } else { 32 } - usize::from(network.prefix_len());
    if host_bits < 3 {
        return Err(ConfigError::InvalidDns(format!(
            "{field} does not contain a valid fake-IP pool"
        )));
    }
    Ok(Some(network))
}

pub(crate) fn parse_hosts(raw: BTreeMap<String, RawHostValue>) -> Result<HostTable, ConfigError> {
    let mut hosts = HostTable::default();
    hosts.insert(
        "localhost".to_owned(),
        HostEntry::Addresses(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]),
    );
    for (name, raw_value) in raw {
        let Ok(name) = normalize_host_pattern(&name) else {
            continue;
        };
        let mut values = match raw_value {
            RawHostValue::One(value) => vec![value],
            RawHostValue::Many(values) => values,
        };
        if values == ["lan"] {
            values = local_lan_addresses()?
                .into_iter()
                .map(|address| address.to_string())
                .collect();
        }
        if values.is_empty() {
            return Err(ConfigError::InvalidHosts(format!("{name} has no values")));
        }
        let entry = if values.len() == 1 {
            match values[0].parse::<IpAddr>() {
                Ok(address) => HostEntry::Addresses(vec![address.to_canonical()]),
                Err(_) => HostEntry::Domain(normalize_host_target(&values[0])?),
            }
        } else {
            let addresses = values
                .iter()
                .map(|value| {
                    value
                        .parse::<IpAddr>()
                        .map(|address| address.to_canonical())
                        .map_err(|_| {
                            ConfigError::InvalidHosts(format!(
                                "{name} mixes a domain with address values"
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            HostEntry::Addresses(addresses)
        };
        hosts.insert(name, entry);
    }
    validate_host_cycles(&hosts)?;
    Ok(hosts)
}

fn normalize_host_pattern(value: &str) -> Result<String, ConfigError> {
    if value.is_empty()
        || value.ends_with('.')
        || value.trim() != value
        || value.split('.').skip(1).any(str::is_empty)
    {
        return Err(ConfigError::InvalidHosts("invalid hosts key".to_owned()));
    }
    let labels: Vec<_> = value.split('.').collect();
    for (index, label) in labels.iter().enumerate() {
        if label.contains('+') && (*label != "+" || index != 0 || labels.len() == 1)
            || label.contains('*') && *label != "*"
        {
            return Err(ConfigError::InvalidHosts(
                "invalid hosts wildcard".to_owned(),
            ));
        }
    }
    Ok(value.to_lowercase())
}

fn normalize_host_target(value: &str) -> Result<String, ConfigError> {
    let value = value.trim_matches('.');
    if value.split('.').count() < 2 {
        return Err(ConfigError::InvalidHosts(
            "hosts domain target must contain at least two labels".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn normalize_host_name(value: &str, field: &str) -> Result<String, ConfigError> {
    let value = value.trim_matches('.').to_lowercase();
    if value.is_empty()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ConfigError::InvalidHosts(format!("invalid {field}")));
    }
    Ok(value)
}

fn local_lan_addresses() -> Result<Vec<IpAddr>, ConfigError> {
    let interfaces = NetworkInterface::show().map_err(|error| {
        ConfigError::InvalidHosts(format!("cannot list LAN addresses: {error}"))
    })?;
    let mut addresses = Vec::new();
    for address in interfaces
        .into_iter()
        .flat_map(|interface| interface.addr)
        .map(|address| match address {
            Addr::V4(address) => IpAddr::V4(address.ip),
            Addr::V6(address) => IpAddr::V6(address.ip),
        })
        .filter(|address| !address.is_loopback())
        .filter(|address| match address {
            IpAddr::V4(address) => !address.is_link_local(),
            IpAddr::V6(address) => !address.is_unicast_link_local(),
        })
    {
        let address = address.to_canonical();
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(ConfigError::InvalidHosts(
            "lan did not produce an eligible interface address".to_owned(),
        ));
    }
    Ok(addresses)
}

fn validate_host_cycles(hosts: &HostTable) -> Result<(), ConfigError> {
    for origin in hosts.keys() {
        let mut seen = std::collections::BTreeSet::new();
        let mut current = origin.as_str();
        while let Some(HostEntry::Domain(next)) = hosts.search(current) {
            if !seen.insert(current.to_lowercase()) {
                return Err(ConfigError::InvalidHosts(format!(
                    "{origin} has a domain mapping cycle"
                )));
            }
            current = next;
        }
    }
    Ok(())
}

fn parse_loopback_dns_addr(value: &str, field: &str) -> Result<SocketAddr, ConfigError> {
    let address = parse_dns_socket_addr(value, field)?;
    if !address.ip().is_loopback() {
        return Err(ConfigError::InvalidDns(format!(
            "{field} must be a nonzero loopback socket address"
        )));
    }
    Ok(address)
}

fn parse_dns_socket_addr(value: &str, field: &str) -> Result<SocketAddr, ConfigError> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| ConfigError::InvalidDns(format!("{field} must be an IP socket address")))?;
    if address.port() == 0 {
        return Err(ConfigError::InvalidDns(format!(
            "{field} must use a nonzero port"
        )));
    }
    Ok(address)
}
