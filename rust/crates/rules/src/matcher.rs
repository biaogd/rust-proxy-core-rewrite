use rewrite_model::{Metadata, Network};

use crate::model::{GeoMatcherKind, MatchResult, Matcher, PortField};
use crate::parser::{domain_wildcard_matches, ip_suffix_matches};

impl Matcher {
    pub(crate) fn record_size(&self) -> i64 {
        match self {
            Self::Geo {
                kind: GeoMatcherKind::GeoIp,
                payload,
                ..
            } if payload.eq_ignore_ascii_case("lan") => 0,
            Self::Geo {
                kind: GeoMatcherKind::GeoSite | GeoMatcherKind::GeoIp,
                matchers,
                ..
            } => i64::try_from(matchers.len()).unwrap_or(i64::MAX),
            _ => -1,
        }
    }

    pub(crate) fn match_result(&self, metadata: &Metadata, allow_resolution: bool) -> MatchResult {
        match self {
            Self::Match => MatchResult::Matched,
            Self::Domain(domain) => MatchResult::from_bool(metadata.rule_host() == domain),
            Self::DomainSuffix(suffix) => MatchResult::from_bool(
                metadata.rule_host() == suffix
                    || metadata
                        .rule_host()
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.')),
            ),
            Self::DomainKeyword(keyword) => {
                MatchResult::from_bool(metadata.rule_host().contains(keyword))
            }
            Self::DomainRegex(regex) => MatchResult::from_bool(
                regex
                    .expression
                    .is_match(metadata.rule_host())
                    .unwrap_or(false),
            ),
            Self::DomainWildcard(pattern) => {
                MatchResult::from_bool(domain_wildcard_matches(pattern, metadata.rule_host()))
            }
            Self::IpCidr {
                network,
                source,
                no_resolve,
            } => match_ip_address(
                metadata,
                *source,
                *no_resolve,
                allow_resolution,
                |address| network.contains(&address),
            ),
            Self::IpSuffix {
                address,
                bits,
                source,
                no_resolve,
            } => match_ip_address(
                metadata,
                *source,
                *no_resolve,
                allow_resolution,
                |candidate| ip_suffix_matches(*address, *bits, candidate),
            ),
            Self::Port { ranges, field } => {
                let port = match field {
                    PortField::Source => metadata.source_port,
                    PortField::Destination => metadata.destination.port,
                    PortField::Inbound => metadata.inbound_port,
                };
                MatchResult::from_bool(
                    ranges
                        .iter()
                        .any(|range| (range.start..=range.end).contains(&port)),
                )
            }
            Self::Network(network) => MatchResult::from_bool(metadata.network == *network),
            Self::InType(types) => MatchResult::from_bool(types.contains(&metadata.inbound)),
            Self::InUser(users) => MatchResult::from_bool(users.contains(&metadata.inbound_user)),
            Self::InName(names) => MatchResult::from_bool(names.contains(&metadata.inbound_name)),
            Self::Dscp(ranges) => MatchResult::from_bool(
                ranges.is_empty()
                    || ranges
                        .iter()
                        .any(|range| (range.start..=range.end).contains(&metadata.dscp)),
            ),
            Self::RematchName(names) => {
                MatchResult::from_bool(names.contains(&metadata.rematch_name))
            }
            Self::And(matchers) => match_all(matchers, metadata, allow_resolution),
            Self::Or(matchers) => match_any(matchers, metadata, allow_resolution),
            Self::Not(matcher) => match matcher.match_result(metadata, allow_resolution) {
                MatchResult::Matched => MatchResult::Unmatched,
                MatchResult::Unmatched => MatchResult::Matched,
                MatchResult::ResolveDestinationIp => MatchResult::ResolveDestinationIp,
            },
            Self::SubRule { condition, .. } => condition.match_result(metadata, allow_resolution),
            Self::RuleSet {
                matchers,
                no_resolve,
                ..
            } => match_provider(matchers, metadata, allow_resolution && !no_resolve),
            Self::Geo { matchers, .. } => match_provider(matchers, metadata, allow_resolution),
        }
    }

    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Match => "Match",
            Self::Domain(_) => "Domain",
            Self::DomainSuffix(_) => "DomainSuffix",
            Self::DomainKeyword(_) => "DomainKeyword",
            Self::DomainRegex(_) => "DomainRegex",
            Self::DomainWildcard(_) => "DomainWildcard",
            Self::IpCidr { source: true, .. } => "SrcIPCIDR",
            Self::IpCidr { source: false, .. } => "IPCIDR",
            Self::IpSuffix { source: true, .. } => "SrcIPSuffix",
            Self::IpSuffix { source: false, .. } => "IPSuffix",
            Self::Port {
                field: PortField::Source,
                ..
            } => "SrcPort",
            Self::Port {
                field: PortField::Destination,
                ..
            } => "DstPort",
            Self::Port {
                field: PortField::Inbound,
                ..
            } => "InPort",
            Self::Network(_) => "Network",
            Self::InType(_) => "InType",
            Self::InUser(_) => "InUser",
            Self::InName(_) => "InName",
            Self::Dscp(_) => "DSCP",
            Self::RematchName(_) => "RematchName",
            Self::And(_) => "AND",
            Self::Or(_) => "OR",
            Self::Not(_) => "NOT",
            Self::SubRule { .. } => "SubRules",
            Self::RuleSet { .. } => "RuleSet",
            Self::Geo {
                kind: GeoMatcherKind::GeoSite,
                ..
            } => "GeoSite",
            Self::Geo {
                kind: GeoMatcherKind::GeoIp,
                ..
            } => "GeoIP",
            Self::Geo {
                kind: GeoMatcherKind::SrcGeoIp,
                ..
            } => "SrcGeoIP",
        }
    }

    pub(crate) fn payload(&self) -> String {
        match self {
            Self::Domain(value)
            | Self::DomainSuffix(value)
            | Self::DomainKeyword(value)
            | Self::DomainWildcard(value) => value.clone(),
            Self::DomainRegex(regex) => regex.pattern.clone(),
            Self::IpCidr { network, .. } => network.to_string(),
            Self::IpSuffix { address, bits, .. } => format!("{address}/{bits}"),
            Self::Port { ranges, .. } => ranges
                .iter()
                .map(|range| {
                    if range.start == range.end {
                        range.start.to_string()
                    } else {
                        format!("{}-{}", range.start, range.end)
                    }
                })
                .collect::<Vec<_>>()
                .join("/"),
            Self::Network(network) => match network {
                Network::Tcp => "TCP".to_owned(),
                Network::Udp => "UDP".to_owned(),
            },
            Self::InType(types) => types
                .iter()
                .map(|kind| format!("{kind:?}").to_uppercase())
                .collect::<Vec<_>>()
                .join("/"),
            Self::InName(names) | Self::InUser(names) | Self::RematchName(names) => names.join("/"),
            Self::RuleSet { name, .. } => name.clone(),
            Self::Geo { payload, .. } => payload.clone(),
            Self::Dscp(ranges) => ranges
                .iter()
                .map(|range| {
                    if range.start == range.end {
                        range.start.to_string()
                    } else {
                        format!("{}-{}", range.start, range.end)
                    }
                })
                .collect::<Vec<_>>()
                .join("/"),
            Self::Match | Self::And(_) | Self::Or(_) | Self::Not(_) | Self::SubRule { .. } => {
                String::new()
            }
        }
    }
}

pub(crate) fn match_all(
    matchers: &[Matcher],
    metadata: &Metadata,
    allow_resolution: bool,
) -> MatchResult {
    for matcher in matchers {
        match matcher.match_result(metadata, allow_resolution) {
            MatchResult::Matched => {}
            result => return result,
        }
    }
    MatchResult::Matched
}

pub(crate) fn match_any(
    matchers: &[Matcher],
    metadata: &Metadata,
    allow_resolution: bool,
) -> MatchResult {
    for matcher in matchers {
        match matcher.match_result(metadata, allow_resolution) {
            MatchResult::Unmatched => {}
            result => return result,
        }
    }
    MatchResult::Unmatched
}

pub(crate) fn match_provider(
    matchers: &[Matcher],
    metadata: &Metadata,
    allow_resolution: bool,
) -> MatchResult {
    let mut pending_resolution = false;
    for matcher in matchers {
        match matcher.match_result(metadata, allow_resolution) {
            MatchResult::Matched => return MatchResult::Matched,
            MatchResult::Unmatched => {}
            MatchResult::ResolveDestinationIp => pending_resolution = true,
        }
    }
    if pending_resolution {
        MatchResult::ResolveDestinationIp
    } else {
        MatchResult::Unmatched
    }
}

impl MatchResult {
    const fn from_bool(value: bool) -> Self {
        if value {
            Self::Matched
        } else {
            Self::Unmatched
        }
    }
}

pub(crate) fn match_ip_address(
    metadata: &Metadata,
    source: bool,
    no_resolve: bool,
    allow_resolution: bool,
    predicate: impl FnOnce(std::net::IpAddr) -> bool,
) -> MatchResult {
    let address = if source {
        metadata.source_ip
    } else {
        metadata.destination_ip
    };
    match address {
        Some(address) => MatchResult::from_bool(predicate(address)),
        None if !source && !no_resolve && allow_resolution => MatchResult::ResolveDestinationIp,
        None => MatchResult::Unmatched,
    }
}
