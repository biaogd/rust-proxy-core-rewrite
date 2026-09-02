use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use ipnet::IpNet;
use rewrite_model::{Metadata, Network};

use crate::model::{
    Action, Decision, DomainRegex, DscpRange, GeoMatcherKind, Matcher, PortField, PortRange,
    ProviderBehavior, ProviderDefinition, Rule, RuleError,
};

pub(crate) fn parse_rule_list(
    lines: &[String],
    actions: &BTreeMap<String, Action>,
    sub_rules: &BTreeSet<String>,
    providers: &BTreeMap<String, ProviderDefinition>,
) -> Result<Vec<Rule>, RuleError> {
    lines
        .iter()
        .map(|line| parse_rule(line, actions, sub_rules, providers))
        .collect()
}

pub(crate) fn parse_rule(
    raw: &str,
    actions: &BTreeMap<String, Action>,
    sub_rules: &BTreeSet<String>,
    providers: &BTreeMap<String, ProviderDefinition>,
) -> Result<Rule, RuleError> {
    let fields = parse_rule_payload(raw, true);
    if fields.target.is_empty() {
        return Err(RuleError::FormatInvalid);
    }
    if fields.kind == "SUB-RULE" {
        if !sub_rules.contains(&fields.target) {
            return Err(RuleError::SubRuleNotFound(fields.target));
        }
    } else if !actions.contains_key(&fields.target) {
        return Err(RuleError::ProxyNotFound(fields.target));
    }
    let matcher = if fields.kind == "RULE-SET" {
        parse_rule_set(&fields.payload, &fields.params, providers)?
    } else if matches!(fields.kind.as_str(), "GEOSITE" | "GEOIP" | "SRC-GEOIP") {
        parse_geo_matcher(&fields.kind, &fields.payload, &fields.params, providers)?
    } else {
        parse_matcher(&fields.kind, &fields.payload, &fields.params)?
    };
    let matcher = if fields.kind == "SUB-RULE" {
        Matcher::SubRule {
            condition: Box::new(matcher),
            name: fields.target.clone(),
        }
    } else {
        matcher
    };
    Ok(Rule {
        matcher,
        target: fields.target,
    })
}

/// Returns the internal provider key used to pass already validated geodata
/// across the configuration/rule boundary.
#[must_use]
pub fn geodata_provider_key(kind: &str, payload: &str) -> String {
    format!(
        "__mihomo_rust_geo__{}__{}",
        kind.to_ascii_uppercase(),
        payload.to_ascii_uppercase()
    )
}

pub(crate) fn parse_geo_matcher(
    kind: &str,
    payload: &str,
    params: &[String],
    providers: &BTreeMap<String, ProviderDefinition>,
) -> Result<Matcher, RuleError> {
    if payload.is_empty() {
        return Err(RuleError::InvalidPayload);
    }
    let provider = providers
        .get(&geodata_provider_key(kind, payload))
        .ok_or_else(|| RuleError::Unsupported(format!("{kind}:{payload}")))?;
    let source = kind == "SRC-GEOIP" || params.iter().any(|param| param == "src");
    let no_resolve = source || params.iter().any(|param| param == "no-resolve");
    let matchers = match kind {
        "GEOSITE" if provider.behavior == ProviderBehavior::Classical => provider
            .payload
            .iter()
            .filter_map(|entry| {
                parse_provider_entry(ProviderBehavior::Classical, entry).transpose()
            })
            .collect::<Result<Vec<_>, _>>()?,
        "GEOIP" | "SRC-GEOIP" if provider.behavior == ProviderBehavior::IpCidr => provider
            .payload
            .iter()
            .map(|entry| parse_ip_cidr(entry, source, no_resolve))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(RuleError::Unsupported(format!("{kind}:{payload}"))),
    };
    let kind = match kind {
        "GEOSITE" => GeoMatcherKind::GeoSite,
        "GEOIP" => GeoMatcherKind::GeoIp,
        "SRC-GEOIP" => GeoMatcherKind::SrcGeoIp,
        _ => return Err(RuleError::Unsupported(kind.to_owned())),
    };
    let payload = if matches!(kind, GeoMatcherKind::GeoIp | GeoMatcherKind::SrcGeoIp) {
        payload.to_ascii_lowercase()
    } else {
        payload.to_owned()
    };
    Ok(Matcher::Geo {
        kind,
        payload,
        matchers,
    })
}

pub(crate) fn parse_rule_set(
    name: &str,
    params: &[String],
    providers: &BTreeMap<String, ProviderDefinition>,
) -> Result<Matcher, RuleError> {
    let provider = providers
        .get(name)
        .ok_or_else(|| RuleError::Unsupported(format!("RULE-SET:{name}")))?;
    let matchers = provider
        .payload
        .iter()
        .filter_map(|entry| parse_provider_entry(provider.behavior, entry).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Matcher::RuleSet {
        name: name.to_owned(),
        matchers,
        no_resolve: params.iter().any(|param| param == "no-resolve"),
    })
}

pub(crate) fn parse_provider_entry(
    behavior: ProviderBehavior,
    entry: &str,
) -> Result<Option<Matcher>, RuleError> {
    match behavior {
        ProviderBehavior::Domain => {
            let entry = entry.trim().to_lowercase();
            if entry.is_empty() || entry.contains('/') {
                return Ok(None);
            }
            if let Some(suffix) = entry.strip_prefix("+.") {
                require_payload(suffix, |value| Matcher::DomainSuffix(value.to_owned())).map(Some)
            } else if entry.contains(['*', '?']) {
                Ok(Some(Matcher::DomainWildcard(entry)))
            } else {
                Ok(Some(Matcher::Domain(entry)))
            }
        }
        ProviderBehavior::IpCidr => match parse_ip_cidr(entry.trim(), false, false) {
            Ok(matcher) => Ok(Some(matcher)),
            Err(_) => Ok(None),
        },
        ProviderBehavior::Classical => {
            let fields = parse_rule_payload(entry, false);
            if matches!(fields.kind.as_str(), "" | "MATCH" | "RULE-SET" | "SUB-RULE") {
                return Ok(None);
            }
            match parse_matcher(&fields.kind, &fields.payload, &fields.params) {
                Ok(matcher) => Ok(Some(matcher)),
                Err(_) => Ok(None),
            }
        }
    }
}

pub(crate) struct RuleFields {
    kind: String,
    payload: String,
    target: String,
    params: Vec<String>,
}

pub(crate) fn parse_rule_payload(raw: &str, need_target: bool) -> RuleFields {
    let mut items: Vec<_> = raw.split(',').map(str::trim).collect();
    let kind = items
        .first()
        .map_or(String::new(), |item| item.to_uppercase());
    let mut payload = String::new();
    let mut target = String::new();
    let mut params = Vec::new();
    if items.len() > 1 {
        match kind.as_str() {
            "MATCH" => items[1].clone_into(&mut target),
            "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX" => {
                if need_target {
                    items.pop().unwrap_or_default().clone_into(&mut target);
                }
                payload = items[1..].join(",");
            }
            _ => {
                items[1].clone_into(&mut payload);
                if items.len() > 2 {
                    if need_target {
                        items[2].clone_into(&mut target);
                        params.extend(items[3..].iter().map(|item| (*item).to_owned()));
                    } else {
                        params.extend(items[2..].iter().map(|item| (*item).to_owned()));
                    }
                }
            }
        }
    }
    RuleFields {
        kind,
        payload,
        target,
        params,
    }
}

pub(crate) fn parse_matcher(
    kind: &str,
    payload: &str,
    params: &[String],
) -> Result<Matcher, RuleError> {
    match kind {
        "MATCH" => Ok(Matcher::Match),
        "DOMAIN" => require_payload(payload, |value| Matcher::Domain(value.to_lowercase())),
        "DOMAIN-SUFFIX" => {
            require_payload(payload, |value| Matcher::DomainSuffix(value.to_lowercase()))
        }
        "DOMAIN-KEYWORD" => require_payload(payload, |value| {
            Matcher::DomainKeyword(value.to_lowercase())
        }),
        "DOMAIN-REGEX" => parse_domain_regex(payload),
        "DOMAIN-WILDCARD" => require_payload(payload, |value| {
            Matcher::DomainWildcard(value.to_lowercase())
        }),
        "IP-CIDR" | "IP-CIDR6" => parse_ip_cidr(
            payload,
            params.iter().any(|param| param == "src"),
            params.iter().any(|param| param == "no-resolve"),
        ),
        "SRC-IP-CIDR" => parse_ip_cidr(payload, true, true),
        "IP-SUFFIX" => parse_ip_suffix(
            payload,
            params.iter().any(|param| param == "src"),
            params.iter().any(|param| param == "no-resolve"),
        ),
        "SRC-IP-SUFFIX" => parse_ip_suffix(payload, true, true),
        "SRC-PORT" => parse_port(payload, PortField::Source),
        "DST-PORT" => parse_port(payload, PortField::Destination),
        "IN-PORT" => parse_port(payload, PortField::Inbound),
        "NETWORK" => match payload.to_uppercase().as_str() {
            "TCP" => Ok(Matcher::Network(Network::Tcp)),
            "UDP" => Ok(Matcher::Network(Network::Udp)),
            _ => Err(RuleError::Unsupported("NETWORK".to_owned())),
        },
        "IN-TYPE" => parse_in_type(payload),
        "IN-USER" => parse_in_user(payload),
        "IN-NAME" => parse_in_name(payload),
        "DSCP" => parse_dscp(payload),
        "REMATCH-NAME" => {
            let names: Vec<_> = payload
                .split('/')
                .map(str::trim)
                .map(str::to_owned)
                .collect();
            if names.iter().any(String::is_empty) {
                Err(RuleError::InvalidPayload)
            } else {
                Ok(Matcher::RematchName(names))
            }
        }
        "AND" => Ok(Matcher::And(parse_logic_children(payload)?)),
        "OR" => Ok(Matcher::Or(parse_logic_children(payload)?)),
        "NOT" => {
            let children = parse_logic_children(payload)?;
            let [child] = children.try_into().map_err(|_| RuleError::InvalidPayload)?;
            Ok(Matcher::Not(Box::new(child)))
        }
        "SUB-RULE" => {
            let wrapped = format!("({payload})");
            let children = parse_logic_children(&wrapped)?;
            let [child] = children.try_into().map_err(|_| RuleError::InvalidPayload)?;
            Ok(child)
        }
        "" => Err(RuleError::FormatInvalid),
        other => Err(RuleError::Unsupported(other.to_owned())),
    }
}

pub(crate) fn parse_domain_regex(payload: &str) -> Result<Matcher, RuleError> {
    if payload.is_empty() {
        return Err(RuleError::InvalidPayload);
    }
    let expression = fancy_regex::Regex::new(&format!("(?i:{payload})"))
        .map_err(|_| RuleError::InvalidPayload)?;
    Ok(Matcher::DomainRegex(DomainRegex {
        pattern: payload.to_owned(),
        expression,
    }))
}

pub(crate) fn domain_wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star, mut star_value) = (None, 0);
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index += 1;
            star_value = value_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            star_value += 1;
            value_index = star_value;
        } else {
            return false;
        }
    }
    pattern[pattern_index..].iter().all(|byte| *byte == b'*')
}

pub(crate) fn require_payload(
    payload: &str,
    make: impl FnOnce(&str) -> Matcher,
) -> Result<Matcher, RuleError> {
    if payload.is_empty() {
        Err(RuleError::InvalidPayload)
    } else {
        Ok(make(payload))
    }
}

pub(crate) fn parse_ip_cidr(
    payload: &str,
    source: bool,
    no_resolve: bool,
) -> Result<Matcher, RuleError> {
    let network = IpNet::from_str(payload).map_err(|_| RuleError::InvalidPayload)?;
    Ok(Matcher::IpCidr {
        network,
        source,
        no_resolve,
    })
}

pub(crate) fn parse_ip_suffix(
    payload: &str,
    source: bool,
    no_resolve: bool,
) -> Result<Matcher, RuleError> {
    let (address, bits) = payload.split_once('/').ok_or(RuleError::InvalidPayload)?;
    let address = std::net::IpAddr::from_str(address).map_err(|_| RuleError::InvalidPayload)?;
    let bits = bits.parse::<u8>().map_err(|_| RuleError::InvalidPayload)?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if bits > maximum {
        return Err(RuleError::InvalidPayload);
    }
    Ok(Matcher::IpSuffix {
        address,
        bits,
        source,
        no_resolve: no_resolve || source,
    })
}

pub(crate) fn parse_in_type(payload: &str) -> Result<Matcher, RuleError> {
    let mut types = Vec::new();
    for value in payload.split('/').map(str::trim) {
        match value.to_ascii_uppercase().as_str() {
            "HTTP" => types.push(rewrite_model::InboundProtocol::Http),
            "HTTPS" => types.push(rewrite_model::InboundProtocol::Https),
            "SOCKS4" => types.push(rewrite_model::InboundProtocol::Socks4),
            "SOCKS5" => types.push(rewrite_model::InboundProtocol::Socks5),
            "SHADOWSOCKS" | "SS" => types.push(rewrite_model::InboundProtocol::Shadowsocks),
            "INNER" => types.push(rewrite_model::InboundProtocol::Inner),
            "SOCKS" => types.extend([
                rewrite_model::InboundProtocol::Socks4,
                rewrite_model::InboundProtocol::Socks5,
            ]),
            _ => return Err(RuleError::InvalidPayload),
        }
    }
    if types.is_empty() {
        return Err(RuleError::InvalidPayload);
    }
    Ok(Matcher::InType(types))
}

pub(crate) fn parse_in_user(payload: &str) -> Result<Matcher, RuleError> {
    let users = payload
        .split('/')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if users.is_empty() || users.iter().any(String::is_empty) {
        return Err(RuleError::InvalidPayload);
    }
    Ok(Matcher::InUser(users))
}

pub(crate) fn parse_in_name(payload: &str) -> Result<Matcher, RuleError> {
    let names = payload
        .split('/')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.is_empty() || names.iter().any(String::is_empty) {
        return Err(RuleError::InvalidPayload);
    }
    Ok(Matcher::InName(names))
}

pub(crate) fn parse_dscp(payload: &str) -> Result<Matcher, RuleError> {
    if payload == "*" {
        return Ok(Matcher::Dscp(Vec::new()));
    }
    let parts = payload.split('/').filter(|part| !part.is_empty());
    let mut ranges = Vec::new();
    for part in parts {
        let bounds = part.split('-').map(str::trim).collect::<Vec<_>>();
        let (start, end) = match bounds.as_slice() {
            [single] => {
                let value = parse_dscp_value(single)?;
                (value, value)
            }
            [start, end] => {
                let start = parse_dscp_value(start)?;
                let end = parse_dscp_value(end)?;
                (start.min(end), start.max(end))
            }
            _ => return Err(RuleError::InvalidPayload),
        };
        ranges.push(DscpRange { start, end });
        if ranges.len() > 28 {
            return Err(RuleError::InvalidPayload);
        }
    }
    if ranges.is_empty() {
        return Err(RuleError::InvalidPayload);
    }
    Ok(Matcher::Dscp(ranges))
}

pub(crate) fn parse_dscp_value(value: &str) -> Result<u8, RuleError> {
    let value = value.parse::<u8>().map_err(|_| RuleError::InvalidPayload)?;
    (value <= 63)
        .then_some(value)
        .ok_or(RuleError::InvalidPayload)
}

pub(crate) fn ip_suffix_matches(
    pattern: std::net::IpAddr,
    bits: u8,
    candidate: std::net::IpAddr,
) -> bool {
    let pattern = ip_address_bytes(pattern);
    let candidate = ip_address_bytes(candidate);
    if pattern.len() != candidate.len() {
        return false;
    }
    let full_bytes = usize::from(bits / 8);
    let remaining_bits = bits % 8;
    let size = pattern.len();
    if pattern[size - full_bytes..] != candidate[size - full_bytes..] {
        return false;
    }
    remaining_bits == 0
        || pattern[size - full_bytes - 1] << (8 - remaining_bits)
            == candidate[size - full_bytes - 1] << (8 - remaining_bits)
}

pub(crate) fn ip_address_bytes(address: std::net::IpAddr) -> Vec<u8> {
    match address {
        std::net::IpAddr::V4(address) => address.octets().to_vec(),
        std::net::IpAddr::V6(address) => address.octets().to_vec(),
    }
}

pub(crate) fn parse_port(payload: &str, field: PortField) -> Result<Matcher, RuleError> {
    let normalized = payload.trim().replace(',', "/");
    if normalized.is_empty() || normalized == "*" {
        return Err(RuleError::InvalidPayload);
    }
    let parts: Vec<_> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() || parts.len() > 28 {
        return Err(RuleError::InvalidPayload);
    }
    let mut ranges = Vec::with_capacity(parts.len());
    for part in parts {
        let bounds: Vec<_> = part.split('-').map(str::trim).collect();
        let (start, end) = match bounds.as_slice() {
            [single] => {
                let value = parse_port_number(single)?;
                (value, value)
            }
            [start, end] => (parse_port_number(start)?, parse_port_number(end)?),
            _ => return Err(RuleError::InvalidPayload),
        };
        ranges.push(PortRange {
            start: start.min(end),
            end: start.max(end),
        });
    }
    Ok(Matcher::Port { ranges, field })
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn parse_port_number(value: &str) -> Result<u16, RuleError> {
    let parsed = value
        .trim_matches(['[', ']', ' '])
        .parse::<u64>()
        .map_err(|_| RuleError::InvalidPayload)?;
    // The Go oracle parses into uint64 and then converts to uint16, including
    // wraparound. Preserve that observable compatibility at this boundary.
    Ok(parsed as u16)
}

pub(crate) fn parse_logic_children(payload: &str) -> Result<Vec<Matcher>, RuleError> {
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return Err(RuleError::FormatInvalid);
    }
    let mut stack = Vec::new();
    let mut ranges = Vec::new();
    for (index, character) in payload.char_indices() {
        match character {
            '(' => stack.push(index),
            ')' => {
                let start = stack.pop().ok_or(RuleError::FormatInvalid)?;
                ranges.push((start, index));
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(RuleError::FormatInvalid);
    }
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut immediate: Vec<(usize, usize)> = Vec::new();
    for range in ranges {
        if range == (0, payload.len() - 1) {
            continue;
        }
        if immediate
            .iter()
            .any(|(start, end)| *start < range.0 && *end > range.1)
        {
            continue;
        }
        immediate.push(range);
    }

    immediate
        .into_iter()
        .map(|(start, end)| {
            let child = &payload[(start + 1)..end];
            let fields = parse_rule_payload(child, false);
            if matches!(fields.kind.as_str(), "MATCH" | "SUB-RULE" | "") {
                return Err(RuleError::Unsupported(fields.kind));
            }
            parse_matcher(&fields.kind, &fields.payload, &fields.params)
        })
        .collect()
}

pub(crate) fn verify_sub_rule_cycles(
    sub_rules: &BTreeMap<String, Vec<Rule>>,
) -> Result<(), RuleError> {
    for name in sub_rules.keys() {
        visit_sub_rule(name, sub_rules, &mut Vec::new())?;
    }
    Ok(())
}

pub(crate) fn visit_sub_rule(
    name: &str,
    sub_rules: &BTreeMap<String, Vec<Rule>>,
    chain: &mut Vec<String>,
) -> Result<(), RuleError> {
    chain.push(name.to_owned());
    if let Some(rules) = sub_rules.get(name) {
        for rule in rules {
            if let Matcher::SubRule { name: target, .. } = &rule.matcher {
                if let Some(position) = chain.iter().position(|name| name == target) {
                    let mut cycle = chain[position..].to_vec();
                    cycle.push(target.clone());
                    return Err(RuleError::SubRuleCycle(cycle.join("->")));
                }
                visit_sub_rule(target, sub_rules, chain)?;
            }
        }
    }
    chain.pop();
    Ok(())
}

pub(crate) fn make_decision(
    target: String,
    matched_kind: Option<String>,
    rematch_cycle: bool,
    metadata: &Metadata,
) -> Decision {
    Decision {
        target,
        matched_kind,
        rematch_cycle,
        rematch_name: metadata.rematch_name.clone(),
        special_rules: metadata.special_rules.clone(),
    }
}
