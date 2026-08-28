use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use rewrite_config::{
    Config, DnsConfig, DnsPolicyMatcher, EcsConfig, FakeIpConfig, FakeIpFilterMode,
    FakeIpRuleAction, FakeIpRuleMatcher, HostEntry,
};
use rewrite_state::RuntimeState;

use crate::cache::skip_name;
use crate::server::{HostLookup, Question};
use crate::wire::{policy_matcher_matches, validate_query};
use crate::{DNS_HEADER_LENGTH, DnsError};

pub(crate) fn empty_upstream_answer(query: &[u8], question: &Question) -> Vec<u8> {
    let mut response = query[..question.end].to_vec();
    response[2] = 0x84 | (query[2] & 0x79);
    response[3] = (query[3] & 0xf0) | 0x80;
    response[6..12].fill(0);
    response
}

pub(crate) fn apply_ecs(query: &[u8], ecs: EcsConfig) -> Result<Vec<u8>, DnsError> {
    let questions = usize::from(u16::from_be_bytes([query[4], query[5]]));
    let answers = usize::from(u16::from_be_bytes([query[6], query[7]]));
    let authorities = usize::from(u16::from_be_bytes([query[8], query[9]]));
    let additionals = usize::from(u16::from_be_bytes([query[10], query[11]]));
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(query, offset)?;
        offset = checked_record_end(query, offset, 4, "question is truncated")?;
    }
    for _ in 0..answers + authorities {
        offset = resource_record_end(query, offset)?.1;
    }

    let option = ecs_option(ecs);
    for _ in 0..additionals {
        let start = offset;
        let name_end = skip_name(query, start)?;
        let (record_type, end) = resource_record_end(query, start)?;
        if record_type == 41 {
            let data_length_offset = name_end + 8;
            let data_start = name_end + 10;
            let mut option_offset = data_start;
            while option_offset < end {
                if option_offset + 4 > end {
                    return Err(DnsError::InvalidMessage("EDNS option is truncated"));
                }
                let code = u16::from_be_bytes([query[option_offset], query[option_offset + 1]]);
                let length = usize::from(u16::from_be_bytes([
                    query[option_offset + 2],
                    query[option_offset + 3],
                ]));
                let option_end = checked_record_end(
                    query,
                    option_offset + 4,
                    length,
                    "EDNS option data is truncated",
                )?;
                if code == 8 {
                    if !ecs.override_existing {
                        return Ok(query.to_vec());
                    }
                    let mut rewritten = Vec::with_capacity(query.len() + option.len());
                    rewritten.extend_from_slice(&query[..option_offset]);
                    rewritten.extend_from_slice(&option);
                    rewritten.extend_from_slice(&query[option_end..]);
                    let old_data_length = end - data_start;
                    let new_data_length =
                        old_data_length - (option_end - option_offset) + option.len();
                    rewritten[data_length_offset..data_length_offset + 2].copy_from_slice(
                        &u16::try_from(new_data_length)
                            .map_err(|_| DnsError::InvalidMessage("EDNS option data is too large"))?
                            .to_be_bytes(),
                    );
                    return Ok(rewritten);
                }
                option_offset = option_end;
            }
            let mut rewritten = Vec::with_capacity(query.len() + option.len());
            rewritten.extend_from_slice(&query[..end]);
            rewritten.extend_from_slice(&option);
            rewritten.extend_from_slice(&query[end..]);
            let new_data_length = end - data_start + option.len();
            rewritten[data_length_offset..data_length_offset + 2].copy_from_slice(
                &u16::try_from(new_data_length)
                    .map_err(|_| DnsError::InvalidMessage("EDNS option data is too large"))?
                    .to_be_bytes(),
            );
            return Ok(rewritten);
        }
        offset = end;
    }

    let mut rewritten = query.to_vec();
    rewritten[10..12].copy_from_slice(
        &u16::try_from(additionals + 1)
            .map_err(|_| DnsError::InvalidMessage("too many additional records"))?
            .to_be_bytes(),
    );
    rewritten.push(0);
    rewritten.extend_from_slice(&41_u16.to_be_bytes());
    rewritten.extend_from_slice(&0_u16.to_be_bytes());
    rewritten.extend_from_slice(&0_u32.to_be_bytes());
    rewritten.extend_from_slice(
        &u16::try_from(option.len())
            .map_err(|_| DnsError::InvalidMessage("ECS option is too large"))?
            .to_be_bytes(),
    );
    rewritten.extend_from_slice(&option);
    Ok(rewritten)
}

pub(crate) fn ecs_option(ecs: EcsConfig) -> Vec<u8> {
    let (family, mut address) = match ecs.address {
        IpAddr::V4(address) => (1_u16, address.octets().to_vec()),
        IpAddr::V6(address) => (2_u16, address.octets().to_vec()),
    };
    let address_length = usize::from(ecs.prefix).div_ceil(8);
    address.truncate(address_length);
    if !ecs.prefix.is_multiple_of(8)
        && let Some(last) = address.last_mut()
    {
        *last &= u8::MAX << (8 - ecs.prefix % 8);
    }
    let data_length = 4_u16 + u16::from(ecs.prefix.div_ceil(8));
    let mut option = Vec::with_capacity(4 + usize::from(data_length));
    option.extend_from_slice(&8_u16.to_be_bytes());
    option.extend_from_slice(&data_length.to_be_bytes());
    option.extend_from_slice(&family.to_be_bytes());
    option.push(ecs.prefix);
    option.push(0);
    option.extend_from_slice(&address);
    option
}

pub(crate) fn filter_disabled_records(
    message: &[u8],
    disabled_types: &[u16],
) -> Result<Vec<u8>, DnsError> {
    if disabled_types.is_empty() {
        return Ok(message.to_vec());
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let section_counts = [
        usize::from(u16::from_be_bytes([message[6], message[7]])),
        usize::from(u16::from_be_bytes([message[8], message[9]])),
        usize::from(u16::from_be_bytes([message[10], message[11]])),
    ];
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    let mut filtered = message[..offset].to_vec();
    let mut retained = [0_u16; 3];
    for (section, count) in section_counts.into_iter().enumerate() {
        for _ in 0..count {
            let start = offset;
            let (record_type, end) = resource_record_end(message, start)?;
            if !disabled_types.contains(&record_type) {
                filtered.extend_from_slice(&message[start..end]);
                retained[section] += 1;
            }
            offset = end;
        }
    }
    filtered[6..8].copy_from_slice(&retained[0].to_be_bytes());
    filtered[8..10].copy_from_slice(&retained[1].to_be_bytes());
    filtered[10..12].copy_from_slice(&retained[2].to_be_bytes());
    Ok(filtered)
}

pub(crate) fn resource_record_end(message: &[u8], start: usize) -> Result<(u16, usize), DnsError> {
    let name_end = skip_name(message, start)?;
    if name_end + 10 > message.len() {
        return Err(DnsError::InvalidMessage("resource record is truncated"));
    }
    let record_type = u16::from_be_bytes([message[name_end], message[name_end + 1]]);
    let data_length = usize::from(u16::from_be_bytes([
        message[name_end + 8],
        message[name_end + 9],
    ]));
    let end = checked_record_end(
        message,
        name_end + 10,
        data_length,
        "resource data is truncated",
    )?;
    Ok((record_type, end))
}

pub(crate) fn lookup_host(name: &str, config: &Config, dns: &DnsConfig) -> Option<HostLookup> {
    let mut current = name;
    let mut followed_alias = false;
    loop {
        match config.hosts.search(current) {
            Some(HostEntry::Addresses(addresses)) => {
                return Some(HostLookup::Addresses(addresses.clone()));
            }
            Some(HostEntry::Domain(next)) => {
                current = next;
                followed_alias = true;
            }
            None if followed_alias => {
                return Some(HostLookup::ExternalAlias(current.to_owned()));
            }
            None => break,
        }
    }
    dns.use_system_hosts
        .then(|| system_host_addresses(name))
        .flatten()
        .map(HostLookup::Addresses)
}

pub(crate) fn matches_address_type(address: IpAddr, record_type: u16) -> bool {
    matches!(
        (address, record_type),
        (IpAddr::V4(_), 1) | (IpAddr::V6(_), 28)
    )
}

pub(crate) fn host_response(
    query: &[u8],
    question: &Question,
    addresses: &[IpAddr],
    cname: Option<&str>,
) -> Vec<u8> {
    let answers = addresses.len() + usize::from(cname.is_some());
    let mut response = response_prefix(query, question, answers);
    if let Some(target) = cname {
        push_cname(&mut response, target);
    }
    for address in addresses {
        push_address(&mut response, NameOwner::Question, *address, 10);
    }
    response
}

pub(crate) fn fake_ip_response(
    query: &[u8],
    question: &Question,
    address: Option<IpAddr>,
    ttl: u32,
) -> Vec<u8> {
    let mut response = response_prefix(query, question, usize::from(address.is_some()));
    if let Some(address) = address {
        push_address(&mut response, NameOwner::Question, address, ttl.max(1));
    }
    response
}

pub(crate) fn fake_ip_skipped(host: &str, config: &FakeIpConfig) -> bool {
    if config.filter_mode == FakeIpFilterMode::Rule {
        return config
            .rules
            .iter()
            .find_map(|rule| {
                fake_ip_rule_matches(&rule.matcher, host)
                    .then_some(rule.action == FakeIpRuleAction::RealIp)
            })
            .unwrap_or(false);
    }
    let matched = config
        .filter
        .iter()
        .any(|matcher| policy_matcher_matches(matcher, host));
    match config.filter_mode {
        FakeIpFilterMode::Blacklist => matched,
        FakeIpFilterMode::Whitelist => !matched,
        FakeIpFilterMode::Rule => unreachable!("rule mode returned above"),
    }
}

pub(crate) fn fake_ip_rule_matches(matcher: &FakeIpRuleMatcher, host: &str) -> bool {
    match matcher {
        FakeIpRuleMatcher::Domain(domain) => host.eq_ignore_ascii_case(domain),
        FakeIpRuleMatcher::DomainSuffix(suffix) => {
            host.eq_ignore_ascii_case(suffix)
                || host
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }
        FakeIpRuleMatcher::DomainKeyword(keyword) => host.contains(keyword),
        FakeIpRuleMatcher::DomainRegex(pattern) => {
            regex::Regex::new(pattern).is_ok_and(|expression| expression.is_match(host))
        }
        FakeIpRuleMatcher::DomainWildcard(pattern) => wildcard_matches(pattern, host),
        FakeIpRuleMatcher::Geosite { name, domains } => policy_matcher_matches(
            &DnsPolicyMatcher::Geosite {
                name: name.clone(),
                domains: domains.clone(),
            },
            host,
        ),
        FakeIpRuleMatcher::RuleSet { name, domains } => policy_matcher_matches(
            &DnsPolicyMatcher::RuleSet {
                name: name.clone(),
                domains: domains.clone(),
            },
            host,
        ),
        FakeIpRuleMatcher::Match => true,
    }
}

pub(crate) fn wildcard_matches(pattern: &str, value: &str) -> bool {
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

pub(crate) fn alias_response(
    query: &[u8],
    question: &Question,
    target: &str,
    addresses: &[(IpAddr, u32)],
) -> Vec<u8> {
    let mut response = response_prefix(query, question, addresses.len() + 1);
    push_cname(&mut response, target);
    for (address, ttl) in addresses {
        push_address(&mut response, NameOwner::Domain(target), *address, *ttl);
    }
    response
}

#[derive(Clone, Copy)]
pub(crate) enum NameOwner<'a> {
    Question,
    Domain(&'a str),
}

pub(crate) fn response_prefix(query: &[u8], question: &Question, answers: usize) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len() + answers * 32);
    response.extend_from_slice(&query[..2]);
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let flags = 0x8480 | (request_flags & 0x0110);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&u16::try_from(answers).unwrap_or(u16::MAX).to_be_bytes());
    response.extend_from_slice(&[0; 4]);
    response.extend_from_slice(&query[DNS_HEADER_LENGTH..question.end]);
    response
}

pub(crate) fn push_cname(response: &mut Vec<u8>, target: &str) {
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&5_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&10_u32.to_be_bytes());
    let encoded = encode_name(target);
    response.extend_from_slice(
        &u16::try_from(encoded.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    response.extend_from_slice(&encoded);
}

pub(crate) fn push_address(
    response: &mut Vec<u8>,
    owner: NameOwner<'_>,
    address: IpAddr,
    ttl: u32,
) {
    match owner {
        NameOwner::Question => response.extend_from_slice(&[0xc0, 0x0c]),
        NameOwner::Domain(domain) => response.extend_from_slice(&encode_name(domain)),
    }
    let (record_type, data): (u16, Vec<u8>) = match address {
        IpAddr::V4(address) => (1, address.octets().to_vec()),
        IpAddr::V6(address) => (28, address.octets().to_vec()),
    };
    response.extend_from_slice(&record_type.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    response.extend_from_slice(&data);
}

pub(crate) fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        encoded.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

pub(crate) fn make_query(name: &str, record_type: u16) -> Result<Vec<u8>, DnsError> {
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii());
    if !valid {
        return Err(DnsError::InvalidMessage("invalid resolver domain"));
    }
    let name =
        Name::from_ascii(name).map_err(|_| DnsError::InvalidMessage("invalid resolver domain"))?;
    let mut message = Message::new(0xc04c, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::from(record_type)));
    message
        .to_vec()
        .map_err(|_| DnsError::InvalidMessage("invalid resolver query"))
}

pub(crate) fn rewrite_question(
    query: &[u8],
    question: &Question,
    target: &str,
) -> Result<Vec<u8>, DnsError> {
    let mut rewritten = query[..DNS_HEADER_LENGTH].to_vec();
    rewritten.extend_from_slice(&encode_name(target));
    rewritten.extend_from_slice(&question.record_type.to_be_bytes());
    rewritten.extend_from_slice(&question.class.to_be_bytes());
    rewritten.extend_from_slice(&query[question.end..]);
    validate_query(&rewritten)?;
    Ok(rewritten)
}

pub(crate) fn record_mappings(
    response: &[u8],
    host: &str,
    state: &RuntimeState,
) -> Result<(), DnsError> {
    for (address, ttl) in answer_addresses(response)? {
        if is_mapping_address(address) {
            state.insert_dns_mapping(address, host, ttl);
        }
    }
    Ok(())
}

pub(crate) fn is_mapping_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_unicast_link_local()
                && !address.is_multicast()
        }
    }
}

pub(crate) fn answer_addresses(message: &[u8]) -> Result<Vec<(IpAddr, u32)>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answers = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(DnsError::InvalidMessage("resource record is truncated"));
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let ttl = u32::from_be_bytes([
            message[offset + 4],
            message[offset + 5],
            message[offset + 6],
            message[offset + 7],
        ]);
        let data_length = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        let data_start = offset + 10;
        let record_end = checked_record_end(
            message,
            data_start,
            data_length,
            "resource data is truncated",
        )?;
        let address = match (record_type, data_length) {
            (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                message[data_start],
                message[data_start + 1],
                message[data_start + 2],
                message[data_start + 3],
            ))),
            (28, 16) => {
                let octets: [u8; 16] = message[data_start..record_end]
                    .try_into()
                    .map_err(|_| DnsError::InvalidMessage("invalid AAAA record"))?;
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        };
        if let Some(address) = address {
            addresses.push((address.to_canonical(), ttl));
        }
        offset = record_end;
    }
    Ok(addresses)
}

pub(crate) fn answer_https_ech(message: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answers = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(DnsError::InvalidMessage("resource record is truncated"));
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let data_length = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        let data_start = offset + 10;
        let record_end = checked_record_end(
            message,
            data_start,
            data_length,
            "resource data is truncated",
        )?;
        if record_type == 65 {
            if data_length < 3 {
                return Err(DnsError::InvalidMessage("HTTPS record is truncated"));
            }
            let mut parameter = skip_name(message, data_start + 2)?;
            if parameter > record_end {
                return Err(DnsError::InvalidMessage("HTTPS target exceeds record"));
            }
            while parameter < record_end {
                if parameter + 4 > record_end {
                    return Err(DnsError::InvalidMessage(
                        "HTTPS service parameter is truncated",
                    ));
                }
                let key = u16::from_be_bytes([message[parameter], message[parameter + 1]]);
                let length = usize::from(u16::from_be_bytes([
                    message[parameter + 2],
                    message[parameter + 3],
                ]));
                let value_start = parameter + 4;
                let value_end = value_start
                    .checked_add(length)
                    .filter(|end| *end <= record_end);
                let Some(value_end) = value_end else {
                    return Err(DnsError::InvalidMessage(
                        "HTTPS service parameter value is truncated",
                    ));
                };
                if key == 5 {
                    return Ok(Some(message[value_start..value_end].to_vec()));
                }
                parameter = value_end;
            }
        }
        offset = record_end;
    }
    Ok(None)
}

pub(crate) fn checked_record_end(
    message: &[u8],
    offset: usize,
    length: usize,
    error: &'static str,
) -> Result<usize, DnsError> {
    offset
        .checked_add(length)
        .filter(|end| *end <= message.len())
        .ok_or(DnsError::InvalidMessage(error))
}

pub(crate) fn parse_system_hosts(contents: &str) -> BTreeMap<String, Vec<IpAddr>> {
    let mut hosts = BTreeMap::<String, Vec<IpAddr>>::new();
    for line in contents.lines() {
        let mut fields = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let Some(address) = fields.next().and_then(|field| field.parse::<IpAddr>().ok()) else {
            continue;
        };
        for name in fields {
            hosts
                .entry(name.trim_matches('.').to_lowercase())
                .or_default()
                .push(address.to_canonical());
        }
    }
    hosts
}

pub(crate) struct SystemHostsCache {
    checked_at: Option<Instant>,
    modified: Option<std::time::SystemTime>,
    size: u64,
    entries: BTreeMap<String, Vec<IpAddr>>,
}

impl SystemHostsCache {
    pub(crate) fn new() -> Self {
        Self {
            checked_at: None,
            modified: None,
            size: 0,
            entries: BTreeMap::new(),
        }
    }

    pub(crate) fn lookup(&mut self, name: &str) -> Option<Vec<IpAddr>> {
        let now = Instant::now();
        if self
            .checked_at
            .is_none_or(|checked| now.duration_since(checked) >= Duration::from_secs(5))
        {
            self.refresh();
            self.checked_at = Some(now);
        }
        self.entries
            .get(&name.trim_matches('.').to_lowercase())
            .cloned()
    }

    pub(crate) fn refresh(&mut self) {
        let path = system_hosts_path();
        let Ok(metadata) = std::fs::metadata(&path) else {
            self.entries.clear();
            self.modified = None;
            self.size = 0;
            return;
        };
        let modified = metadata.modified().ok();
        if self.modified == modified && self.size == metadata.len() && !self.entries.is_empty() {
            return;
        }
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        self.entries = parse_system_hosts(&contents);
        self.modified = modified;
        self.size = metadata.len();
    }
}

pub(crate) fn system_hosts_cache() -> &'static StdMutex<SystemHostsCache> {
    static CACHE: OnceLock<StdMutex<SystemHostsCache>> = OnceLock::new();
    CACHE.get_or_init(|| StdMutex::new(SystemHostsCache::new()))
}

pub(crate) fn system_hosts_path() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        return std::path::PathBuf::from(root).join("System32/drivers/etc/hosts");
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/etc/hosts")
    }
}

/// Looks up one name through the native hosts file with the Go five-second
/// metadata refresh interval.
#[must_use]
pub fn system_host_addresses(name: &str) -> Option<Vec<IpAddr>> {
    if std::env::var("DISABLE_SYSTEM_HOSTS")
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "t" | "true"))
    {
        return None;
    }
    system_hosts_cache().lock().ok()?.lookup(name)
}
