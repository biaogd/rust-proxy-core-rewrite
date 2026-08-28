use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::Query;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use rewrite_config::{
    DnsClassicEndpoint, DnsClassicUpstream, DnsConfig, DnsFallbackConfig, DnsMainKind, DnsPolicy,
    DnsPolicyMatcher, DnsResolverClient, DnsTlsConfig, DnsTransport, DnsUpstream,
    GeositeDomainKind, RuleSetDomainKind, SyntheticRcode,
};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::enhancer::{
    answer_addresses, apply_ecs, empty_upstream_answer, filter_disabled_records, make_query,
};
use crate::server::Question;
use crate::service::{
    HttpConnectionPool, RestDnsResponse, RestQuestion, RestRecord, TlsConnectionPool,
};
use crate::transport::{
    query_http_reuse, query_https_verified_reuse, query_quic_verified_reuse, query_tcp, query_tls,
    query_tls_insecure_reuse, query_tls_verified, query_tls_verified_reuse,
    query_udp_with_tcp_retry,
};
use crate::{
    DNS_HEADER_LENGTH, DhcpDnsCacheEntry, DnsError, SYSTEM_DNS_REFRESH_INTERVAL, UPSTREAM_TIMEOUT,
    dhcp_clock_start, dhcp_dns_cache, system_dns_cache, tailscale_resolvers,
};

pub(crate) fn parse_question(query: &[u8]) -> Result<Question, DnsError> {
    if query.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    if query[2] & 0x80 != 0 {
        return Err(DnsError::InvalidMessage("QR bit is set on a query"));
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return Err(DnsError::InvalidMessage(
            "Phase 4A requires exactly one question",
        ));
    }
    let decoder = BinDecoder::new(query);
    let question_offset = u16::try_from(DNS_HEADER_LENGTH)
        .map_err(|_| DnsError::InvalidMessage("DNS header offset exceeds message"))?;
    let mut decoder = decoder.clone(question_offset);
    let parsed =
        Query::read(&mut decoder).map_err(|_| DnsError::InvalidMessage("invalid question"))?;
    Ok(Question {
        name: parsed
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_lowercase(),
        record_type: parsed.query_type().into(),
        class: parsed.query_class().into(),
        end: decoder.index(),
    })
}

pub(crate) fn validate_query(query: &[u8]) -> Result<(), DnsError> {
    parse_question(query).map(|_| ())
}

pub(crate) fn validate_response(response: &[u8], identifier: [u8; 2]) -> Result<(), DnsError> {
    if response.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("upstream response is truncated"));
    }
    if response[..2] != identifier || response[2] & 0x80 == 0 {
        return Err(DnsError::InvalidMessage(
            "upstream response does not match query",
        ));
    }
    Ok(())
}

pub(crate) fn rest_response(message: &[u8]) -> Result<RestDnsResponse, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("upstream response is truncated"));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let question_count = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answer_count = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let authority_count = usize::from(u16::from_be_bytes([message[8], message[9]]));
    let additional_count = usize::from(u16::from_be_bytes([message[10], message[11]]));
    let mut offset = DNS_HEADER_LENGTH;
    let mut question = Vec::with_capacity(question_count);
    for _ in 0..question_count {
        let (name, next) = read_name(message, offset)?;
        offset = next;
        if offset + 4 > message.len() {
            return Err(DnsError::InvalidMessage("question is truncated"));
        }
        question.push(RestQuestion {
            name: fqdn(&name),
            qtype: u16::from_be_bytes([message[offset], message[offset + 1]]),
            qclass: u16::from_be_bytes([message[offset + 2], message[offset + 3]]),
        });
        offset += 4;
    }
    let (answer, next) = rest_records(message, offset, answer_count)?;
    let (authority, next) = rest_records(message, next, authority_count)?;
    let (additional, _) = rest_records(message, next, additional_count)?;
    Ok(RestDnsResponse {
        status: (flags & 0x000f) as u8,
        question,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        authenticated_data: flags & 0x0020 != 0,
        checking_disabled: flags & 0x0010 != 0,
        answer,
        authority,
        additional,
    })
}

pub(crate) fn rest_records(
    message: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<RestRecord>, usize), DnsError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let record_start = offset;
        let (name, next) = read_name(message, offset)?;
        offset = next;
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
        let data_offset = offset + 10;
        let data_end = data_offset
            .checked_add(data_length)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("resource data is truncated"))?;
        let data = rest_record_data(message, record_type, record_start, data_offset, data_end)?;
        records.push(RestRecord {
            name: fqdn(&name),
            record_type,
            ttl,
            data,
        });
        offset = data_end;
    }
    Ok((records, offset))
}

pub(crate) fn rest_record_data(
    message: &[u8],
    record_type: u16,
    record_start: usize,
    data_start: usize,
    end: usize,
) -> Result<String, DnsError> {
    let record_start = u16::try_from(record_start)
        .map_err(|_| DnsError::InvalidMessage("resource record offset exceeds DNS message"))?;
    let decoder = BinDecoder::new(message);
    let mut decoder = decoder.clone(record_start);
    let record = Record::read(&mut decoder)
        .map_err(|_| DnsError::InvalidMessage("unsupported REST resource record"))?;
    if decoder.index() != end {
        return Err(DnsError::InvalidMessage(
            "resource record length does not match",
        ));
    }
    if matches!(record_type, 13 | 16 | 19 | 20 | 56 | 99 | 258) {
        return format_character_strings(&message[data_start..end]);
    }
    match &record.data {
        RData::Unknown { rdata, .. } => Ok(format_rfc3597(&rdata.anything)),
        RData::NULL(null) => Ok(format_rfc3597(&null.anything)),
        RData::OPT(_) => Ok(String::new()),
        data => Ok(data.to_string()),
    }
}

pub(crate) fn format_character_strings(data: &[u8]) -> Result<String, DnsError> {
    let mut offset = 0;
    let mut rendered = Vec::new();
    while offset < data.len() {
        let length = usize::from(data[offset]);
        offset += 1;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or(DnsError::InvalidMessage(
                "character string exceeds resource record",
            ))?;
        let mut value = String::from("\"");
        for byte in &data[offset..end] {
            match *byte {
                b'"' | b'\\' => {
                    value.push('\\');
                    value.push(char::from(*byte));
                }
                b' '..=b'~' => value.push(char::from(*byte)),
                _ => {
                    use std::fmt::Write;
                    let _ = write!(value, "\\{byte:03}");
                }
            }
        }
        value.push('"');
        rendered.push(value);
        offset = end;
    }
    Ok(rendered.join(" "))
}

pub(crate) fn format_rfc3597(data: &[u8]) -> String {
    let mut hex = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("\\# {} {hex}", data.len())
}

pub(crate) fn read_name(message: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let start = u16::try_from(start)
        .map_err(|_| DnsError::InvalidMessage("DNS name offset exceeds message"))?;
    let decoder = BinDecoder::new(message);
    let mut decoder = decoder.clone(start);
    let name =
        Name::read(&mut decoder).map_err(|_| DnsError::InvalidMessage("invalid DNS name"))?;
    Ok((
        name.to_ascii().trim_end_matches('.').to_owned(),
        decoder.index(),
    ))
}

pub(crate) fn fqdn(name: &str) -> String {
    if name.is_empty() {
        ".".to_owned()
    } else {
        format!("{name}.")
    }
}

pub(crate) fn cache_key(query: &[u8], transport: DnsTransport, upstream: SocketAddr) -> Vec<u8> {
    let mut key = Vec::with_capacity(query.len() + 24);
    key.push(match transport {
        DnsTransport::Udp => 0,
        DnsTransport::Tcp => 1,
        DnsTransport::TlsInsecureNoReuse => 2,
        DnsTransport::TlsInsecureReuse => 3,
        DnsTransport::TlsVerifiedNoReuse => 4,
        DnsTransport::TlsVerifiedReuse => 5,
        DnsTransport::HttpReuse => 6,
        DnsTransport::HttpsVerifiedReuse => 7,
        DnsTransport::QuicVerifiedReuse => 8,
    });
    key.extend_from_slice(upstream.to_string().as_bytes());
    key.push(0);
    key.extend_from_slice(&[0, 0]);
    key.extend_from_slice(&query[2..]);
    key
}

pub(crate) fn resolution_cache_key(query: &[u8], config: &DnsConfig, domain: &str) -> Vec<u8> {
    if let Some(resolvers) = selected_policy(&config.policies, domain) {
        let mut key = cache_key(query, config.transport, config.upstream);
        key.push(0xed);
        append_resolver_clients_cache_identity(&mut key, resolvers);
        return key;
    }

    let mut key = cache_key(query, config.transport, config.upstream);
    append_main_kind_cache_identity(&mut key, &config.main_kind);
    if !config.classic_upstreams.is_empty() {
        key.push(0xf5);
        for upstream in &config.classic_upstreams {
            key.push(upstream.transport as u8);
            match &upstream.endpoint {
                DnsClassicEndpoint::Socket(address) => {
                    key.push(0);
                    key.extend_from_slice(address.to_string().as_bytes());
                }
                DnsClassicEndpoint::Domain {
                    host,
                    port,
                    bootstrap,
                } => {
                    key.push(1);
                    key.extend_from_slice(host.as_bytes());
                    key.extend_from_slice(&port.to_be_bytes());
                    key.extend_from_slice(bootstrap.address.to_string().as_bytes());
                    key.push(bootstrap.transport as u8);
                }
            }
            append_query_options_cache_identity(&mut key, &upstream.query_options);
            key.push(0);
        }
    }
    if let Some(tls) = &config.tls {
        key.push(0xfd);
        key.extend_from_slice(tls.server_name.as_bytes());
        key.push(0xf8);
        key.extend_from_slice(tls.tls_server_name.as_bytes());
        key.push(u8::from(tls.skip_certificate_verification));
        key.push(tls.doh_protocol as u8);
        if let Some(endpoint_host) = &tls.endpoint_host {
            key.push(0xfb);
            key.extend_from_slice(endpoint_host.as_bytes());
        }
        if let Some(bootstrap) = tls.bootstrap {
            key.push(0xfa);
            key.extend_from_slice(bootstrap.address.to_string().as_bytes());
            key.push(bootstrap.transport as u8);
        }
        key.push(0);
        for certificate in &tls.trust_certificates {
            key.extend_from_slice(certificate.as_bytes());
            key.push(0);
        }
        if let Some(path) = &tls.doh_path {
            key.push(0xfc);
            key.extend_from_slice(path.as_bytes());
        }
        if let Some(credentials) = &tls.doh_basic_credentials {
            key.push(0xf9);
            key.extend_from_slice(credentials.as_bytes());
        }
    }
    append_query_options_cache_identity(&mut key, &config.query_options);
    append_resolver_clients_cache_identity(&mut key, &config.main_resolvers);
    key.push(0xff);
    if let Some(fallback) = &config.fallback {
        append_resolver_clients_cache_identity(&mut key, &fallback.resolvers);
        key.push(u8::from(fallback.lazy));
        for pattern in &fallback.domains {
            key.extend_from_slice(pattern.as_bytes());
            key.push(0);
        }
        for matcher in &fallback.geosites {
            key.extend_from_slice(format!("{matcher:?}").as_bytes());
            key.push(0);
        }
        key.push(0xfe);
        for network in &fallback.ipcidr {
            key.extend_from_slice(network.to_string().as_bytes());
            key.push(0);
        }
        if let Some(filter) = &fallback.geoip {
            key.extend_from_slice(filter.code.as_bytes());
            key.push(u8::from(filter.inverted));
            for network in &filter.networks {
                key.extend_from_slice(network.to_string().as_bytes());
                key.push(0);
            }
        }
    }
    key
}

pub(crate) fn append_resolver_clients_cache_identity(
    key: &mut Vec<u8>,
    clients: &[DnsResolverClient],
) {
    key.push(0xee);
    for client in clients {
        key.extend_from_slice(format!("{client:?}").as_bytes());
        key.push(0);
    }
}

pub(crate) fn append_query_options_cache_identity(
    key: &mut Vec<u8>,
    options: &rewrite_config::DnsQueryOptions,
) {
    if let Some(ecs) = options.ecs {
        key.push(0xf7);
        key.extend_from_slice(ecs.address.to_string().as_bytes());
        key.push(ecs.prefix);
        key.push(u8::from(ecs.override_existing));
    }
    if !options.disabled_types.is_empty() {
        key.push(0xf6);
        for record_type in &options.disabled_types {
            key.extend_from_slice(&record_type.to_be_bytes());
        }
    }
}

pub(crate) fn append_main_kind_cache_identity(key: &mut Vec<u8>, main_kind: &DnsMainKind) {
    match main_kind {
        DnsMainKind::Configured => {}
        DnsMainKind::System => key.push(0xf4),
        DnsMainKind::Dhcp(interface) => {
            key.push(0xf3);
            key.extend_from_slice(interface.as_bytes());
            key.push(0);
        }
        DnsMainKind::Rcode(rcode) => {
            key.push(0xf2);
            key.push(*rcode as u8);
        }
        DnsMainKind::Tailscale(name) => {
            key.push(0xf1);
            key.extend_from_slice(name.as_bytes());
            key.push(0);
        }
    }
}

pub(crate) fn selected_policy<'a>(
    policies: &'a [DnsPolicy],
    domain: &str,
) -> Option<&'a [DnsResolverClient]> {
    let mut index = 0;
    while index < policies.len() {
        if matches!(policies[index].matcher, DnsPolicyMatcher::Domain(_)) {
            let start = index;
            while index < policies.len()
                && matches!(policies[index].matcher, DnsPolicyMatcher::Domain(_))
            {
                index += 1;
            }
            if let Some(policy) = policies[start..index]
                .iter()
                .filter_map(|policy| {
                    let DnsPolicyMatcher::Domain(pattern) = &policy.matcher else {
                        return None;
                    };
                    policy_match_rank(pattern, domain).map(|rank| (rank, policy))
                })
                .max_by(|(left, _), (right, _)| left.cmp(right))
                .map(|(_, policy)| policy)
            {
                return Some(&policy.resolvers);
            }
            continue;
        }
        let policy = &policies[index];
        index += 1;
        if policy_matcher_matches(&policy.matcher, domain) {
            return Some(&policy.resolvers);
        }
    }
    None
}

pub(crate) fn policy_matcher_matches(matcher: &DnsPolicyMatcher, domain: &str) -> bool {
    match matcher {
        DnsPolicyMatcher::Domain(pattern) => policy_match_rank(pattern, domain).is_some(),
        DnsPolicyMatcher::Geosite { domains, .. } => domains.iter().any(|entry| match entry.kind {
            GeositeDomainKind::Plain => domain.contains(&entry.value),
            GeositeDomainKind::Regex => {
                regex::Regex::new(&entry.value).is_ok_and(|expression| expression.is_match(domain))
            }
            GeositeDomainKind::Domain => {
                domain == entry.value
                    || domain
                        .strip_suffix(&entry.value)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            GeositeDomainKind::Full => domain == entry.value,
        }),
        DnsPolicyMatcher::RuleSet { domains, .. } => domains.iter().any(|entry| match entry.kind {
            RuleSetDomainKind::Trie => policy_match_rank(&entry.value, domain).is_some(),
            RuleSetDomainKind::Keyword => domain.contains(&entry.value),
        }),
    }
}

pub(crate) async fn query_configured(
    query: &[u8],
    config: &DnsConfig,
    domain: &str,
    tls_pool: Option<&Mutex<TlsConnectionPool>>,
    http_pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    if let Some(resolvers) = selected_policy(&config.policies, domain) {
        return query_resolver_set(query, resolvers, tls_pool, http_pool).await;
    }

    let Some(fallback_config) = &config.fallback else {
        return query_main(query, config, tls_pool, http_pool).await;
    };
    if fallback_config
        .domains
        .iter()
        .any(|pattern| policy_match_rank(pattern, domain).is_some())
        || fallback_config
            .geosites
            .iter()
            .any(|matcher| policy_matcher_matches(matcher, domain))
    {
        return query_resolver_set(query, &fallback_config.resolvers, tls_pool, http_pool).await;
    }

    if fallback_config.lazy {
        let started = Instant::now();
        return match query_main(query, config, tls_pool, http_pool).await {
            Ok(response) if response_passes_fallback_filter(&response, fallback_config)? => {
                Ok(response)
            }
            Err(DnsError::UpstreamTimeout) => Err(DnsError::UpstreamTimeout),
            _ => {
                let remaining = UPSTREAM_TIMEOUT
                    .checked_sub(started.elapsed())
                    .ok_or(DnsError::UpstreamTimeout)?;
                tokio::time::timeout(
                    remaining,
                    query_resolver_set(query, &fallback_config.resolvers, tls_pool, http_pool),
                )
                .await
                .map_err(|_| DnsError::UpstreamTimeout)?
            }
        };
    }

    let fallback_query = query.to_vec();
    let fallback_resolvers = fallback_config.resolvers.clone();
    let fallback_task = tokio::spawn(async move {
        query_resolver_set(&fallback_query, &fallback_resolvers, None, None).await
    });
    match query_main(query, config, tls_pool, http_pool).await {
        Ok(response) if response_passes_fallback_filter(&response, fallback_config)? => {
            Ok(response)
        }
        _ => fallback_task
            .await
            .map_err(|_| DnsError::InvalidMessage("fallback query task failed"))?,
    }
}

pub(crate) async fn query_main(
    query: &[u8],
    config: &DnsConfig,
    tls_pool: Option<&Mutex<TlsConnectionPool>>,
    http_pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    if !config.main_resolvers.is_empty() {
        return query_resolver_set(query, &config.main_resolvers, tls_pool, http_pool).await;
    }
    match &config.main_kind {
        DnsMainKind::System => return query_system(query).await,
        DnsMainKind::Dhcp(interface) => return query_dhcp(query, interface).await,
        DnsMainKind::Rcode(rcode) => return Ok(query_rcode(query, *rcode)),
        DnsMainKind::Tailscale(name) => return query_tailscale(query, name).await,
        DnsMainKind::Configured => {}
    }
    if !config.classic_upstreams.is_empty() {
        return query_classic_group(query, &config.classic_upstreams).await;
    }
    query_one(
        query,
        DnsUpstream {
            address: config.upstream,
            transport: config.transport,
        },
        config.tls.as_ref(),
        tls_pool,
        http_pool,
    )
    .await
}

pub(crate) async fn query_resolver_set(
    query: &[u8],
    resolvers: &[DnsResolverClient],
    tls_pool: Option<&Mutex<TlsConnectionPool>>,
    http_pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    if let [resolver] = resolvers {
        return query_resolver_client(query, resolver, tls_pool, http_pool).await;
    }
    if let Some(resolver @ DnsResolverClient::Rcode(_)) = resolvers
        .iter()
        .find(|resolver| matches!(resolver, DnsResolverClient::Rcode(_)))
    {
        return query_resolver_client(query, resolver, tls_pool, http_pool).await;
    }
    let identifier = [query[0], query[1]];
    let mut tasks = JoinSet::new();
    for resolver in resolvers {
        let query = query.to_vec();
        let resolver = resolver.clone();
        tasks.spawn(async move { query_resolver_client(&query, &resolver, None, None).await });
    }
    let selected = tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        while let Some(result) = tasks.join_next().await {
            let Ok(Ok(response)) = result else { continue };
            if validate_response(&response, identifier).is_ok()
                && !matches!(response[3] & 0x0f, 2 | 5)
            {
                return Ok(response);
            }
        }
        Err(DnsError::InvalidMessage("all DNS resolver clients failed"))
    })
    .await
    .map_err(|_| DnsError::UpstreamTimeout)?;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    selected
}

pub(crate) async fn query_resolver_client(
    query: &[u8],
    resolver: &DnsResolverClient,
    tls_pool: Option<&Mutex<TlsConnectionPool>>,
    http_pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let default_options = rewrite_config::DnsQueryOptions::default();
    let options = match resolver {
        DnsResolverClient::Classic(upstream) => &upstream.query_options,
        DnsResolverClient::Network { query_options, .. } => query_options,
        _ => &default_options,
    };
    let question = parse_question(query)?;
    if options.disabled_types.contains(&question.record_type) {
        return Ok(empty_upstream_answer(query, &question));
    }
    let query = options
        .ecs
        .map_or_else(|| Ok(query.to_vec()), |ecs| apply_ecs(query, ecs))?;
    let response = match resolver {
        DnsResolverClient::Classic(upstream) => query_classic(&query, upstream).await?,
        DnsResolverClient::Network { upstream, tls, .. } => {
            query_one(&query, *upstream, tls.as_ref(), tls_pool, http_pool).await?
        }
        DnsResolverClient::System => query_system(&query).await?,
        DnsResolverClient::Dhcp(interface) => query_dhcp(&query, interface).await?,
        DnsResolverClient::Rcode(rcode) => query_rcode(&query, *rcode),
        DnsResolverClient::Tailscale(name) => query_tailscale(&query, name).await?,
    };
    filter_disabled_records(&response, &options.disabled_types)
}

pub(crate) fn query_rcode(query: &[u8], rcode: SyntheticRcode) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] |= 0x80;
    response[3] = (response[3] & 0xf0) | rcode as u8;
    response
}

pub(crate) async fn query_tailscale(query: &[u8], name: &str) -> Result<Vec<u8>, DnsError> {
    let resolver = tailscale_resolvers()
        .read()
        .map_err(|_| DnsError::InvalidMessage("Tailscale DNS registry lock poisoned"))?
        .get(name)
        .map(|entry| Arc::clone(&entry.resolver))
        .ok_or(DnsError::InvalidMessage(
            "proxy does not provide Tailscale DNS",
        ))?;
    resolver.exchange(query).await
}

pub(crate) async fn query_dhcp(query: &[u8], interface: &str) -> Result<Vec<u8>, DnsError> {
    let interface = interface.to_owned();
    let servers = tokio::task::spawn_blocking(move || active_dhcp_dns(&interface))
        .await
        .map_err(|_| DnsError::InvalidMessage("DHCP discovery task failed"))??;
    let upstreams = servers
        .into_iter()
        .map(|address| DnsClassicUpstream {
            endpoint: DnsClassicEndpoint::Socket(address),
            transport: DnsTransport::Udp,
            query_options: rewrite_config::DnsQueryOptions::default(),
        })
        .collect::<Vec<_>>();
    if upstreams.is_empty() {
        return Err(DnsError::InvalidMessage(
            "DHCP discovery returned no DNS servers",
        ));
    }
    query_classic_group(query, &upstreams).await
}

pub(crate) fn active_dhcp_dns(interface: &str) -> std::io::Result<Vec<SocketAddr>> {
    let snapshot = rewrite_platform::dhcp_interface_snapshot(interface);
    let now = Instant::now().saturating_duration_since(dhcp_clock_start());
    let mut cache = dhcp_dns_cache()
        .lock()
        .map_err(|_| std::io::Error::other("DHCP DNS cache lock poisoned"))?;
    let entry = cache.entry(interface.to_owned()).or_default();
    let decision = entry
        .tracker
        .observe(now, snapshot.as_ref().ok().map(|snapshot| snapshot.ipv4));
    match decision {
        rewrite_platform::DhcpRefreshDecision::Cached => return cached_dhcp_result(entry),
        rewrite_platform::DhcpRefreshDecision::InterfaceError => {
            let error = snapshot.expect_err("interface error decision requires an error");
            entry.error = Some((error.kind(), error.to_string()));
            return Err(error);
        }
        rewrite_platform::DhcpRefreshDecision::Refresh => {}
    }
    let snapshot = snapshot.expect("refresh decision requires an interface snapshot");
    match rewrite_platform::resolve_dns_from_dhcp(&snapshot) {
        Ok(servers) => {
            entry.servers.clone_from(&servers);
            entry.error = None;
            Ok(servers)
        }
        Err(error) => {
            entry.servers.clear();
            entry.error = Some((error.kind(), error.to_string()));
            Err(error)
        }
    }
}

pub(crate) fn cached_dhcp_result(entry: &DhcpDnsCacheEntry) -> std::io::Result<Vec<SocketAddr>> {
    match &entry.error {
        Some((kind, message)) => Err(std::io::Error::new(*kind, message.clone())),
        None => Ok(entry.servers.clone()),
    }
}

pub(crate) async fn query_system(query: &[u8]) -> Result<Vec<u8>, DnsError> {
    let servers = active_system_dns()?;
    let upstreams = servers
        .into_iter()
        .map(|address| DnsClassicUpstream {
            endpoint: DnsClassicEndpoint::Socket(address),
            transport: DnsTransport::Udp,
            query_options: rewrite_config::DnsQueryOptions::default(),
        })
        .collect::<Vec<_>>();
    if upstreams.is_empty() {
        return Err(DnsError::InvalidMessage(
            "system DNS discovery returned no active servers",
        ));
    }
    query_classic_group(query, &upstreams).await
}

pub(crate) fn active_system_dns() -> Result<Vec<SocketAddr>, DnsError> {
    let now = Instant::now();
    let mut cache = system_dns_cache()
        .lock()
        .map_err(|_| DnsError::InvalidMessage("system DNS cache lock poisoned"))?;
    let refresh_due = cache
        .last_refresh
        .is_none_or(|last| now.duration_since(last) > SYSTEM_DNS_REFRESH_INTERVAL);
    if refresh_due {
        match rewrite_platform::discover_system_dns() {
            Ok(discovered) => {
                let active = cache.tracker.refresh(&discovered);
                if !active.is_empty() {
                    cache.last_refresh = Some(now);
                }
                return Ok(active);
            }
            Err(_) if cache.tracker.active().is_empty() => {
                return Err(DnsError::InvalidMessage("system DNS discovery failed"));
            }
            Err(_) => {}
        }
    }
    Ok(cache.tracker.active())
}

pub(crate) async fn query_classic_group(
    query: &[u8],
    upstreams: &[DnsClassicUpstream],
) -> Result<Vec<u8>, DnsError> {
    let identifier = [query[0], query[1]];
    let mut tasks = JoinSet::new();
    for upstream in upstreams {
        let query = query.to_vec();
        let upstream = upstream.clone();
        tasks.spawn(async move { query_classic_wrapped(&query, &upstream).await });
    }
    let selected = tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        while let Some(result) = tasks.join_next().await {
            let Ok(Ok(response)) = result else { continue };
            if validate_response(&response, identifier).is_ok()
                && !matches!(response[3] & 0x0f, 2 | 5)
            {
                return Ok(response);
            }
        }
        Err(DnsError::InvalidMessage("all classic DNS upstreams failed"))
    })
    .await
    .map_err(|_| DnsError::UpstreamTimeout)?;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    selected
}

pub(crate) async fn query_classic_wrapped(
    query: &[u8],
    upstream: &DnsClassicUpstream,
) -> Result<Vec<u8>, DnsError> {
    let question = parse_question(query)?;
    if upstream
        .query_options
        .disabled_types
        .contains(&question.record_type)
    {
        return Ok(empty_upstream_answer(query, &question));
    }
    let query = upstream
        .query_options
        .ecs
        .map_or_else(|| Ok(query.to_vec()), |ecs| apply_ecs(query, ecs))?;
    let response = query_classic(&query, upstream).await?;
    filter_disabled_records(&response, &upstream.query_options.disabled_types)
}

pub(crate) async fn query_classic(
    query: &[u8],
    upstream: &DnsClassicUpstream,
) -> Result<Vec<u8>, DnsError> {
    let address = match &upstream.endpoint {
        DnsClassicEndpoint::Socket(address) => *address,
        DnsClassicEndpoint::Domain {
            host,
            port,
            bootstrap,
        } => {
            let bootstrap_query = make_query(host, 1)?;
            let identifier = [bootstrap_query[0], bootstrap_query[1]];
            let response = query_one(&bootstrap_query, *bootstrap, None, None, None).await?;
            validate_response(&response, identifier)?;
            let address = answer_addresses(&response)?
                .into_iter()
                .find_map(|(address, _)| address.is_ipv4().then_some(address))
                .ok_or(DnsError::NoAddress)?;
            SocketAddr::new(address, *port)
        }
    };
    match upstream.transport {
        DnsTransport::Udp => query_udp_with_tcp_retry(query, address).await,
        DnsTransport::Tcp => query_tcp(query, address).await,
        _ => Err(DnsError::InvalidMessage(
            "classic upstream has a non-classic transport",
        )),
    }
}

pub(crate) async fn query_one(
    query: &[u8],
    upstream: DnsUpstream,
    tls: Option<&DnsTlsConfig>,
    tls_pool: Option<&Mutex<TlsConnectionPool>>,
    http_pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    match upstream.transport {
        DnsTransport::Udp => query_udp_with_tcp_retry(query, upstream.address).await,
        DnsTransport::Tcp => query_tcp(query, upstream.address).await,
        DnsTransport::TlsInsecureNoReuse => query_tls(query, upstream.address).await,
        DnsTransport::TlsInsecureReuse => {
            query_tls_insecure_reuse(query, upstream.address, tls_pool).await
        }
        DnsTransport::TlsVerifiedNoReuse => {
            let tls = tls.ok_or(DnsError::InvalidMessage(
                "verified TLS upstream lacks verification configuration",
            ))?;
            query_tls_verified(query, upstream.address, tls).await
        }
        DnsTransport::TlsVerifiedReuse => {
            let tls = tls.ok_or(DnsError::InvalidMessage(
                "verified TLS upstream lacks verification configuration",
            ))?;
            query_tls_verified_reuse(query, upstream.address, tls, tls_pool).await
        }
        DnsTransport::HttpReuse => {
            let http = tls.ok_or(DnsError::InvalidMessage(
                "HTTP DoH upstream lacks request configuration",
            ))?;
            query_http_reuse(query, upstream.address, http, http_pool).await
        }
        DnsTransport::HttpsVerifiedReuse => {
            let tls = tls.ok_or(DnsError::InvalidMessage(
                "verified HTTPS upstream lacks verification configuration",
            ))?;
            query_https_verified_reuse(query, upstream.address, tls, tls_pool).await
        }
        DnsTransport::QuicVerifiedReuse => {
            let tls = tls.ok_or(DnsError::InvalidMessage(
                "verified DoQ upstream lacks verification configuration",
            ))?;
            query_quic_verified_reuse(query, upstream.address, tls, tls_pool).await
        }
    }
}

pub(crate) fn response_passes_fallback_filter(
    response: &[u8],
    fallback: &DnsFallbackConfig,
) -> Result<bool, DnsError> {
    let addresses = answer_addresses(response)?;
    Ok(!addresses.is_empty()
        && addresses.iter().all(|(address, _)| {
            fallback
                .ipcidr
                .iter()
                .all(|network| !network.contains(address))
                && !fallback
                    .geoip
                    .as_ref()
                    .is_some_and(|filter| geoip_requires_fallback(*address, filter))
        }))
}

pub(crate) fn geoip_requires_fallback(
    address: IpAddr,
    filter: &rewrite_config::DnsGeoIpFilter,
) -> bool {
    if is_lan_address(address) {
        return false;
    }
    if filter.code == "lan" {
        return true;
    }
    let contained = filter
        .networks
        .iter()
        .any(|network| network.contains(&address));
    let matches = if filter.inverted {
        !contained
    } else {
        contained
    };
    !matches
}

pub(crate) fn is_lan_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_link_local()
        }
        IpAddr::V6(address) => {
            address.is_unique_local()
                || address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unicast_link_local()
        }
    }
}

pub(crate) fn policy_match_rank(pattern: &str, domain: &str) -> Option<Vec<u8>> {
    let domain_labels: Vec<_> = domain.split('.').collect();
    let pattern_labels: Vec<_> = pattern.split('.').collect();
    let suffix = pattern_labels.first().is_some_and(|label| *label == "+");
    let compared = if suffix {
        &pattern_labels[1..]
    } else {
        &pattern_labels[..]
    };
    if domain_labels.len() < compared.len() || (!suffix && domain_labels.len() != compared.len()) {
        return None;
    }
    let domain_suffix = &domain_labels[domain_labels.len() - compared.len()..];
    let mut rank = Vec::with_capacity(domain_labels.len());
    for (pattern_label, domain_label) in compared.iter().zip(domain_suffix).rev() {
        if *pattern_label == "*" {
            rank.push(1);
        } else if pattern_label.eq_ignore_ascii_case(domain_label) {
            rank.push(2);
        } else {
            return None;
        }
    }
    rank.resize(domain_labels.len(), 0);
    Some(rank)
}
