use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Empty;
use hyper::client::conn::http1::SendRequest as Http1SendRequest;
use rewrite_config::{
    Config, DnsConfig, DnsMainKind, DnsMode, DnsResolverClient, DohProtocol, HostEntry,
};
use rewrite_state::RuntimeState;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio_rustls::client::TlsStream;

use crate::DnsError;
use crate::cache::{Cache, CacheLookup, cache_ttl, without_opt_records};
use crate::enhancer::{
    alias_response, answer_addresses, answer_https_ech, apply_ecs, empty_upstream_answer,
    fake_ip_response, fake_ip_skipped, filter_disabled_records, host_response, lookup_host,
    make_query, matches_address_type, record_mappings, rewrite_question,
};
use crate::server::{
    HostLookup, Question, local_response, server_failure_response, truncate_udp_response,
};
use crate::wire::{
    parse_question, query_configured, query_resolver_set, resolution_cache_key, rest_response,
    selected_policy, validate_query, validate_response,
};

#[derive(Default)]
pub(crate) struct TlsConnectionPool {
    pub(crate) key: Vec<u8>,
    pub(crate) connections: Vec<TlsStream<TcpStream>>,
    pub(crate) h1_key: Vec<u8>,
    pub(crate) h1_senders: Vec<Http1Sender>,
    pub(crate) h2_key: Vec<u8>,
    pub(crate) h2_sender: Option<h2::client::SendRequest<Bytes>>,
    pub(crate) h3_key: Vec<u8>,
    pub(crate) h3_endpoint: Option<quinn::Endpoint>,
    pub(crate) h3_connection: Option<quinn::Connection>,
    pub(crate) h3_sender: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    pub(crate) doh_choice_key: Vec<u8>,
    pub(crate) doh_choice: Option<DohProtocol>,
    pub(crate) doq_key: Vec<u8>,
    pub(crate) doq_endpoint: Option<quinn::Endpoint>,
    pub(crate) doq_connection: Option<quinn::Connection>,
}

#[derive(Default)]
pub(crate) struct HttpConnectionPool {
    pub(crate) key: Vec<u8>,
    pub(crate) senders: Vec<Http1Sender>,
}

pub(crate) type Http1Sender = Http1SendRequest<Empty<Bytes>>;

pub(crate) type SharedDnsResult = Result<Vec<u8>, SharedDnsError>;

#[derive(Clone)]
pub(crate) enum SharedDnsError {
    Io(String),
    InvalidMessage(&'static str),
    UpstreamTimeout,
    Inactive,
    NoAddress,
    NoEchConfig,
}

impl SharedDnsError {
    pub(crate) fn capture(error: &DnsError) -> Self {
        match error {
            DnsError::Io(error) => Self::Io(error.to_string()),
            DnsError::InvalidMessage(message) => Self::InvalidMessage(message),
            DnsError::UpstreamTimeout => Self::UpstreamTimeout,
            DnsError::Inactive => Self::Inactive,
            DnsError::NoAddress => Self::NoAddress,
            DnsError::NoEchConfig => Self::NoEchConfig,
        }
    }

    pub(crate) fn restore(self) -> DnsError {
        match self {
            Self::Io(message) => DnsError::Io(std::io::Error::other(message)),
            Self::InvalidMessage(message) => DnsError::InvalidMessage(message),
            Self::UpstreamTimeout => DnsError::UpstreamTimeout,
            Self::Inactive => DnsError::Inactive,
            Self::NoAddress => DnsError::NoAddress,
            Self::NoEchConfig => DnsError::NoEchConfig,
        }
    }
}

pub(crate) struct InflightQuery {
    result: StdMutex<Option<SharedDnsResult>>,
    ready: Notify,
}

impl InflightQuery {
    pub(crate) fn new() -> Self {
        Self {
            result: StdMutex::new(None),
            ready: Notify::new(),
        }
    }

    pub(crate) fn complete(&self, result: SharedDnsResult) {
        if let Ok(mut stored) = self.result.lock() {
            *stored = Some(result);
        }
        self.ready.notify_waiters();
    }

    pub(crate) async fn wait(&self) -> Result<Vec<u8>, DnsError> {
        loop {
            let notified = self.ready.notified();
            if let Ok(stored) = self.result.lock()
                && let Some(result) = stored.clone()
            {
                return result.map_err(SharedDnsError::restore);
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
pub(crate) struct Resolver {
    cache: Arc<Mutex<Cache>>,
    inflight: Arc<Mutex<BTreeMap<Vec<u8>, Arc<InflightQuery>>>>,
    tls_pool: Arc<Mutex<TlsConnectionPool>>,
    http_pool: Arc<Mutex<HttpConnectionPool>>,
}

/// Resolver state shared by the local DNS listener and controller cache APIs.
pub struct DnsService {
    pub(crate) resolver: Resolver,
}

impl DnsService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: Resolver::new(),
        }
    }

    /// Runs a controller DNS query through the configured upstream resolver.
    ///
    /// This intentionally bypasses hosts and fake-IP enhancement, matching the
    /// Go controller's use of `DefaultResolver` rather than the DNS middleware.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError`] when the name, upstream exchange or response is
    /// invalid.
    pub async fn rest_query(
        &self,
        config: &DnsConfig,
        name: &str,
        record_type: u16,
    ) -> Result<RestDnsResponse, DnsError> {
        let name = name.trim_end_matches('.');
        let query = make_query(name, record_type)?;
        let response = self.resolver.resolve_upstream(&query, config).await?;
        rest_response(&response)
    }

    /// Relays one RFC 8484 DNS message through the local DNS service path.
    ///
    /// Resolver failures become a DNS `SERVFAIL` response, matching the Go
    /// relay boundary; malformed wire input remains an HTTP-visible error.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError`] when the request or generated response is not a
    /// valid DNS message.
    pub async fn relay_query(
        &self,
        config: &Config,
        state: &RuntimeState,
        query: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        validate_query(query)?;
        let response = match self.resolver.resolve(query, config, state).await {
            Ok(response) => Ok(response),
            Err(_) => server_failure_response(query),
        }?;
        let response = local_response(query, response, true)?;
        if response.len() > 2 * 1024 {
            truncate_udp_response(&response, 2 * 1024)
        } else {
            Ok(response)
        }
    }

    /// Clears the positive resolver cache shared by DNS and REST queries.
    pub async fn clear_cache(&self) {
        self.resolver.cache.lock().await.clear();
    }

    /// Drops every idle encrypted-DNS connection and invalidates returns from
    /// exchanges that started before a configuration reload.
    pub async fn reset_connections(&self) {
        let mut pool = self.resolver.tls_pool.lock().await;
        pool.key.clear();
        pool.connections.clear();
        pool.h1_key.clear();
        pool.h1_senders.clear();
        pool.h2_key.clear();
        pool.h2_sender = None;
        pool.h3_key.clear();
        if let Some(connection) = pool.h3_connection.take() {
            connection.close(0_u32.into(), b"DNS reset");
        }
        pool.h3_sender = None;
        pool.h3_endpoint = None;
        pool.doh_choice_key.clear();
        pool.doh_choice = None;
        if let Some(connection) = pool.doq_connection.take() {
            connection.close(0_u32.into(), b"DNS reset");
        }
        drop(pool);
        let mut pool = self.resolver.http_pool.lock().await;
        pool.key.clear();
        pool.senders.clear();
    }
}

impl Default for DnsService {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestQuestion {
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
}

#[derive(Debug, Serialize)]
pub struct RestRecord {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) record_type: u16,
    #[serde(rename = "TTL")]
    pub(crate) ttl: u32,
    pub(crate) data: String,
}

#[derive(Debug, Serialize)]
// These booleans are independent DNS header bits required as separate fields
// by the existing controller JSON contract, not an internal state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct RestDnsResponse {
    #[serde(rename = "Status")]
    pub(crate) status: u8,
    #[serde(rename = "Question")]
    pub(crate) question: Vec<RestQuestion>,
    #[serde(rename = "TC")]
    pub(crate) truncated: bool,
    #[serde(rename = "RD")]
    pub(crate) recursion_desired: bool,
    #[serde(rename = "RA")]
    pub(crate) recursion_available: bool,
    #[serde(rename = "AD")]
    pub(crate) authenticated_data: bool,
    #[serde(rename = "CD")]
    pub(crate) checking_disabled: bool,
    #[serde(rename = "Answer", skip_serializing_if = "Vec::is_empty")]
    pub(crate) answer: Vec<RestRecord>,
    #[serde(rename = "Authority", skip_serializing_if = "Vec::is_empty")]
    pub(crate) authority: Vec<RestRecord>,
    #[serde(rename = "Additional", skip_serializing_if = "Vec::is_empty")]
    pub(crate) additional: Vec<RestRecord>,
}

impl Resolver {
    pub(crate) fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(Cache::default())),
            inflight: Arc::new(Mutex::new(BTreeMap::new())),
            tls_pool: Arc::new(Mutex::new(TlsConnectionPool::default())),
            http_pool: Arc::new(Mutex::new(HttpConnectionPool::default())),
        }
    }

    pub(crate) async fn resolve(
        &self,
        query: &[u8],
        config: &Config,
        state: &RuntimeState,
    ) -> Result<Vec<u8>, DnsError> {
        let question = parse_question(query)?;
        let dns = config.dns.as_ref().ok_or(DnsError::Inactive)?;
        if dns.use_hosts
            && question.class == 1
            && matches!(question.record_type, 1 | 5 | 28)
            && let Some(response) = self
                .resolve_hosts(query, &question, config, dns, state)
                .await?
        {
            return Ok(response);
        }

        if dns.mode == DnsMode::FakeIp
            && question.class == 1
            && matches!(question.record_type, 1 | 28)
            && let Some(fake) = dns.fake_ip.as_ref()
            && !fake_ip_skipped(&question.name, fake)
        {
            let network = match question.record_type {
                1 => fake.ipv4_range,
                28 if dns.ipv6 => fake.ipv6_range,
                _ => None,
            };
            let address = network.map(|network| {
                state.allocate_fake_ip(network, &question.name, config.profile.store_fake_ip)
            });
            return Ok(fake_ip_response(query, &question, address, fake.ttl));
        }

        let response = self.resolve_upstream(query, dns).await?;
        record_mappings(&response, &question.name, state)?;
        Ok(response)
    }

    pub(crate) async fn resolve_hosts(
        &self,
        query: &[u8],
        question: &Question,
        config: &Config,
        dns: &DnsConfig,
        state: &RuntimeState,
    ) -> Result<Option<Vec<u8>>, DnsError> {
        if question.record_type == 5 {
            return Ok(match config.hosts.search(&question.name) {
                Some(HostEntry::Domain(target)) => {
                    Some(host_response(query, question, &[], Some(target)))
                }
                _ => None,
            });
        }

        match lookup_host(&question.name, config, dns) {
            Some(HostLookup::Addresses(addresses)) => {
                let selected: Vec<_> = addresses
                    .into_iter()
                    .filter(|address| matches_address_type(*address, question.record_type))
                    .collect();
                for address in &selected {
                    state.insert_dns_mapping(*address, &question.name, 10);
                }
                Ok(Some(host_response(query, question, &selected, None)))
            }
            Some(HostLookup::ExternalAlias(target)) => {
                let rewritten = rewrite_question(query, question, &target)?;
                let upstream = self.resolve_upstream(&rewritten, dns).await?;
                let addresses: Vec<_> = answer_addresses(&upstream)?
                    .into_iter()
                    .filter(|(address, _)| matches_address_type(*address, question.record_type))
                    .collect();
                for (address, ttl) in &addresses {
                    state.insert_dns_mapping(*address, &target, *ttl);
                }
                Ok(Some(alias_response(query, question, &target, &addresses)))
            }
            None => Ok(None),
        }
    }

    pub(crate) async fn resolve_upstream(
        &self,
        query: &[u8],
        config: &DnsConfig,
    ) -> Result<Vec<u8>, DnsError> {
        let question = parse_question(query)?;
        let per_client_wrappers = !config.main_resolvers.is_empty();
        if !per_client_wrappers
            && config
                .query_options
                .disabled_types
                .contains(&question.record_type)
        {
            return Ok(empty_upstream_answer(query, &question));
        }
        let identifier = [query[0], query[1]];
        let key = resolution_cache_key(query, config, &question.name);
        let now = Instant::now();
        let cached = {
            let mut cache = self.cache.lock().await;
            if !cache.matches(config.cache_algorithm, config.cache_max_size) {
                *cache = Cache::new(config.cache_algorithm, config.cache_max_size);
            }
            cache.get(&key, identifier, now)
        };
        match cached {
            Some(CacheLookup::Fresh(response)) => return Ok(response),
            Some(CacheLookup::Stale(response)) => {
                let resolver = self.clone();
                let query = query.to_vec();
                let config = config.clone();
                let refresh_key = key.clone();
                tokio::spawn(async move {
                    let _ = resolver
                        .exchange_shared(&query, &config, refresh_key, false)
                        .await;
                });
                return Ok(response);
            }
            None => {}
        }

        self.exchange_shared(query, config, key, true).await
    }

    pub(crate) async fn exchange_shared(
        &self,
        query: &[u8],
        config: &DnsConfig,
        key: Vec<u8>,
        retry_on_failure: bool,
    ) -> Result<Vec<u8>, DnsError> {
        let (inflight, leader) = {
            let mut queries = self.inflight.lock().await;
            if let Some(inflight) = queries.get(&key) {
                (Arc::clone(inflight), false)
            } else {
                let inflight = Arc::new(InflightQuery::new());
                queries.insert(key.clone(), Arc::clone(&inflight));
                (inflight, true)
            }
        };
        if !leader {
            let mut response = inflight.wait().await?;
            response[..2].copy_from_slice(&query[..2]);
            return Ok(response);
        }

        let result = self.exchange_once(query, config, key.clone()).await;
        let shared = match &result {
            Ok(response) => Ok(response.clone()),
            Err(error) => Err(SharedDnsError::capture(error)),
        };
        inflight.complete(shared);
        let mut queries = self.inflight.lock().await;
        if queries
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &inflight))
        {
            queries.remove(&key);
        }
        drop(queries);

        if retry_on_failure && result.is_err() {
            let resolver = self.clone();
            let query = query.to_vec();
            let config = config.clone();
            tokio::spawn(async move {
                resolver.background_retry(&query, &config, key).await;
            });
        }
        result
    }

    pub(crate) async fn background_retry(&self, query: &[u8], config: &DnsConfig, key: Vec<u8>) {
        let (inflight, leader) = {
            let mut queries = self.inflight.lock().await;
            if let Some(inflight) = queries.get(&key) {
                (Arc::clone(inflight), false)
            } else {
                let inflight = Arc::new(InflightQuery::new());
                queries.insert(key.clone(), Arc::clone(&inflight));
                (inflight, true)
            }
        };
        if !leader {
            let _ = inflight.wait().await;
            return;
        }
        let result = self.exchange_once(query, config, key.clone()).await;
        let shared = match &result {
            Ok(response) => Ok(response.clone()),
            Err(error) => Err(SharedDnsError::capture(error)),
        };
        inflight.complete(shared);
        let mut queries = self.inflight.lock().await;
        if queries
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &inflight))
        {
            queries.remove(&key);
        }
    }

    pub(crate) async fn exchange_once(
        &self,
        query: &[u8],
        config: &DnsConfig,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, DnsError> {
        let question = parse_question(query)?;
        let per_client_wrappers = !config.main_resolvers.is_empty();
        let identifier = [query[0], query[1]];

        let upstream_query = if per_client_wrappers {
            query.to_vec()
        } else {
            config
                .query_options
                .ecs
                .map_or_else(|| Ok(query.to_vec()), |ecs| apply_ecs(query, ecs))?
        };
        let mut response = query_configured(
            &upstream_query,
            config,
            &question.name,
            Some(&self.tls_pool),
            Some(&self.http_pool),
        )
        .await?;
        if !per_client_wrappers {
            response = filter_disabled_records(&response, &config.query_options.disabled_types)?;
        }
        validate_response(&response, identifier)?;
        let synthetic_rcode = matches!(&config.main_kind, DnsMainKind::Rcode(_))
            || config
                .main_resolvers
                .iter()
                .any(|resolver| matches!(resolver, DnsResolverClient::Rcode(_)));
        if !synthetic_rcode && matches!(response[3] & 0x0f, 2 | 5) {
            return Err(DnsError::InvalidMessage(
                "upstream returned a retryable failure rcode",
            ));
        }
        // The pinned Go local DNS service marks responses authoritative even
        // when their records came from an upstream resolver.
        response[2] |= 0x04;
        if let Some(ttl) = cache_ttl(&response)? {
            let cached_response = without_opt_records(&response)?;
            self.cache
                .lock()
                .await
                .insert(key, cached_response, ttl, Instant::now());
        }
        Ok(response)
    }
}

/// Resolves the real address for a domain through the configured classic
/// upstream, bypassing fake-IP response generation.
///
/// # Errors
///
/// Returns [`DnsError`] for transport/message failures or when no permitted
/// A/AAAA address is present.
pub async fn resolve_domain(
    config: &DnsConfig,
    host: &str,
    allow_ipv6: bool,
) -> Result<IpAddr, DnsError> {
    preferred_address(lookup_domain_with(config, host, allow_ipv6, false).await?)
}

/// Returns the Go-compatible ordered A/AAAA lookup result. A and AAAA start
/// concurrently; after A completes, AAAA receives only `dns.ipv6-timeout` of
/// additional wait time.
///
/// # Errors
///
/// Returns [`DnsError`] when neither address family produces an address before
/// the declared lookup boundary.
pub async fn lookup_domain(
    config: &DnsConfig,
    host: &str,
    allow_ipv6: bool,
) -> Result<Vec<IpAddr>, DnsError> {
    lookup_domain_with(config, host, allow_ipv6, false).await
}

/// Starts A and AAAA concurrently, returning A immediately when available and
/// waiting for AAAA only when A fails.
///
/// # Errors
///
/// Returns [`DnsError`] if both address-family lookups fail.
pub async fn lookup_domain_primary_ipv4(
    config: &DnsConfig,
    host: &str,
) -> Result<Vec<IpAddr>, DnsError> {
    let ipv6_config = config.clone();
    let ipv6_host = host.to_owned();
    let ipv6 = tokio::spawn(async move {
        query_configured_addresses(&ipv6_config, &ipv6_host, 28, false).await
    });
    match query_configured_addresses(config, host, 1, false).await {
        Ok(addresses) => Ok(addresses),
        Err(_) => match ipv6.await {
            Ok(Ok(addresses)) => Ok(addresses),
            Ok(Err(_)) | Err(_) => Err(DnsError::NoAddress),
        },
    }
}

/// Resolves the first ECH configuration value from an HTTPS DNS answer.
///
/// # Errors
///
/// Returns [`DnsError`] for transport/message failures or when no HTTPS answer
/// contains the ECH service parameter.
pub async fn resolve_ech(config: &DnsConfig, host: &str) -> Result<Vec<u8>, DnsError> {
    let query = make_query(host, 65)?;
    let identifier = [query[0], query[1]];
    let response = query_configured(&query, config, host, None, None).await?;
    validate_response(&response, identifier)?;
    answer_https_ech(&response)?.ok_or(DnsError::NoEchConfig)
}

/// Resolves ECH through the proxy-server resolver set used for proxy endpoints.
///
/// # Errors
///
/// Returns [`DnsError`] for transport/message failures or when no HTTPS answer
/// contains the ECH service parameter.
pub async fn resolve_proxy_ech(config: &DnsConfig, host: &str) -> Result<Vec<u8>, DnsError> {
    let query = make_query(host, 65)?;
    let identifier = [query[0], query[1]];
    let response = if let Some(resolvers) = selected_policy(&config.proxy_policies, host) {
        query_resolver_set(&query, resolvers, None, None).await?
    } else if config.proxy_resolvers.is_empty() {
        query_configured(&query, config, host, None, None).await?
    } else {
        query_resolver_set(&query, &config.proxy_resolvers, None, None).await?
    };
    validate_response(&response, identifier)?;
    answer_https_ech(&response)?.ok_or(DnsError::NoEchConfig)
}

/// Resolves a DIRECT outbound domain through the configured direct resolver.
/// If no direct resolver is configured, the normal resolver remains the Go
/// compatible fallback.
///
/// # Errors
///
/// Returns [`DnsError`] for transport/message failures or when no permitted
/// A/AAAA address is present.
pub async fn resolve_direct_domain(
    config: &DnsConfig,
    host: &str,
    allow_ipv6: bool,
) -> Result<IpAddr, DnsError> {
    preferred_address(lookup_domain_with(config, host, allow_ipv6, true).await?)
}

/// Resolves a proxy endpoint through `dns.proxy-server-nameserver`.
///
/// # Errors
///
/// Returns [`DnsError`] when the set is empty or produces no permitted address.
pub async fn resolve_proxy_domain(
    config: &DnsConfig,
    host: &str,
    allow_ipv6: bool,
) -> Result<IpAddr, DnsError> {
    preferred_address(
        lookup_domain_from_set(
            selected_policy(&config.proxy_policies, host).unwrap_or(&config.proxy_resolvers),
            host,
            allow_ipv6,
            config.ipv6_timeout,
        )
        .await?,
    )
}

/// Resolves a bootstrap name through `dns.default-nameserver`.
///
/// # Errors
///
/// Returns [`DnsError`] when the set is empty or produces no permitted address.
pub async fn resolve_default_domain(
    config: &DnsConfig,
    host: &str,
    allow_ipv6: bool,
) -> Result<IpAddr, DnsError> {
    preferred_address(
        lookup_domain_from_set(
            &config.default_resolvers,
            host,
            allow_ipv6,
            config.ipv6_timeout,
        )
        .await?,
    )
}

pub(crate) fn preferred_address(addresses: Vec<IpAddr>) -> Result<IpAddr, DnsError> {
    addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| addresses.into_iter().next())
        .ok_or(DnsError::NoAddress)
}

pub(crate) async fn lookup_domain_from_set(
    resolvers: &[DnsResolverClient],
    host: &str,
    allow_ipv6: bool,
    ipv6_timeout: Duration,
) -> Result<Vec<IpAddr>, DnsError> {
    if !allow_ipv6 {
        return query_set_addresses(resolvers, host, 1).await;
    }
    let ipv6_resolvers = resolvers.to_vec();
    let ipv6_host = host.to_owned();
    let ipv6 =
        tokio::spawn(async move { query_set_addresses(&ipv6_resolvers, &ipv6_host, 28).await });
    let ipv4 = query_set_addresses(resolvers, host, 1).await;
    finish_dual_stack(ipv4, ipv6, ipv6_timeout).await
}

pub(crate) async fn lookup_domain_with(
    config: &DnsConfig,
    host: &str,
    allow_ipv6: bool,
    direct: bool,
) -> Result<Vec<IpAddr>, DnsError> {
    if !allow_ipv6 {
        return query_configured_addresses(config, host, 1, direct).await;
    }
    let ipv6_config = config.clone();
    let ipv6_host = host.to_owned();
    let ipv6 = tokio::spawn(async move {
        query_configured_addresses(&ipv6_config, &ipv6_host, 28, direct).await
    });
    let ipv4 = query_configured_addresses(config, host, 1, direct).await;
    finish_dual_stack(ipv4, ipv6, config.ipv6_timeout).await
}

pub(crate) async fn finish_dual_stack(
    ipv4: Result<Vec<IpAddr>, DnsError>,
    ipv6: tokio::task::JoinHandle<Result<Vec<IpAddr>, DnsError>>,
    ipv6_timeout: Duration,
) -> Result<Vec<IpAddr>, DnsError> {
    let ipv6 = tokio::time::timeout(ipv6_timeout, ipv6).await;
    let mut addresses = ipv4.unwrap_or_default();
    match ipv6 {
        Ok(Ok(Ok(mut ipv6))) => addresses.append(&mut ipv6),
        Ok(Ok(Err(_)) | Err(_)) if addresses.is_empty() => {
            return Err(DnsError::NoAddress);
        }
        Ok(Ok(Err(_)) | Err(_)) | Err(_) => {}
    }
    Ok(addresses)
}

pub(crate) async fn query_set_addresses(
    resolvers: &[DnsResolverClient],
    host: &str,
    record_type: u16,
) -> Result<Vec<IpAddr>, DnsError> {
    if let Some(addresses) = literal_addresses(host, record_type)? {
        return Ok(addresses);
    }
    let query = make_query(host, record_type)?;
    let identifier = [query[0], query[1]];
    let response = query_resolver_set(&query, resolvers, None, None).await?;
    validate_response(&response, identifier)?;
    response_addresses(&response)
}

pub(crate) async fn query_configured_addresses(
    config: &DnsConfig,
    host: &str,
    record_type: u16,
    direct: bool,
) -> Result<Vec<IpAddr>, DnsError> {
    if let Some(addresses) = literal_addresses(host, record_type)? {
        return Ok(addresses);
    }
    let query = make_query(host, record_type)?;
    let identifier = [query[0], query[1]];
    let response = if direct && let Some(direct_config) = &config.direct {
        if direct_config.follow_policy
            && let Some(resolvers) = selected_policy(&config.policies, host)
        {
            query_resolver_set(&query, resolvers, None, None).await?
        } else {
            query_resolver_set(&query, &direct_config.resolvers, None, None).await?
        }
    } else {
        query_configured(&query, config, host, None, None).await?
    };
    validate_response(&response, identifier)?;
    response_addresses(&response)
}

pub(crate) fn literal_addresses(
    host: &str,
    record_type: u16,
) -> Result<Option<Vec<IpAddr>>, DnsError> {
    let Ok(address) = host.parse::<IpAddr>() else {
        return Ok(None);
    };
    let address = address.to_canonical();
    if matches!(
        (record_type, address),
        (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))
    ) {
        Ok(Some(vec![address]))
    } else {
        Err(DnsError::NoAddress)
    }
}

pub(crate) fn response_addresses(response: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
    let addresses = answer_addresses(response)?
        .into_iter()
        .map(|(address, _)| address)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        Err(DnsError::NoAddress)
    } else {
        Ok(addresses)
    }
}
