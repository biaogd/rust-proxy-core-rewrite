use std::collections::BTreeMap;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use http::{Method, Request};
use rewrite_config::{
    Config, DnsConfig, DnsFallbackConfig, DnsMode, DnsTlsConfig, DnsTransport, DnsUpstream,
    DohProtocol, FakeIpConfig, FakeIpFilterMode, HostEntry,
};
use rewrite_state::RuntimeState;
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinSet;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;

const DNS_HEADER_LENGTH: usize = 12;
const MAX_DNS_MESSAGE: usize = 65_535;
const MAX_DOH_REDIRECT_REQUESTS: usize = 10;
const CACHE_CAPACITY: usize = 256;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_POOLED_TLS_CONNECTIONS: usize = 8;

#[derive(Debug)]
struct NoCertificateVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl NoCertificateVerification {
    fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct NameOverrideVerification {
    verifier: Arc<WebPkiServerVerifier>,
    verification_name: ServerName<'static>,
}

impl ServerCertVerifier for NameOverrideVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            &self.verification_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid DNS message: {0}")]
    InvalidMessage(&'static str),
    #[error("DNS upstream timed out")]
    UpstreamTimeout,
    #[error("DNS configuration is no longer active")]
    Inactive,
    #[error("DNS upstream returned no permitted address")]
    NoAddress,
}

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    stored_at: Instant,
    lifetime: Duration,
    sequence: u64,
}

#[derive(Default)]
struct Cache {
    entries: BTreeMap<Vec<u8>, CacheEntry>,
    next_sequence: u64,
}

impl Cache {
    fn get(&mut self, key: &[u8], identifier: [u8; 2], now: Instant) -> Option<Vec<u8>> {
        let entry = self.entries.get(key)?.clone();
        let elapsed = now.saturating_duration_since(entry.stored_at);
        if elapsed >= entry.lifetime {
            self.entries.remove(key);
            return None;
        }
        let mut response = entry.response;
        response[..2].copy_from_slice(&identifier);
        let rounded_seconds = elapsed
            .as_secs()
            .saturating_add(u64::from(elapsed.subsec_nanos() != 0));
        let elapsed_seconds = u32::try_from(rounded_seconds).unwrap_or(u32::MAX);
        age_ttls(&mut response, elapsed_seconds).ok()?;
        Some(response)
    }

    fn insert(&mut self, key: Vec<u8>, response: Vec<u8>, ttl: u32, now: Instant) {
        if self.entries.len() >= CACHE_CAPACITY
            && !self.entries.contains_key(&key)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.sequence)
                .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.entries.insert(
            key,
            CacheEntry {
                response,
                stored_at: now,
                lifetime: Duration::from_secs(u64::from(ttl)),
                sequence,
            },
        );
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

#[derive(Default)]
struct TlsConnectionPool {
    key: Vec<u8>,
    connections: Vec<TlsStream<TcpStream>>,
    h2_key: Vec<u8>,
    h2_sender: Option<h2::client::SendRequest<Bytes>>,
    h3_key: Vec<u8>,
    h3_endpoint: Option<quinn::Endpoint>,
    h3_connection: Option<quinn::Connection>,
    h3_sender: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    doh_choice_key: Vec<u8>,
    doh_choice: Option<DohProtocol>,
}

#[derive(Default)]
struct HttpConnectionPool {
    key: Vec<u8>,
    connections: Vec<TcpStream>,
}

struct Resolver {
    cache: Mutex<Cache>,
    tls_pool: Mutex<TlsConnectionPool>,
    http_pool: Mutex<HttpConnectionPool>,
    system_hosts: BTreeMap<String, Vec<IpAddr>>,
}

/// Resolver state shared by the local DNS listener and controller cache APIs.
pub struct DnsService {
    resolver: Resolver,
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
        drop(pool);
        let mut pool = self.resolver.http_pool.lock().await;
        pool.key.clear();
        pool.connections.clear();
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
    name: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Serialize)]
pub struct RestRecord {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

#[derive(Debug, Serialize)]
// These booleans are independent DNS header bits required as separate fields
// by the existing controller JSON contract, not an internal state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct RestDnsResponse {
    #[serde(rename = "Status")]
    status: u8,
    #[serde(rename = "Question")]
    question: Vec<RestQuestion>,
    #[serde(rename = "TC")]
    truncated: bool,
    #[serde(rename = "RD")]
    recursion_desired: bool,
    #[serde(rename = "RA")]
    recursion_available: bool,
    #[serde(rename = "AD")]
    authenticated_data: bool,
    #[serde(rename = "CD")]
    checking_disabled: bool,
    #[serde(rename = "Answer", skip_serializing_if = "Vec::is_empty")]
    answer: Vec<RestRecord>,
    #[serde(rename = "Authority", skip_serializing_if = "Vec::is_empty")]
    authority: Vec<RestRecord>,
    #[serde(rename = "Additional", skip_serializing_if = "Vec::is_empty")]
    additional: Vec<RestRecord>,
}

impl Resolver {
    fn new() -> Self {
        Self {
            cache: Mutex::new(Cache::default()),
            tls_pool: Mutex::new(TlsConnectionPool::default()),
            http_pool: Mutex::new(HttpConnectionPool::default()),
            system_hosts: load_system_hosts(),
        }
    }

    async fn resolve(
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
                state.allocate_fake_ip(network, &question.name, config.store_fake_ip)
            });
            return Ok(fake_ip_response(query, &question, address, fake.ttl));
        }

        let response = self.resolve_upstream(query, dns).await?;
        record_mappings(&response, &question.name, state)?;
        Ok(response)
    }

    async fn resolve_hosts(
        &self,
        query: &[u8],
        question: &Question,
        config: &Config,
        dns: &DnsConfig,
        state: &RuntimeState,
    ) -> Result<Option<Vec<u8>>, DnsError> {
        if question.record_type == 5 {
            return Ok(match config.hosts.get(&question.name) {
                Some(HostEntry::Domain(target)) => {
                    Some(host_response(query, question, &[], Some(target)))
                }
                _ => None,
            });
        }

        match lookup_host(&question.name, config, dns, &self.system_hosts) {
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

    async fn resolve_upstream(
        &self,
        query: &[u8],
        config: &DnsConfig,
    ) -> Result<Vec<u8>, DnsError> {
        let question = parse_question(query)?;
        let identifier = [query[0], query[1]];
        let key = resolution_cache_key(query, config, &question.name);
        let now = Instant::now();
        if let Some(response) = self.cache.lock().await.get(&key, identifier, now) {
            return Ok(response);
        }

        let mut response = query_configured(
            query,
            config,
            &question.name,
            Some(&self.tls_pool),
            Some(&self.http_pool),
        )
        .await?;
        validate_response(&response, identifier)?;
        // The pinned Go local DNS service marks responses authoritative even
        // when their records came from an upstream resolver.
        response[2] |= 0x04;
        if let Some(ttl) = positive_ttl(&response)? {
            self.cache
                .lock()
                .await
                .insert(key, response.clone(), ttl, now);
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
    resolve_domain_with(config, host, allow_ipv6, false).await
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
    resolve_domain_with(config, host, allow_ipv6, true).await
}

async fn resolve_domain_with(
    config: &DnsConfig,
    host: &str,
    allow_ipv6: bool,
    direct: bool,
) -> Result<IpAddr, DnsError> {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for record_type in [28_u16, 1_u16] {
        if record_type == 28 && !allow_ipv6 {
            continue;
        }
        let query = make_query(host, record_type)?;
        let identifier = [query[0], query[1]];
        let direct_upstream = if direct {
            config.direct.map(|direct| {
                if direct.follow_policy {
                    selected_policy(config, host).unwrap_or(direct.upstream)
                } else {
                    direct.upstream
                }
            })
        } else {
            None
        };
        let response = match direct_upstream {
            Some(upstream) => query_one(&query, upstream, None, None, None).await?,
            None => query_configured(&query, config, host, None, None).await?,
        };
        validate_response(&response, identifier)?;
        if let Some((address, _)) = answer_addresses(&response)?
            .into_iter()
            .find(|(address, _)| allow_ipv6 || address.is_ipv4())
        {
            if address.is_ipv4() {
                ipv4 = Some(address);
            } else {
                ipv6 = Some(address);
            }
        }
    }
    ipv4.or(ipv6).ok_or(DnsError::NoAddress)
}

enum HostLookup {
    Addresses(Vec<IpAddr>),
    ExternalAlias(String),
}

struct Question {
    name: String,
    record_type: u16,
    class: u16,
    end: usize,
}

/// Serves DNS over UDP and TCP on sockets prepared by the runtime generation.
///
/// Existing listeners read the current configuration for every new query, so
/// an upstream-only reload does not require rebinding the local address.
pub async fn serve(
    tcp: TcpListener,
    udp: UdpSocket,
    service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let udp = Arc::new(udp);
    let mut tasks = JoinSet::new();
    let mut datagram = vec![0_u8; MAX_DNS_MESSAGE];

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            received = udp.recv_from(&mut datagram) => {
                match received {
                    Ok((length, peer)) => {
                        let query = datagram[..length].to_vec();
                        let socket = Arc::clone(&udp);
                        let service = Arc::clone(&service);
                        let current = current_config(&config);
                        let state = Arc::clone(&state);
                        tasks.spawn(async move {
                            let Ok(current) = current else { return };
                            let response = service
                                .resolver
                                .resolve(&query, &current, &state)
                                .await
                                .or_else(|_| server_failure_response(&query));
                            if let Ok(response) = response {
                                let _ = socket.send_to(&response, peer).await;
                            }
                        });
                    }
                    Err(error) => {
                        eprintln!("DNS UDP listener failed: {error}");
                        break;
                    }
                }
            }
            accepted = tcp.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let service = Arc::clone(&service);
                        let config = config.clone();
                        let state = Arc::clone(&state);
                        let connection_shutdown = shutdown.child_token();
                        tasks.spawn(async move {
                            serve_tcp_connection(
                                stream,
                                service,
                                config,
                                state,
                                connection_shutdown,
                            ).await;
                        });
                    }
                    Err(error) => {
                        eprintln!("DNS TCP listener failed: {error}");
                        break;
                    }
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    eprintln!("DNS task failed: {error}");
                }
            }
        }
    }

    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
}

async fn serve_tcp_connection(
    mut stream: TcpStream,
    service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    loop {
        let mut length = [0_u8; 2];
        let read = tokio::select! {
            () = shutdown.cancelled() => return,
            result = stream.read_exact(&mut length) => result,
        };
        if read.is_err() {
            return;
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 {
            return;
        }
        let mut query = vec![0_u8; length];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        let Ok(current) = current_config(&config) else {
            return;
        };
        let response = service
            .resolver
            .resolve(&query, &current, &state)
            .await
            .or_else(|_| server_failure_response(&query));
        let Ok(response) = response else { return };
        let Ok(length) = u16::try_from(response.len()) else {
            return;
        };
        if stream.write_all(&length.to_be_bytes()).await.is_err()
            || stream.write_all(&response).await.is_err()
        {
            return;
        }
    }
}

fn current_config(config: &watch::Receiver<Arc<Config>>) -> Result<Arc<Config>, DnsError> {
    let current = Arc::clone(&config.borrow());
    current.dns.as_ref().ok_or(DnsError::Inactive)?;
    Ok(current)
}

fn server_failure_response(query: &[u8]) -> Result<Vec<u8>, DnsError> {
    let question = parse_question(query)?;
    let mut response = query[..question.end].to_vec();
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = (query[3] & 0xf0) | 0x02;
    response[6..12].fill(0);
    Ok(response)
}

fn lookup_host(
    name: &str,
    config: &Config,
    dns: &DnsConfig,
    system_hosts: &BTreeMap<String, Vec<IpAddr>>,
) -> Option<HostLookup> {
    let mut current = name;
    let mut followed_alias = false;
    loop {
        match config.hosts.get(current) {
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
        .then(|| system_hosts.get(name).cloned())
        .flatten()
        .map(HostLookup::Addresses)
}

fn matches_address_type(address: IpAddr, record_type: u16) -> bool {
    matches!(
        (address, record_type),
        (IpAddr::V4(_), 1) | (IpAddr::V6(_), 28)
    )
}

fn host_response(
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

fn fake_ip_response(
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

fn fake_ip_skipped(host: &str, config: &FakeIpConfig) -> bool {
    let matched = config.filter.iter().any(|pattern| pattern == host);
    match config.filter_mode {
        FakeIpFilterMode::Blacklist => matched,
        FakeIpFilterMode::Whitelist => !matched,
    }
}

fn alias_response(
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
enum NameOwner<'a> {
    Question,
    Domain(&'a str),
}

fn response_prefix(query: &[u8], question: &Question, answers: usize) -> Vec<u8> {
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

fn push_cname(response: &mut Vec<u8>, target: &str) {
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

fn push_address(response: &mut Vec<u8>, owner: NameOwner<'_>, address: IpAddr, ttl: u32) {
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

fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        encoded.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

fn make_query(name: &str, record_type: u16) -> Result<Vec<u8>, DnsError> {
    let valid = !name.is_empty()
        && name.len() <= 253
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63 && label.is_ascii());
    if !valid {
        return Err(DnsError::InvalidMessage("invalid resolver domain"));
    }
    let mut query = 0xc04c_u16.to_be_bytes().to_vec();
    query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(&encode_name(name));
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn rewrite_question(query: &[u8], question: &Question, target: &str) -> Result<Vec<u8>, DnsError> {
    let mut rewritten = query[..DNS_HEADER_LENGTH].to_vec();
    rewritten.extend_from_slice(&encode_name(target));
    rewritten.extend_from_slice(&question.record_type.to_be_bytes());
    rewritten.extend_from_slice(&question.class.to_be_bytes());
    rewritten.extend_from_slice(&query[question.end..]);
    validate_query(&rewritten)?;
    Ok(rewritten)
}

fn record_mappings(response: &[u8], host: &str, state: &RuntimeState) -> Result<(), DnsError> {
    for (address, ttl) in answer_addresses(response)? {
        if is_mapping_address(address) {
            state.insert_dns_mapping(address, host, ttl);
        }
    }
    Ok(())
}

fn is_mapping_address(address: IpAddr) -> bool {
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

fn answer_addresses(message: &[u8]) -> Result<Vec<(IpAddr, u32)>, DnsError> {
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
        let end = checked_record_end(
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
                let octets: [u8; 16] = message[data_start..end]
                    .try_into()
                    .map_err(|_| DnsError::InvalidMessage("invalid AAAA record"))?;
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        };
        if let Some(address) = address {
            addresses.push((address.to_canonical(), ttl));
        }
        offset = end;
    }
    Ok(addresses)
}

fn checked_record_end(
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

fn load_system_hosts() -> BTreeMap<String, Vec<IpAddr>> {
    #[cfg(unix)]
    let contents = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    #[cfg(not(unix))]
    let contents = String::new();

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

async fn query_udp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
    let bind = match upstream.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut response = vec![0_u8; MAX_DNS_MESSAGE];
    let length = tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    response.truncate(length);
    Ok(response)
}

async fn query_tcp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
    let mut stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let length = u16::try_from(query.len())
        .map_err(|_| DnsError::InvalidMessage("query exceeds TCP DNS frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut length = [0_u8; 2];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut length))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    Ok(response)
}

async fn query_tls(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
    let mut stream = connect_tls_insecure(upstream).await?;
    exchange_tls(query, &mut stream).await
}

async fn connect_tls_insecure(upstream: SocketAddr) -> Result<TlsStream<TcpStream>, DnsError> {
    let stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::IpAddress(upstream.ip().into());
    tokio::time::timeout(UPSTREAM_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)
        .map_err(DnsError::Io)
}

async fn query_tls_verified(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<Vec<u8>, DnsError> {
    let mut stream = connect_tls_verified(upstream, tls).await?;
    exchange_tls(query, &mut stream).await
}

async fn connect_tls_verified(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<TlsStream<TcpStream>, DnsError> {
    connect_tls_verified_with_alpn(upstream, tls, false).await
}

async fn connect_https_verified(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<TlsStream<TcpStream>, DnsError> {
    connect_tls_verified_with_alpn(upstream, tls, true).await
}

async fn connect_tls_verified_with_alpn(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    https: bool,
) -> Result<TlsStream<TcpStream>, DnsError> {
    let mut client_config = verified_client_config(tls)?;
    if https {
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(tls.tls_server_name.clone())
        .map_err(|_| DnsError::InvalidMessage("invalid TLS server name"))?;
    let upstream = resolve_tls_endpoint(upstream, tls).await?;
    let stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    tokio::time::timeout(UPSTREAM_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)
        .map_err(DnsError::Io)
}

fn verified_client_config(tls: &DnsTlsConfig) -> Result<ClientConfig, DnsError> {
    let mut roots = RootCertStore::empty();
    if !go_style_env_flag("DISABLE_SYSTEM_CA") {
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots.add(certificate).map_err(std::io::Error::other)?;
        }
    }
    if !go_style_env_flag("DISABLE_EMBED_CA") {
        let embedded = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
            "../../../../component/ca/ca-certificates.crt"
        )))
        .collect::<Result<Vec<_>, _>>()?;
        for certificate in embedded {
            roots.add(certificate).map_err(std::io::Error::other)?;
        }
    }
    for pem in &tls.trust_certificates {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        if certificates.is_empty() {
            return Err(DnsError::InvalidMessage(
                "custom TLS root contains no certificate",
            ));
        }
        for certificate in certificates {
            roots.add(certificate).map_err(std::io::Error::other)?;
        }
    }
    let client_config = if tls.skip_certificate_verification {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
            .with_no_client_auth()
    } else {
        let verification_name = ServerName::try_from(tls.server_name.clone())
            .map_err(|_| DnsError::InvalidMessage("invalid TLS verification name"))?;
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(std::io::Error::other)?;
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NameOverrideVerification {
                verifier,
                verification_name,
            }))
            .with_no_client_auth()
    };
    Ok(client_config)
}

fn go_style_env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| go_style_true(&value))
}

fn go_style_true(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

async fn resolve_tls_endpoint(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<SocketAddr, DnsError> {
    let Some(host) = &tls.endpoint_host else {
        return Ok(upstream);
    };
    let bootstrap = tls.bootstrap.ok_or(DnsError::InvalidMessage(
        "domain TLS endpoint lacks bootstrap resolver",
    ))?;
    let query = make_query(host, 1)?;
    let response = match bootstrap.transport {
        DnsTransport::Udp => query_udp(&query, bootstrap.address).await?,
        DnsTransport::Tcp => query_tcp(&query, bootstrap.address).await?,
        _ => {
            return Err(DnsError::InvalidMessage(
                "Phase 4E9 bootstrap resolver must use UDP or TCP",
            ));
        }
    };
    let address = answer_addresses(&response)?
        .into_iter()
        .map(|(address, _)| address)
        .find(IpAddr::is_ipv4)
        .ok_or(DnsError::NoAddress)?;
    Ok(SocketAddr::new(address, upstream.port()))
}

async fn exchange_tls(
    query: &[u8],
    stream: &mut TlsStream<TcpStream>,
) -> Result<Vec<u8>, DnsError> {
    let length = u16::try_from(query.len())
        .map_err(|_| DnsError::InvalidMessage("query exceeds TLS DNS frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut length = [0_u8; 2];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut length))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    Ok(response)
}

fn tls_pool_key(upstream: SocketAddr, tls: &DnsTlsConfig) -> Vec<u8> {
    let mut key = upstream.to_string().into_bytes();
    key.push(0);
    key.extend_from_slice(tls.server_name.as_bytes());
    key.push(0xff);
    key.extend_from_slice(tls.tls_server_name.as_bytes());
    key.push(u8::from(tls.skip_certificate_verification));
    key.push(tls.doh_protocol as u8);
    if let Some(endpoint_host) = &tls.endpoint_host {
        key.push(0xfe);
        key.extend_from_slice(endpoint_host.as_bytes());
    }
    if let Some(bootstrap) = tls.bootstrap {
        key.push(0xfd);
        key.extend_from_slice(bootstrap.address.to_string().as_bytes());
        key.push(bootstrap.transport as u8);
    }
    for certificate in &tls.trust_certificates {
        key.push(0);
        key.extend_from_slice(certificate.as_bytes());
    }
    if let Some(path) = &tls.doh_path {
        key.push(0);
        key.extend_from_slice(path.as_bytes());
    }
    if let Some(credentials) = &tls.doh_basic_credentials {
        key.push(0xfc);
        key.extend_from_slice(credentials.as_bytes());
    }
    key
}

fn insecure_tls_pool_key(upstream: SocketAddr) -> Vec<u8> {
    let mut key = b"insecure\0".to_vec();
    key.extend_from_slice(upstream.to_string().as_bytes());
    key
}

async fn return_tls_connection(
    pool: &Mutex<TlsConnectionPool>,
    key: &[u8],
    stream: TlsStream<TcpStream>,
) {
    let mut pool = pool.lock().await;
    if pool.key != key {
        return;
    }
    if pool.connections.len() >= MAX_POOLED_TLS_CONNECTIONS {
        pool.connections.remove(0);
    }
    pool.connections.push(stream);
}

async fn query_tls_verified_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let Some(pool) = pool else {
        return query_tls_verified(query, upstream, tls).await;
    };
    let key = tls_pool_key(upstream, tls);
    let old_stream = {
        let mut pool = pool.lock().await;
        if pool.key != key {
            pool.connections.clear();
            pool.key.clone_from(&key);
        }
        pool.connections.pop()
    };
    if let Some(mut stream) = old_stream
        && let Ok(response) = exchange_tls(query, &mut stream).await
    {
        return_tls_connection(pool, &key, stream).await;
        return Ok(response);
    }

    let mut stream = connect_tls_verified(upstream, tls).await?;
    let response = exchange_tls(query, &mut stream).await?;
    return_tls_connection(pool, &key, stream).await;
    Ok(response)
}

async fn query_tls_insecure_reuse(
    query: &[u8],
    upstream: SocketAddr,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let Some(pool) = pool else {
        return query_tls(query, upstream).await;
    };
    let key = insecure_tls_pool_key(upstream);
    let old_stream = {
        let mut pool = pool.lock().await;
        if pool.key != key {
            pool.connections.clear();
            pool.key.clone_from(&key);
        }
        pool.connections.pop()
    };
    if let Some(mut stream) = old_stream
        && let Ok(response) = exchange_tls(query, &mut stream).await
    {
        return_tls_connection(pool, &key, stream).await;
        return Ok(response);
    }

    let mut stream = connect_tls_insecure(upstream).await?;
    let response = exchange_tls(query, &mut stream).await?;
    return_tls_connection(pool, &key, stream).await;
    Ok(response)
}

async fn exchange_doh<S>(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    stream: &mut S,
) -> Result<(Vec<u8>, bool), DnsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = tls
        .doh_path
        .as_deref()
        .ok_or(DnsError::InvalidMessage("DoH path is missing"))?;
    let mut upstream_query = query.to_vec();
    upstream_query[..2].fill(0);
    let encoded = URL_SAFE_NO_PAD.encode(&upstream_query);
    let mut target = format!("{path}?dns={encoded}");
    let authority = tls.endpoint_host.as_ref().map_or_else(
        || upstream.to_string(),
        |host| format!("{host}:{}", upstream.port()),
    );

    for request_number in 0..MAX_DOH_REDIRECT_REQUESTS {
        let authorization =
            tls.doh_basic_credentials
                .as_ref()
                .map_or_else(String::new, |credentials| {
                    format!(
                        "Authorization: Basic {}\r\n",
                        STANDARD.encode(credentials.as_bytes())
                    )
                });
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/dns-message\r\nUser-Agent: \r\n{authorization}\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        let (status, location, mut response, reusable) = read_doh_response(stream).await?;
        if status == 200 {
            if response.len() < DNS_HEADER_LENGTH || response[..2] != [0, 0] {
                return Err(DnsError::InvalidMessage("DoH response DNS ID is not zero"));
            }
            response[..2].copy_from_slice(&query[..2]);
            return Ok((response, reusable));
        }
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(DnsError::InvalidMessage("DoH response status is not 200"));
        }
        if !reusable {
            return Err(DnsError::InvalidMessage(
                "DoH redirect closed its connection",
            ));
        }
        if request_number + 1 == MAX_DOH_REDIRECT_REQUESTS {
            return Err(DnsError::InvalidMessage("DoH redirect limit exceeded"));
        }
        let location =
            location.ok_or(DnsError::InvalidMessage("DoH redirect Location is missing"))?;
        let location = location.split('#').next().unwrap_or_default();
        if !location.starts_with('/') || location.starts_with("//") || location.is_empty() {
            return Err(DnsError::InvalidMessage(
                "DoH redirect is not same-origin relative",
            ));
        }
        location.clone_into(&mut target);
    }
    Err(DnsError::InvalidMessage("DoH redirect limit exceeded"))
}

async fn read_doh_response<S>(
    stream: &mut S,
) -> Result<(u16, Option<String>, Vec<u8>, bool), DnsError>
where
    S: AsyncRead + Unpin,
{
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let mut expected_length = None;
    loop {
        let length = tokio::time::timeout(UPSTREAM_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;
        if length == 0 {
            break;
        }
        if raw.len().saturating_add(length) > MAX_DNS_MESSAGE + 16_384 {
            return Err(DnsError::InvalidMessage("DoH response is too large"));
        }
        raw.extend_from_slice(&chunk[..length]);
        if expected_length.is_none()
            && let Some(offset) = raw.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let header_end = offset + 4;
            let headers = std::str::from_utf8(&raw[..header_end])
                .map_err(|_| DnsError::InvalidMessage("DoH response headers are not ASCII"))?;
            let content_length = header_value(headers, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(DnsError::InvalidMessage(
                    "DoH response Content-Length is missing",
                ))?;
            expected_length = header_end.checked_add(content_length);
        }
        if expected_length.is_some_and(|expected| raw.len() >= expected) {
            break;
        }
    }
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or(DnsError::InvalidMessage(
            "DoH response headers are truncated",
        ))?;
    let headers = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| DnsError::InvalidMessage("DoH response headers are not ASCII"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or(DnsError::InvalidMessage("DoH response status is invalid"))?;
    let location = header_value(headers, "location").map(ToOwned::to_owned);
    let reusable = !header_value(headers, "connection")
        .is_some_and(|value| value.eq_ignore_ascii_case("close"));
    let response_end = expected_length.ok_or(DnsError::InvalidMessage(
        "DoH response Content-Length is missing",
    ))?;
    if raw.len() < response_end {
        return Err(DnsError::InvalidMessage("DoH response body is truncated"));
    }
    Ok((
        status,
        location,
        raw[header_end..response_end].to_vec(),
        reusable,
    ))
}

fn header_value<'a>(headers: &'a str, expected_name: &str) -> Option<&'a str> {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case(expected_name))
        .map(|(_, value)| value.trim())
}

fn http_pool_key(upstream: SocketAddr, http: &DnsTlsConfig) -> Vec<u8> {
    let mut key = b"http\0".to_vec();
    key.extend_from_slice(upstream.to_string().as_bytes());
    key.push(0);
    if let Some(path) = &http.doh_path {
        key.extend_from_slice(path.as_bytes());
    }
    if let Some(credentials) = &http.doh_basic_credentials {
        key.push(0xfc);
        key.extend_from_slice(credentials.as_bytes());
    }
    key
}

async fn return_http_connection(pool: &Mutex<HttpConnectionPool>, key: &[u8], stream: TcpStream) {
    let mut pool = pool.lock().await;
    if pool.key != key {
        return;
    }
    if pool.connections.len() >= MAX_POOLED_TLS_CONNECTIONS {
        pool.connections.remove(0);
    }
    pool.connections.push(stream);
}

async fn query_http_reuse(
    query: &[u8],
    upstream: SocketAddr,
    http: &DnsTlsConfig,
    pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let key = http_pool_key(upstream, http);
    if let Some(pool) = pool {
        let old_stream = {
            let mut pool = pool.lock().await;
            if pool.key != key {
                pool.connections.clear();
                pool.key.clone_from(&key);
            }
            pool.connections.pop()
        };
        if let Some(mut stream) = old_stream
            && let Ok((response, reusable)) = exchange_doh(query, upstream, http, &mut stream).await
        {
            if reusable {
                return_http_connection(pool, &key, stream).await;
            }
            return Ok(response);
        }
    }

    let mut stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let (response, reusable) = exchange_doh(query, upstream, http, &mut stream).await?;
    if reusable && let Some(pool) = pool {
        return_http_connection(pool, &key, stream).await;
    }
    Ok(response)
}

async fn query_https_verified_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let protocol = match tls.doh_protocol {
        DohProtocol::Http => DohProtocol::Http,
        DohProtocol::Http3Only => DohProtocol::Http3Only,
        DohProtocol::PreferHttp3 => select_doh_protocol(upstream, tls, pool).await?,
    };
    match protocol {
        DohProtocol::Http => query_https_http_reuse(query, upstream, tls, pool).await,
        DohProtocol::Http3Only => query_https_h3_reuse(query, upstream, tls, pool).await,
        DohProtocol::PreferHttp3 => unreachable!("preference probe returns a concrete protocol"),
    }
}

async fn select_doh_protocol(
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<DohProtocol, DnsError> {
    let key = tls_pool_key(upstream, tls);
    if let Some(pool) = pool {
        let pool = pool.lock().await;
        if pool.doh_choice_key == key
            && let Some(choice) = pool.doh_choice
        {
            return Ok(choice);
        }
    }

    let h3_probe = probe_h3(upstream, tls);
    let http_probe = async {
        // The pinned Go implementation starts QUIC and TLS probes together,
        // but the local QUIC handshake wins before its TCP goroutine reaches
        // the socket when both transports are immediately available.
        tokio::time::sleep(Duration::from_millis(25)).await;
        connect_https_verified(upstream, tls).await
    };
    tokio::pin!(h3_probe);
    tokio::pin!(http_probe);
    let choice = tokio::select! {
        h3 = &mut h3_probe => if let Ok(()) = h3 {
            DohProtocol::Http3Only
        } else {
                drop(http_probe.await?);
                DohProtocol::Http
        },
        http = &mut http_probe => if let Ok(stream) = http {
            drop(stream);
            DohProtocol::Http
        } else {
            h3_probe.await?;
            DohProtocol::Http3Only
        },
    };
    if let Some(pool) = pool {
        let mut pool = pool.lock().await;
        pool.doh_choice_key = key;
        pool.doh_choice = Some(choice);
    }
    Ok(choice)
}

async fn probe_h3(upstream: SocketAddr, tls: &DnsTlsConfig) -> Result<(), DnsError> {
    let endpoint = h3_endpoint(tls)?;
    let address = resolve_tls_endpoint(upstream, tls).await?;
    let connecting = endpoint
        .connect(address, &tls.tls_server_name)
        .map_err(std::io::Error::other)?;
    let connection = tokio::time::timeout(UPSTREAM_TIMEOUT, connecting)
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    connection.close(0_u32.into(), b"HTTP/3 probe complete");
    Ok(())
}

fn h3_endpoint(tls: &DnsTlsConfig) -> Result<quinn::Endpoint, DnsError> {
    verified_quic_endpoint(tls, b"h3", true)
}

fn verified_quic_endpoint(
    tls: &DnsTlsConfig,
    alpn: &[u8],
    disable_resumption: bool,
) -> Result<quinn::Endpoint, DnsError> {
    let mut crypto = verified_client_config(tls)?;
    crypto.alpn_protocols = vec![alpn.to_vec()];
    // The pinned Go DoH client leaves ClientSessionCache unset. It labels H3
    // GETs as 0-RTT-capable, but reconnects cannot actually resume TLS and the
    // authority observes a full handshake. Disable rustls resumption to keep
    // that externally visible behavior until the oracle changes.
    if disable_resumption {
        crypto.enable_early_data = false;
        crypto.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    }
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(std::io::Error::other)?;
    let config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

async fn query_quic_verified(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<Vec<u8>, DnsError> {
    let endpoint = verified_quic_endpoint(tls, b"doq", false)?;
    let address = resolve_tls_endpoint(upstream, tls).await?;
    let connecting = endpoint
        .connect(address, &tls.tls_server_name)
        .map_err(std::io::Error::other)?;
    let connection = tokio::time::timeout(UPSTREAM_TIMEOUT, connecting)
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    let result = tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        let (mut sender, mut receiver) =
            connection.open_bi().await.map_err(std::io::Error::other)?;
        let mut upstream_query = query.to_vec();
        upstream_query[..2].fill(0);
        let length = u16::try_from(upstream_query.len())
            .map_err(|_| DnsError::InvalidMessage("DoQ query is too large"))?;
        sender
            .write_all(&length.to_be_bytes())
            .await
            .map_err(std::io::Error::other)?;
        sender
            .write_all(&upstream_query)
            .await
            .map_err(std::io::Error::other)?;
        sender.finish().map_err(std::io::Error::other)?;

        let mut length = [0_u8; 2];
        receiver
            .read_exact(&mut length)
            .await
            .map_err(std::io::Error::other)?;
        let response_length = usize::from(u16::from_be_bytes(length));
        if response_length == 0 {
            return Err(DnsError::InvalidMessage("DoQ response is empty"));
        }
        let mut response = vec![0_u8; response_length];
        receiver
            .read_exact(&mut response)
            .await
            .map_err(std::io::Error::other)?;
        if response.len() < DNS_HEADER_LENGTH {
            return Err(DnsError::InvalidMessage("DoQ response is too short"));
        }
        response[..2].copy_from_slice(&query[..2]);
        Ok(response)
    })
    .await
    .map_err(|_| DnsError::UpstreamTimeout)?;
    connection.close(0_u32.into(), b"Phase 4E17 one-shot DoQ complete");
    result
}

async fn connect_h3(
    endpoint: &quinn::Endpoint,
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<quinn::Connection, DnsError> {
    let connecting = endpoint
        .connect(upstream, &tls.tls_server_name)
        .map_err(std::io::Error::other)?;
    match connecting.into_0rtt() {
        Ok((connection, accepted)) => {
            tokio::spawn(async move {
                let _ = accepted.await;
            });
            Ok(connection)
        }
        Err(connecting) => tokio::time::timeout(UPSTREAM_TIMEOUT, connecting)
            .await
            .map_err(|_| DnsError::UpstreamTimeout)?
            .map_err(std::io::Error::other)
            .map_err(DnsError::Io),
    }
}

async fn h3_sender(
    connection: quinn::Connection,
) -> Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, DnsError> {
    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(std::io::Error::other)?;
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|context| driver.poll_close(context)).await;
    });
    Ok(sender)
}

async fn query_https_h3_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let address = resolve_tls_endpoint(upstream, tls).await?;
    let key = tls_pool_key(upstream, tls);
    let Some(pool) = pool else {
        let endpoint = h3_endpoint(tls)?;
        let connection = connect_h3(&endpoint, address, tls).await?;
        let mut sender = h3_sender(connection.clone()).await?;
        let response = exchange_doh_h3(query, upstream, tls, &mut sender).await;
        connection.close(0_u32.into(), b"one-shot HTTP/3 complete");
        return response;
    };

    let mut pool = pool.lock().await;
    if pool.h3_key != key {
        if let Some(connection) = pool.h3_connection.take() {
            connection.close(0_u32.into(), b"HTTP/3 configuration changed");
        }
        pool.h3_sender = None;
        pool.h3_endpoint = None;
        pool.h3_key.clone_from(&key);
    }
    if pool.h3_endpoint.is_none() {
        pool.h3_endpoint = Some(h3_endpoint(tls)?);
    }

    for _ in 0..3 {
        if let Some(mut sender) = pool.h3_sender.take() {
            match exchange_doh_h3(query, upstream, tls, &mut sender).await {
                Ok(response) => {
                    pool.h3_sender = Some(sender);
                    return Ok(response);
                }
                Err(_) => {
                    if let Some(connection) = pool.h3_connection.take() {
                        connection.close(0_u32.into(), b"stale HTTP/3 connection");
                    }
                }
            }
        }
        let endpoint = pool.h3_endpoint.as_ref().expect("HTTP/3 endpoint");
        let connection = connect_h3(endpoint, address, tls).await?;
        let mut sender = h3_sender(connection.clone()).await?;
        match exchange_doh_h3(query, upstream, tls, &mut sender).await {
            Ok(response) => {
                pool.h3_connection = Some(connection);
                pool.h3_sender = Some(sender);
                return Ok(response);
            }
            Err(_) => connection.close(0_u32.into(), b"failed HTTP/3 request"),
        }
    }
    Err(DnsError::InvalidMessage("HTTP/3 retry limit exceeded"))
}

async fn exchange_doh_h3(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
) -> Result<Vec<u8>, DnsError> {
    let path = tls
        .doh_path
        .as_deref()
        .ok_or(DnsError::InvalidMessage("DoH path is missing"))?;
    let mut upstream_query = query.to_vec();
    upstream_query[..2].fill(0);
    let encoded = URL_SAFE_NO_PAD.encode(&upstream_query);
    let authority = tls.endpoint_host.as_ref().map_or_else(
        || upstream.to_string(),
        |host| format!("{host}:{}", upstream.port()),
    );
    let uri = format!("https://{authority}{path}?dns={encoded}")
        .parse::<http::Uri>()
        .map_err(std::io::Error::other)?;
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("accept", "application/dns-message")
        .header("user-agent", "");
    if let Some(credentials) = &tls.doh_basic_credentials {
        builder = builder.header(
            "authorization",
            format!("Basic {}", STANDARD.encode(credentials.as_bytes())),
        );
    }
    let request = builder.body(()).map_err(std::io::Error::other)?;
    let mut stream = tokio::time::timeout(UPSTREAM_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    stream.finish().await.map_err(std::io::Error::other)?;
    let response = tokio::time::timeout(UPSTREAM_TIMEOUT, stream.recv_response())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    if response.status() != http::StatusCode::OK {
        return Err(DnsError::InvalidMessage("DoH response status is not 200"));
    }
    let mut dns_response = Vec::new();
    while let Some(mut chunk) = tokio::time::timeout(UPSTREAM_TIMEOUT, stream.recv_data())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?
    {
        if dns_response.len().saturating_add(chunk.remaining()) > MAX_DNS_MESSAGE {
            return Err(DnsError::InvalidMessage("DoH response is too large"));
        }
        let remaining = chunk.remaining();
        dns_response.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    if dns_response.len() < DNS_HEADER_LENGTH || dns_response[..2] != [0, 0] {
        return Err(DnsError::InvalidMessage("DoH response DNS ID is not zero"));
    }
    dns_response[..2].copy_from_slice(&query[..2]);
    Ok(dns_response)
}

async fn query_https_http_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let key = tls_pool_key(upstream, tls);
    if let Some(pool) = pool {
        let h2_sender = {
            let pool = pool.lock().await;
            (pool.h2_key == key)
                .then(|| pool.h2_sender.clone())
                .flatten()
        };
        if let Some(sender) = h2_sender {
            if let Ok(response) = exchange_doh_h2(query, upstream, tls, sender).await {
                return Ok(response);
            }
            let mut pool = pool.lock().await;
            if pool.h2_key == key {
                pool.h2_sender = None;
            }
        }
    }

    let old_stream = {
        if let Some(pool) = pool {
            let mut pool = pool.lock().await;
            if pool.key != key {
                pool.connections.clear();
                pool.key.clone_from(&key);
            }
            pool.connections.pop()
        } else {
            None
        }
    };
    if let Some(mut stream) = old_stream
        && let Ok((response, reusable)) = exchange_doh(query, upstream, tls, &mut stream).await
    {
        if reusable && let Some(pool) = pool {
            return_tls_connection(pool, &key, stream).await;
        }
        return Ok(response);
    }

    let mut stream = connect_https_verified(upstream, tls).await?;
    if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
        let (sender, connection) =
            tokio::time::timeout(UPSTREAM_TIMEOUT, h2::client::handshake(stream))
                .await
                .map_err(|_| DnsError::UpstreamTimeout)?
                .map_err(std::io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = exchange_doh_h2(query, upstream, tls, sender.clone()).await?;
        if let Some(pool) = pool {
            let mut pool = pool.lock().await;
            pool.h2_key.clone_from(&key);
            pool.h2_sender = Some(sender);
        }
        return Ok(response);
    }
    let (response, reusable) = exchange_doh(query, upstream, tls, &mut stream).await?;
    if reusable && let Some(pool) = pool {
        return_tls_connection(pool, &key, stream).await;
    }
    Ok(response)
}

async fn exchange_doh_h2(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    sender: h2::client::SendRequest<Bytes>,
) -> Result<Vec<u8>, DnsError> {
    let path = tls
        .doh_path
        .as_deref()
        .ok_or(DnsError::InvalidMessage("DoH path is missing"))?;
    let mut upstream_query = query.to_vec();
    upstream_query[..2].fill(0);
    let encoded = URL_SAFE_NO_PAD.encode(&upstream_query);
    let authority = tls.endpoint_host.as_ref().map_or_else(
        || upstream.to_string(),
        |host| format!("{host}:{}", upstream.port()),
    );
    let uri = format!("https://{authority}{path}?dns={encoded}")
        .parse::<http::Uri>()
        .map_err(std::io::Error::other)?;
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("accept", "application/dns-message")
        .header("user-agent", "");
    if let Some(credentials) = &tls.doh_basic_credentials {
        builder = builder.header(
            "authorization",
            format!("Basic {}", STANDARD.encode(credentials.as_bytes())),
        );
    }
    let request = builder.body(()).map_err(std::io::Error::other)?;
    let mut sender = tokio::time::timeout(UPSTREAM_TIMEOUT, sender.ready())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    let (response, _) = sender
        .send_request(request, true)
        .map_err(std::io::Error::other)?;
    let response = tokio::time::timeout(UPSTREAM_TIMEOUT, response)
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(std::io::Error::other)?;
    if response.status() != http::StatusCode::OK {
        return Err(DnsError::InvalidMessage("DoH response status is not 200"));
    }
    let mut body = response.into_body();
    let mut dns_response = Vec::new();
    while let Some(chunk) = tokio::time::timeout(UPSTREAM_TIMEOUT, body.data())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
    {
        let chunk = chunk.map_err(std::io::Error::other)?;
        if dns_response.len().saturating_add(chunk.len()) > MAX_DNS_MESSAGE {
            return Err(DnsError::InvalidMessage("DoH response is too large"));
        }
        dns_response.extend_from_slice(&chunk);
    }
    if dns_response.len() < DNS_HEADER_LENGTH || dns_response[..2] != [0, 0] {
        return Err(DnsError::InvalidMessage("DoH response DNS ID is not zero"));
    }
    dns_response[..2].copy_from_slice(&query[..2]);
    Ok(dns_response)
}

fn parse_question(query: &[u8]) -> Result<Question, DnsError> {
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
    let mut offset = DNS_HEADER_LENGTH;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(
            *query
                .get(offset)
                .ok_or(DnsError::InvalidMessage("name is truncated"))?,
        );
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + length > query.len() {
            return Err(DnsError::InvalidMessage("invalid question name"));
        }
        labels.push(
            std::str::from_utf8(&query[offset..offset + length])
                .map_err(|_| DnsError::InvalidMessage("question name is not ASCII"))?,
        );
        offset += length;
    }
    if offset + 4 > query.len() {
        return Err(DnsError::InvalidMessage("question is truncated"));
    }
    let record_type = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let class = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);
    Ok(Question {
        name: labels.join(".").to_lowercase(),
        record_type,
        class,
        end: offset + 4,
    })
}

fn validate_query(query: &[u8]) -> Result<(), DnsError> {
    parse_question(query).map(|_| ())
}

fn validate_response(response: &[u8], identifier: [u8; 2]) -> Result<(), DnsError> {
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

fn rest_response(message: &[u8]) -> Result<RestDnsResponse, DnsError> {
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

fn rest_records(
    message: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<RestRecord>, usize), DnsError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
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
        let data = rest_record_data(message, record_type, data_offset, data_end)?;
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

fn rest_record_data(
    message: &[u8],
    record_type: u16,
    start: usize,
    end: usize,
) -> Result<String, DnsError> {
    match (record_type, end - start) {
        (1, 4) => Ok(Ipv4Addr::new(
            message[start],
            message[start + 1],
            message[start + 2],
            message[start + 3],
        )
        .to_string()),
        (28, 16) => {
            let octets: [u8; 16] = message[start..end]
                .try_into()
                .map_err(|_| DnsError::InvalidMessage("invalid AAAA record"))?;
            Ok(Ipv6Addr::from(octets).to_string())
        }
        (2 | 5 | 12, _) => read_name(message, start).map(|(name, _)| fqdn(&name)),
        _ => Err(DnsError::InvalidMessage("unsupported REST resource record")),
    }
}

fn read_name(message: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut hops = 0_usize;
    loop {
        if hops > message.len() {
            return Err(DnsError::InvalidMessage("name pointer loop"));
        }
        hops += 1;
        let length = *message
            .get(offset)
            .ok_or(DnsError::InvalidMessage("name is truncated"))?;
        if length & 0xc0 == 0xc0 {
            let low = *message
                .get(offset + 1)
                .ok_or(DnsError::InvalidMessage("name pointer is truncated"))?;
            next.get_or_insert(offset + 2);
            offset = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::InvalidMessage("invalid name label"));
        }
        offset += 1;
        if length == 0 {
            return Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset
            .checked_add(usize::from(length))
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("name label is truncated"))?;
        labels.push(
            std::str::from_utf8(&message[offset..end])
                .map_err(|_| DnsError::InvalidMessage("name label is not ASCII"))?
                .to_owned(),
        );
        offset = end;
    }
}

fn fqdn(name: &str) -> String {
    if name.is_empty() {
        ".".to_owned()
    } else {
        format!("{name}.")
    }
}

fn cache_key(query: &[u8], transport: DnsTransport, upstream: SocketAddr) -> Vec<u8> {
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
        DnsTransport::QuicVerifiedNoReuse => 8,
    });
    key.extend_from_slice(upstream.to_string().as_bytes());
    key.push(0);
    key.extend_from_slice(&[0, 0]);
    key.extend_from_slice(&query[2..]);
    key
}

fn resolution_cache_key(query: &[u8], config: &DnsConfig, domain: &str) -> Vec<u8> {
    if let Some(policy) = selected_policy(config, domain) {
        return cache_key(query, policy.transport, policy.address);
    }

    let mut key = cache_key(query, config.transport, config.upstream);
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
    key.push(0xff);
    if let Some(fallback) = &config.fallback {
        key.push(match fallback.upstream.transport {
            DnsTransport::Udp => 0,
            DnsTransport::Tcp => 1,
            DnsTransport::TlsInsecureNoReuse => 2,
            DnsTransport::TlsInsecureReuse => 3,
            DnsTransport::TlsVerifiedNoReuse => 4,
            DnsTransport::TlsVerifiedReuse => 5,
            DnsTransport::HttpReuse => 6,
            DnsTransport::HttpsVerifiedReuse => 7,
            DnsTransport::QuicVerifiedNoReuse => 8,
        });
        key.extend_from_slice(fallback.upstream.address.to_string().as_bytes());
        key.push(u8::from(fallback.lazy));
        for pattern in &fallback.domains {
            key.extend_from_slice(pattern.as_bytes());
            key.push(0);
        }
        key.push(0xfe);
        for network in &fallback.ipcidr {
            key.extend_from_slice(network.to_string().as_bytes());
            key.push(0);
        }
    }
    key
}

fn selected_policy(config: &DnsConfig, domain: &str) -> Option<DnsUpstream> {
    config
        .policies
        .iter()
        .filter_map(|policy| policy_match_rank(&policy.pattern, domain).map(|rank| (rank, policy)))
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, policy)| DnsUpstream {
            address: policy.upstream,
            transport: policy.transport,
        })
}

async fn query_configured(
    query: &[u8],
    config: &DnsConfig,
    domain: &str,
    tls_pool: Option<&Mutex<TlsConnectionPool>>,
    http_pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    if let Some(policy) = selected_policy(config, domain) {
        return query_one(query, policy, None, None, None).await;
    }

    let main = DnsUpstream {
        address: config.upstream,
        transport: config.transport,
    };
    let Some(fallback_config) = &config.fallback else {
        return query_one(query, main, config.tls.as_ref(), tls_pool, http_pool).await;
    };
    let fallback = fallback_config.upstream;

    if fallback_config
        .domains
        .iter()
        .any(|pattern| policy_match_rank(pattern, domain).is_some())
    {
        return query_one(query, fallback, None, None, None).await;
    }

    if fallback_config.lazy {
        return match query_one(query, main, config.tls.as_ref(), tls_pool, http_pool).await {
            Ok(response) if response_passes_fallback_filter(&response, fallback_config)? => {
                Ok(response)
            }
            _ => query_one(query, fallback, None, None, None).await,
        };
    }

    let fallback_query = query.to_vec();
    let fallback_task =
        tokio::spawn(async move { query_one(&fallback_query, fallback, None, None, None).await });
    match query_one(query, main, config.tls.as_ref(), tls_pool, http_pool).await {
        Ok(response) if response_passes_fallback_filter(&response, fallback_config)? => {
            Ok(response)
        }
        _ => fallback_task
            .await
            .map_err(|_| DnsError::InvalidMessage("fallback query task failed"))?,
    }
}

async fn query_one(
    query: &[u8],
    upstream: DnsUpstream,
    tls: Option<&DnsTlsConfig>,
    tls_pool: Option<&Mutex<TlsConnectionPool>>,
    http_pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    match upstream.transport {
        DnsTransport::Udp => query_udp(query, upstream.address).await,
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
        DnsTransport::QuicVerifiedNoReuse => {
            let tls = tls.ok_or(DnsError::InvalidMessage(
                "verified DoQ upstream lacks verification configuration",
            ))?;
            query_quic_verified(query, upstream.address, tls).await
        }
    }
}

fn response_passes_fallback_filter(
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
        }))
}

fn policy_match_rank(pattern: &str, domain: &str) -> Option<Vec<u8>> {
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

fn positive_ttl(response: &[u8]) -> Result<Option<u32>, DnsError> {
    if response[3] & 0x0f != 0 || u16::from_be_bytes([response[6], response[7]]) == 0 {
        return Ok(None);
    }
    Ok(resource_ttls(response)?
        .into_iter()
        .map(|(_, ttl)| ttl)
        .min())
}

fn age_ttls(response: &mut [u8], elapsed: u32) -> Result<(), DnsError> {
    for (offset, ttl) in resource_ttls(response)? {
        response[offset..offset + 4].copy_from_slice(&ttl.saturating_sub(elapsed).to_be_bytes());
    }
    Ok(())
}

fn resource_ttls(message: &[u8]) -> Result<Vec<(usize, u32)>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let records = usize::from(u16::from_be_bytes([message[6], message[7]]))
        + usize::from(u16::from_be_bytes([message[8], message[9]]))
        + usize::from(u16::from_be_bytes([message[10], message[11]]));
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("question is truncated"))?;
    }

    let mut ttls = Vec::new();
    for _ in 0..records {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(DnsError::InvalidMessage("resource record is truncated"));
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let ttl_offset = offset + 4;
        let ttl = u32::from_be_bytes([
            message[ttl_offset],
            message[ttl_offset + 1],
            message[ttl_offset + 2],
            message[ttl_offset + 3],
        ]);
        let data_length = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        offset = offset
            .checked_add(10 + data_length)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("resource data is truncated"))?;
        if record_type != 41 {
            ttls.push((ttl_offset, ttl));
        }
    }
    Ok(ttls)
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    loop {
        let length = *message
            .get(offset)
            .ok_or(DnsError::InvalidMessage("name is truncated"))?;
        if length & 0xc0 == 0xc0 {
            if offset + 2 > message.len() {
                return Err(DnsError::InvalidMessage("name pointer is truncated"));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::InvalidMessage("invalid name label"));
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("name label is truncated"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(identifier: u16, ttl: u32) -> Vec<u8> {
        let mut message = identifier.to_be_bytes().to_vec();
        message.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        message.extend_from_slice(&[7]);
        message.extend_from_slice(b"example");
        message.extend_from_slice(&[4]);
        message.extend_from_slice(b"test");
        message.extend_from_slice(&[0, 0, 1, 0, 1]);
        message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&[0, 4, 192, 0, 2, 42]);
        message
    }

    #[test]
    fn extracts_and_ages_positive_ttl() {
        let mut message = response(1, 60);
        assert_eq!(positive_ttl(&message).expect("valid response"), Some(60));
        age_ttls(&mut message, 7).expect("age response");
        assert_eq!(positive_ttl(&message).expect("valid response"), Some(53));
    }

    #[test]
    fn cache_restores_identifier_and_expires() {
        let now = Instant::now();
        let mut cache = Cache::default();
        cache.insert(vec![1], response(10, 2), 2, now);
        let cached = cache
            .get(&[1], 20_u16.to_be_bytes(), now + Duration::from_secs(1))
            .expect("cache hit");
        assert_eq!(&cached[..2], &20_u16.to_be_bytes());
        assert_eq!(positive_ttl(&cached).expect("valid response"), Some(1));
        assert!(
            cache
                .get(&[1], 30_u16.to_be_bytes(), now + Duration::from_secs(2))
                .is_none()
        );
    }

    #[test]
    fn does_not_cache_negative_response() {
        let mut message = response(1, 60);
        message[3] = 0x83;
        assert_eq!(positive_ttl(&message).expect("valid response"), None);
    }

    #[test]
    fn recognizes_the_go_oracle_certificate_disable_true_forms() {
        for value in ["1", "t", "T", "true", "TRUE", "True"] {
            assert!(go_style_true(value));
        }
        for value in ["", "0", "f", "FALSE", "yes", " true"] {
            assert!(!go_style_true(value));
        }
    }

    #[test]
    fn ranks_static_wildcard_and_suffix_policies_like_the_go_trie() {
        assert!(policy_match_rank("exact.example.test", "exact.example.test").is_some());
        assert!(policy_match_rank("*.example.test", "one.example.test").is_some());
        assert!(policy_match_rank("*.example.test", "deep.one.example.test").is_none());
        assert!(policy_match_rank("+.example.test", "example.test").is_some());
        assert!(policy_match_rank("+.example.test", "deep.one.example.test").is_some());

        let exact =
            policy_match_rank("exact.example.test", "exact.example.test").expect("exact match");
        let wildcard =
            policy_match_rank("*.example.test", "exact.example.test").expect("wildcard match");
        let suffix =
            policy_match_rank("+.example.test", "exact.example.test").expect("suffix match");
        assert!(exact > wildcard);
        assert!(wildcard > suffix);
    }
}
