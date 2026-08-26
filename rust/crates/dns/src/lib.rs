use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use http::header::{ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, USER_AGENT};
use http::{HeaderValue, Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1::SendRequest as Http1SendRequest;
use hyper_util::rt::TokioIo;
use rewrite_config::{
    Config, DnsCacheAlgorithm, DnsClassicEndpoint, DnsClassicUpstream, DnsConfig,
    DnsFallbackConfig, DnsMainKind, DnsMode, DnsPolicy, DnsPolicyMatcher, DnsResolverClient,
    DnsTlsConfig, DnsTransport, DnsUpstream, DohProtocol, EcsConfig, FakeIpConfig,
    FakeIpFilterMode, FakeIpRuleAction, FakeIpRuleMatcher, GeositeDomainKind, HostEntry,
    RuleSetDomainKind, SyntheticRcode,
};
use rewrite_platform::SystemDnsTracker;
use rewrite_state::RuntimeState;
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, watch};
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
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_POOLED_TLS_CONNECTIONS: usize = 8;
const SYSTEM_DNS_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

/// Async DNS transport supplied by a future Tailscale outbound implementation.
pub trait TailscaleDnsResolver: Send + Sync {
    fn exchange<'a>(
        &'a self,
        query: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DnsError>> + Send + 'a>>;
}

struct TailscaleResolverEntry {
    id: u64,
    resolver: Arc<dyn TailscaleDnsResolver>,
}

fn tailscale_resolvers() -> &'static RwLock<BTreeMap<String, TailscaleResolverEntry>> {
    static RESOLVERS: OnceLock<RwLock<BTreeMap<String, TailscaleResolverEntry>>> = OnceLock::new();
    RESOLVERS.get_or_init(|| RwLock::new(BTreeMap::new()))
}

/// Registration guard for one named Tailscale DNS transport.
pub struct TailscaleDnsRegistration {
    name: String,
    id: u64,
}

impl Drop for TailscaleDnsRegistration {
    fn drop(&mut self) {
        let Ok(mut resolvers) = tailscale_resolvers().write() else {
            return;
        };
        if resolvers
            .get(&self.name)
            .is_some_and(|entry| entry.id == self.id)
        {
            resolvers.remove(&self.name);
        }
    }
}

/// Registers or replaces a named Tailscale DNS transport.
#[must_use]
pub fn register_tailscale_dns_resolver(
    name: impl Into<String>,
    resolver: Arc<dyn TailscaleDnsResolver>,
) -> TailscaleDnsRegistration {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let name = name.into();
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut resolvers) = tailscale_resolvers().write() {
        resolvers.insert(name.clone(), TailscaleResolverEntry { id, resolver });
    }
    TailscaleDnsRegistration { name, id }
}

#[derive(Default)]
struct SystemDnsCache {
    tracker: SystemDnsTracker,
    last_refresh: Option<Instant>,
}

#[derive(Default)]
struct DhcpDnsCacheEntry {
    tracker: rewrite_platform::DhcpRefreshTracker,
    servers: Vec<SocketAddr>,
    error: Option<(std::io::ErrorKind, String)>,
}

fn dhcp_dns_cache() -> &'static StdMutex<BTreeMap<String, DhcpDnsCacheEntry>> {
    static CACHE: OnceLock<StdMutex<BTreeMap<String, DhcpDnsCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| StdMutex::new(BTreeMap::new()))
}

fn dhcp_clock_start() -> Instant {
    static STARTED: OnceLock<Instant> = OnceLock::new();
    *STARTED.get_or_init(Instant::now)
}

fn system_dns_cache() -> &'static StdMutex<SystemDnsCache> {
    static CACHE: OnceLock<StdMutex<SystemDnsCache>> = OnceLock::new();
    CACHE.get_or_init(|| StdMutex::new(SystemDnsCache::default()))
}

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
    #[error("no ECH config found in DNS records")]
    NoEchConfig,
}

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    stored_at: Instant,
    lifetime: Duration,
}

enum CacheLookup {
    Fresh(Vec<u8>),
    Stale(Vec<u8>),
}

struct LruCache {
    entries: BTreeMap<Vec<u8>, CacheEntry>,
    order: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl LruCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&mut self, key: &[u8], identifier: [u8; 2], now: Instant) -> Option<CacheLookup> {
        let entry = self.entries.get(key)?.clone();
        touch(&mut self.order, key);
        Some(cache_lookup(entry, identifier, now))
    }

    fn insert(&mut self, key: Vec<u8>, response: Vec<u8>, ttl: u32, now: Instant) {
        if !self.entries.contains_key(&key)
            && self.entries.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        touch(&mut self.order, &key);
        self.entries.insert(key, cache_entry(response, ttl, now));
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ArcList {
    T1,
    T2,
    B1,
    B2,
}

struct ArcRecord {
    entry: Option<CacheEntry>,
    list: ArcList,
}

struct ArcCache {
    records: BTreeMap<Vec<u8>, ArcRecord>,
    t1: VecDeque<Vec<u8>>,
    t2: VecDeque<Vec<u8>>,
    b1: VecDeque<Vec<u8>>,
    b2: VecDeque<Vec<u8>>,
    target_t1: usize,
    capacity: usize,
}

impl ArcCache {
    fn new(capacity: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            target_t1: 0,
            capacity,
        }
    }

    fn get(&mut self, key: &[u8], identifier: [u8; 2], now: Instant) -> Option<CacheLookup> {
        let entry = self.records.get(key)?.entry.clone();
        self.request(key);
        entry.map(|entry| cache_lookup(entry, identifier, now))
    }

    fn insert(&mut self, key: &[u8], response: Vec<u8>, ttl: u32, now: Instant) {
        if let Some(record) = self.records.get_mut(key) {
            record.entry = Some(cache_entry(response, ttl, now));
            self.request(key);
            return;
        }
        self.records.insert(
            key.to_owned(),
            ArcRecord {
                entry: Some(cache_entry(response, ttl, now)),
                list: ArcList::T1,
            },
        );
        self.request_new(key);
    }

    fn request(&mut self, key: &[u8]) {
        let Some(list) = self.records.get(key).map(|record| record.list) else {
            return;
        };
        match list {
            ArcList::T1 | ArcList::T2 => self.move_to(key, ArcList::T2),
            ArcList::B1 => {
                let delta = if self.b1.len() >= self.b2.len() {
                    1
                } else {
                    self.b2.len() / self.b1.len().max(1)
                };
                self.target_t1 = self.target_t1.saturating_add(delta).min(self.capacity);
                self.replace(Some(ArcList::B1));
                self.move_to(key, ArcList::T2);
            }
            ArcList::B2 => {
                let delta = if self.b2.len() >= self.b1.len() {
                    1
                } else {
                    self.b1.len() / self.b2.len().max(1)
                };
                self.target_t1 = self.target_t1.saturating_sub(delta);
                self.replace(Some(ArcList::B2));
                self.move_to(key, ArcList::T2);
            }
        }
    }

    fn request_new(&mut self, key: &[u8]) {
        if self.t1.len() + self.b1.len() == self.capacity {
            if self.t1.len() < self.capacity {
                self.remove_lru(ArcList::B1);
                self.replace(None);
            } else {
                self.remove_lru(ArcList::T1);
            }
        } else if self.t1.len() + self.b1.len() < self.capacity {
            let total = self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len();
            if total >= self.capacity {
                if total == self.capacity.saturating_mul(2) {
                    self.remove_lru(ArcList::B2);
                }
                self.replace(None);
            }
        }
        self.move_to(key, ArcList::T1);
    }

    fn replace(&mut self, incoming: Option<ArcList>) {
        if !self.t1.is_empty()
            && (self.t1.len() > self.target_t1
                || (incoming == Some(ArcList::B2) && self.t1.len() == self.target_t1))
        {
            if let Some(key) = self.t1.pop_back() {
                self.make_ghost(&key, ArcList::B1);
            }
        } else if let Some(key) = self.t2.pop_back() {
            self.make_ghost(&key, ArcList::B2);
        }
    }

    fn make_ghost(&mut self, key: &[u8], list: ArcList) {
        if let Some(record) = self.records.get_mut(key) {
            record.entry = None;
            record.list = list;
        }
        self.list_mut(list).push_front(key.to_vec());
    }

    fn move_to(&mut self, key: &[u8], target: ArcList) {
        if let Some(current) = self.records.get(key).map(|record| record.list) {
            remove_key(self.list_mut(current), key);
        }
        self.list_mut(target).push_front(key.to_vec());
        if let Some(record) = self.records.get_mut(key) {
            record.list = target;
        }
    }

    fn remove_lru(&mut self, list: ArcList) {
        if let Some(key) = self.list_mut(list).pop_back() {
            self.records.remove(&key);
        }
    }

    fn list_mut(&mut self, list: ArcList) -> &mut VecDeque<Vec<u8>> {
        match list {
            ArcList::T1 => &mut self.t1,
            ArcList::T2 => &mut self.t2,
            ArcList::B1 => &mut self.b1,
            ArcList::B2 => &mut self.b2,
        }
    }
}

enum Cache {
    Lru(LruCache),
    Arc(ArcCache),
}

impl Cache {
    fn new(algorithm: DnsCacheAlgorithm, capacity: usize) -> Self {
        match algorithm {
            DnsCacheAlgorithm::Lru => Self::Lru(LruCache::new(capacity)),
            DnsCacheAlgorithm::Arc => Self::Arc(ArcCache::new(capacity)),
        }
    }

    fn matches(&self, algorithm: DnsCacheAlgorithm, capacity: usize) -> bool {
        match self {
            Self::Lru(cache) => algorithm == DnsCacheAlgorithm::Lru && cache.capacity == capacity,
            Self::Arc(cache) => algorithm == DnsCacheAlgorithm::Arc && cache.capacity == capacity,
        }
    }

    fn get(&mut self, key: &[u8], identifier: [u8; 2], now: Instant) -> Option<CacheLookup> {
        match self {
            Self::Lru(cache) => cache.get(key, identifier, now),
            Self::Arc(cache) => cache.get(key, identifier, now),
        }
    }

    fn insert(&mut self, key: Vec<u8>, response: Vec<u8>, ttl: u32, now: Instant) {
        match self {
            Self::Lru(cache) => cache.insert(key, response, ttl, now),
            Self::Arc(cache) => cache.insert(&key, response, ttl, now),
        }
    }

    fn clear(&mut self) {
        match self {
            Self::Lru(cache) => *cache = LruCache::new(cache.capacity),
            Self::Arc(cache) => *cache = ArcCache::new(cache.capacity),
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new(DnsCacheAlgorithm::Lru, 4096)
    }
}

fn cache_entry(response: Vec<u8>, ttl: u32, now: Instant) -> CacheEntry {
    CacheEntry {
        response,
        stored_at: now,
        lifetime: Duration::from_secs(u64::from(ttl)),
    }
}

fn cache_lookup(entry: CacheEntry, identifier: [u8; 2], now: Instant) -> CacheLookup {
    let elapsed = now.saturating_duration_since(entry.stored_at);
    let mut response = entry.response;
    response[..2].copy_from_slice(&identifier);
    if elapsed >= entry.lifetime {
        set_ttls(&mut response, 1).ok();
        return CacheLookup::Stale(response);
    }
    let rounded_seconds = elapsed
        .as_secs()
        .saturating_add(u64::from(elapsed.subsec_nanos() != 0));
    let elapsed_seconds = u32::try_from(rounded_seconds).unwrap_or(u32::MAX);
    let _ = age_ttls(&mut response, elapsed_seconds);
    CacheLookup::Fresh(response)
}

fn touch(order: &mut VecDeque<Vec<u8>>, key: &[u8]) {
    remove_key(order, key);
    order.push_back(key.to_vec());
}

fn remove_key(order: &mut VecDeque<Vec<u8>>, key: &[u8]) {
    if let Some(position) = order.iter().position(|candidate| candidate == key) {
        order.remove(position);
    }
}

#[derive(Default)]
struct TlsConnectionPool {
    key: Vec<u8>,
    connections: Vec<TlsStream<TcpStream>>,
    h1_key: Vec<u8>,
    h1_senders: Vec<Http1Sender>,
    h2_key: Vec<u8>,
    h2_sender: Option<h2::client::SendRequest<Bytes>>,
    h3_key: Vec<u8>,
    h3_endpoint: Option<quinn::Endpoint>,
    h3_connection: Option<quinn::Connection>,
    h3_sender: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    doh_choice_key: Vec<u8>,
    doh_choice: Option<DohProtocol>,
    doq_key: Vec<u8>,
    doq_endpoint: Option<quinn::Endpoint>,
    doq_connection: Option<quinn::Connection>,
}

#[derive(Default)]
struct HttpConnectionPool {
    key: Vec<u8>,
    senders: Vec<Http1Sender>,
}

type Http1Sender = Http1SendRequest<Empty<Bytes>>;

type SharedDnsResult = Result<Vec<u8>, SharedDnsError>;

#[derive(Clone)]
enum SharedDnsError {
    Io(String),
    InvalidMessage(&'static str),
    UpstreamTimeout,
    Inactive,
    NoAddress,
    NoEchConfig,
}

impl SharedDnsError {
    fn capture(error: &DnsError) -> Self {
        match error {
            DnsError::Io(error) => Self::Io(error.to_string()),
            DnsError::InvalidMessage(message) => Self::InvalidMessage(message),
            DnsError::UpstreamTimeout => Self::UpstreamTimeout,
            DnsError::Inactive => Self::Inactive,
            DnsError::NoAddress => Self::NoAddress,
            DnsError::NoEchConfig => Self::NoEchConfig,
        }
    }

    fn restore(self) -> DnsError {
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

struct InflightQuery {
    result: StdMutex<Option<SharedDnsResult>>,
    ready: Notify,
}

impl InflightQuery {
    fn new() -> Self {
        Self {
            result: StdMutex::new(None),
            ready: Notify::new(),
        }
    }

    fn complete(&self, result: SharedDnsResult) {
        if let Ok(mut stored) = self.result.lock() {
            *stored = Some(result);
        }
        self.ready.notify_waiters();
    }

    async fn wait(&self) -> Result<Vec<u8>, DnsError> {
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
struct Resolver {
    cache: Arc<Mutex<Cache>>,
    inflight: Arc<Mutex<BTreeMap<Vec<u8>, Arc<InflightQuery>>>>,
    tls_pool: Arc<Mutex<TlsConnectionPool>>,
    http_pool: Arc<Mutex<HttpConnectionPool>>,
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
            cache: Arc::new(Mutex::new(Cache::default())),
            inflight: Arc::new(Mutex::new(BTreeMap::new())),
            tls_pool: Arc::new(Mutex::new(TlsConnectionPool::default())),
            http_pool: Arc::new(Mutex::new(HttpConnectionPool::default())),
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

    async fn resolve_upstream(
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

    async fn exchange_shared(
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

    async fn background_retry(&self, query: &[u8], config: &DnsConfig, key: Vec<u8>) {
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

    async fn exchange_once(
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

fn preferred_address(addresses: Vec<IpAddr>) -> Result<IpAddr, DnsError> {
    addresses
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| addresses.into_iter().next())
        .ok_or(DnsError::NoAddress)
}

async fn lookup_domain_from_set(
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

async fn lookup_domain_with(
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

async fn finish_dual_stack(
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

async fn query_set_addresses(
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

async fn query_configured_addresses(
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

fn literal_addresses(host: &str, record_type: u16) -> Result<Option<Vec<IpAddr>>, DnsError> {
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

fn response_addresses(response: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
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
                        match local_query_disposition(&query) {
                            LocalQueryDisposition::Ignore => continue,
                            LocalQueryDisposition::Reject(response) => {
                                tasks.spawn(async move {
                                    let _ = socket.send_to(&response, peer).await;
                                });
                                continue;
                            }
                            LocalQueryDisposition::Accept => {}
                        }
                        let service = Arc::clone(&service);
                        let current = current_config(&config);
                        let state = Arc::clone(&state);
                        tasks.spawn(async move {
                            let Ok(current) = current else { return };
                            let response = service
                                .resolver
                                .resolve(&query, &current, &state)
                                .await;
                            let response = match response {
                                Ok(response) => local_response(&query, response, true),
                                Err(_) => server_failure_response(&query),
                            };
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
        match local_query_disposition(&query) {
            LocalQueryDisposition::Ignore => continue,
            LocalQueryDisposition::Reject(response) => {
                if write_tcp_response(&mut stream, &response).await.is_err() {
                    return;
                }
                continue;
            }
            LocalQueryDisposition::Accept => {}
        }
        let Ok(current) = current_config(&config) else {
            return;
        };
        let response = service.resolver.resolve(&query, &current, &state).await;
        let response = match response {
            Ok(response) => local_response(&query, response, false),
            Err(_) => server_failure_response(&query),
        };
        let Ok(response) = response else { return };
        if write_tcp_response(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

async fn write_tcp_response(stream: &mut TcpStream, response: &[u8]) -> Result<(), DnsError> {
    let length = u16::try_from(response.len())
        .map_err(|_| DnsError::InvalidMessage("response exceeds TCP DNS frame"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(response).await?;
    Ok(())
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

enum LocalQueryDisposition {
    Accept,
    Ignore,
    Reject(Vec<u8>),
}

fn local_query_disposition(query: &[u8]) -> LocalQueryDisposition {
    if query.len() < DNS_HEADER_LENGTH {
        return LocalQueryDisposition::Ignore;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return LocalQueryDisposition::Ignore;
    }
    let opcode = (flags >> 11) & 0x0f;
    if !matches!(opcode, 0 | 4) {
        return LocalQueryDisposition::Reject(local_rejection_response(query, 4, true));
    }
    let questions = u16::from_be_bytes([query[4], query[5]]);
    let answers = u16::from_be_bytes([query[6], query[7]]);
    let authorities = u16::from_be_bytes([query[8], query[9]]);
    let additionals = u16::from_be_bytes([query[10], query[11]]);
    if questions != 1 || answers > 1 || authorities > 1 || additionals > 2 {
        return LocalQueryDisposition::Reject(local_rejection_response(query, 1, false));
    }
    if validate_dns_wire(query).is_err() {
        return LocalQueryDisposition::Reject(local_rejection_response(query, 1, false));
    }
    LocalQueryDisposition::Accept
}

fn local_rejection_response(query: &[u8], rcode: u8, preserve_opcode: bool) -> Vec<u8> {
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let mut flags = 0x8000 | (request_flags & 0x03b0) | u16::from(rcode);
    if preserve_opcode {
        flags |= request_flags & 0x7800;
    }
    let mut response = Vec::with_capacity(DNS_HEADER_LENGTH);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&[0; 8]);
    response
}

fn validate_dns_wire(message: &[u8]) -> Result<(), DnsError> {
    let counts = [
        usize::from(u16::from_be_bytes([message[4], message[5]])),
        usize::from(u16::from_be_bytes([message[6], message[7]])),
        usize::from(u16::from_be_bytes([message[8], message[9]])),
        usize::from(u16::from_be_bytes([message[10], message[11]])),
    ];
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..counts[0] {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    for _ in 0..counts[1] + counts[2] + counts[3] {
        offset = resource_record_end(message, offset)?.1;
    }
    if offset > message.len() {
        return Err(DnsError::InvalidMessage("DNS message is truncated"));
    }
    Ok(())
}

fn local_response(query: &[u8], mut response: Vec<u8>, udp: bool) -> Result<Vec<u8>, DnsError> {
    if let Some((_, request_do)) = message_edns(query)?
        && message_edns(&response)?.is_none()
    {
        append_edns(&mut response, 1232, request_do)?;
    }
    if udp {
        let limit = message_edns(query)?.map_or(512, |(size, _)| usize::from(size));
        truncate_udp_response(&response, limit.max(512))
    } else {
        Ok(response)
    }
}

fn message_edns(message: &[u8]) -> Result<Option<(u16, bool)>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answers = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let authorities = usize::from(u16::from_be_bytes([message[8], message[9]]));
    let additionals = usize::from(u16::from_be_bytes([message[10], message[11]]));
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    for _ in 0..answers + authorities {
        offset = resource_record_end(message, offset)?.1;
    }
    for _ in 0..additionals {
        let name_end = skip_name(message, offset)?;
        if name_end + 10 > message.len() {
            return Err(DnsError::InvalidMessage("resource record is truncated"));
        }
        let record_type = u16::from_be_bytes([message[name_end], message[name_end + 1]]);
        let class = u16::from_be_bytes([message[name_end + 2], message[name_end + 3]]);
        let ttl = u32::from_be_bytes([
            message[name_end + 4],
            message[name_end + 5],
            message[name_end + 6],
            message[name_end + 7],
        ]);
        let end = resource_record_end(message, offset)?.1;
        if record_type == 41 {
            return Ok(Some((class, ttl & 0x8000 != 0)));
        }
        offset = end;
    }
    Ok(None)
}

fn append_edns(response: &mut Vec<u8>, udp_size: u16, dnssec_ok: bool) -> Result<(), DnsError> {
    let additionals = u16::from_be_bytes([response[10], response[11]])
        .checked_add(1)
        .ok_or(DnsError::InvalidMessage("too many additional records"))?;
    response[10..12].copy_from_slice(&additionals.to_be_bytes());
    response.push(0);
    response.extend_from_slice(&41_u16.to_be_bytes());
    response.extend_from_slice(&udp_size.to_be_bytes());
    response.extend_from_slice(&(if dnssec_ok { 0x8000_u32 } else { 0 }).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    Ok(())
}

fn truncate_udp_response(message: &[u8], limit: usize) -> Result<Vec<u8>, DnsError> {
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let counts = [
        usize::from(u16::from_be_bytes([message[6], message[7]])),
        usize::from(u16::from_be_bytes([message[8], message[9]])),
        usize::from(u16::from_be_bytes([message[10], message[11]])),
    ];
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = checked_record_end(message, offset, 4, "question is truncated")?;
    }
    let question_end = offset;
    let mut sections = [Vec::new(), Vec::new(), Vec::new()];
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let start = offset;
            let (record_type, end) = resource_record_end(message, start)?;
            sections[section].push((record_type, start, end));
            offset = end;
        }
    }

    if sections[2]
        .last()
        .is_some_and(|(record_type, _, _)| *record_type == 250)
        || message.len() <= limit
    {
        return Ok(message.to_vec());
    }

    let edns = sections[2]
        .iter()
        .rposition(|(record_type, _, _)| *record_type == 41)
        .map(|index| sections[2].remove(index));
    let edns_length = edns.map_or(0, |(_, start, end)| end - start);
    let budget = limit.saturating_sub(edns_length);
    let mut response = message[..question_end].to_vec();
    let mut retained = [0_u16; 3];
    let mut exhausted = false;
    let mut omitted = false;
    for (section_index, section) in sections.iter().enumerate() {
        for &(_, start, end) in section {
            if !exhausted && response.len() + end - start <= budget {
                response.extend_from_slice(&message[start..end]);
                retained[section_index] += 1;
            } else {
                exhausted = true;
                omitted = true;
            }
        }
    }
    if let Some((_, start, end)) = edns {
        response.extend_from_slice(&message[start..end]);
        retained[2] += 1;
    }
    response[6..8].copy_from_slice(&retained[0].to_be_bytes());
    response[8..10].copy_from_slice(&retained[1].to_be_bytes());
    response[10..12].copy_from_slice(&retained[2].to_be_bytes());
    if omitted {
        response[2] |= 0x02;
    }
    Ok(response)
}

fn empty_upstream_answer(query: &[u8], question: &Question) -> Vec<u8> {
    let mut response = query[..question.end].to_vec();
    response[2] = 0x84 | (query[2] & 0x79);
    response[3] = (query[3] & 0xf0) | 0x80;
    response[6..12].fill(0);
    response
}

fn apply_ecs(query: &[u8], ecs: EcsConfig) -> Result<Vec<u8>, DnsError> {
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

fn ecs_option(ecs: EcsConfig) -> Vec<u8> {
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

fn filter_disabled_records(message: &[u8], disabled_types: &[u16]) -> Result<Vec<u8>, DnsError> {
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

fn resource_record_end(message: &[u8], start: usize) -> Result<(u16, usize), DnsError> {
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

fn lookup_host(name: &str, config: &Config, dns: &DnsConfig) -> Option<HostLookup> {
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

fn fake_ip_rule_matches(matcher: &FakeIpRuleMatcher, host: &str) -> bool {
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

fn wildcard_matches(pattern: &str, value: &str) -> bool {
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

fn answer_https_ech(message: &[u8]) -> Result<Option<Vec<u8>>, DnsError> {
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

fn parse_system_hosts(contents: &str) -> BTreeMap<String, Vec<IpAddr>> {
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

struct SystemHostsCache {
    checked_at: Option<Instant>,
    modified: Option<std::time::SystemTime>,
    size: u64,
    entries: BTreeMap<String, Vec<IpAddr>>,
}

impl SystemHostsCache {
    fn new() -> Self {
        Self {
            checked_at: None,
            modified: None,
            size: 0,
            entries: BTreeMap::new(),
        }
    }

    fn lookup(&mut self, name: &str) -> Option<Vec<IpAddr>> {
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

    fn refresh(&mut self) {
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

fn system_hosts_cache() -> &'static StdMutex<SystemHostsCache> {
    static CACHE: OnceLock<StdMutex<SystemHostsCache>> = OnceLock::new();
    CACHE.get_or_init(|| StdMutex::new(SystemHostsCache::new()))
}

fn system_hosts_path() -> std::path::PathBuf {
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

async fn query_udp_with_tcp_retry(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>, DnsError> {
    let response = query_udp(query, upstream).await?;
    if response.len() >= DNS_HEADER_LENGTH && response[2] & 0x02 != 0 {
        query_tcp(query, upstream).await
    } else {
        Ok(response)
    }
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

async fn return_tls_http1_sender(pool: &Mutex<TlsConnectionPool>, key: &[u8], sender: Http1Sender) {
    let mut pool = pool.lock().await;
    if pool.h1_key != key {
        return;
    }
    if pool.h1_senders.len() >= MAX_POOLED_TLS_CONNECTIONS {
        pool.h1_senders.remove(0);
    }
    pool.h1_senders.push(sender);
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

async fn start_http1<S>(stream: S) -> Result<Http1Sender, DnsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        hyper::client::conn::http1::handshake(TokioIo::new(stream)),
    )
    .await
    .map_err(|_| DnsError::UpstreamTimeout)?
    .map_err(std::io::Error::other)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

async fn exchange_doh_http1(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    sender: &mut Http1Sender,
) -> Result<(Vec<u8>, bool), DnsError> {
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
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(&target)
            .header(HOST, &authority)
            .header(ACCEPT, "application/dns-message")
            .header(USER_AGENT, "");
        if let Some(credentials) = &tls.doh_basic_credentials {
            let authorization = HeaderValue::from_str(&format!(
                "Basic {}",
                STANDARD.encode(credentials.as_bytes())
            ))
            .map_err(|_| DnsError::InvalidMessage("invalid DoH authorization"))?;
            request = request.header(AUTHORIZATION, authorization);
        }
        let request = request
            .body(Empty::new())
            .map_err(|_| DnsError::InvalidMessage("invalid DoH request"))?;
        let response = tokio::time::timeout(UPSTREAM_TIMEOUT, sender.send_request(request))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)?
            .map_err(std::io::Error::other)?;
        let (status, location, mut response, reusable) = read_doh_http1_response(response).await?;
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

async fn read_doh_http1_response(
    response: http::Response<hyper::body::Incoming>,
) -> Result<(u16, Option<String>, Vec<u8>, bool), DnsError> {
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let reusable = !response
        .headers()
        .get(CONNECTION)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"close"));
    let expected_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(DnsError::InvalidMessage(
            "DoH response Content-Length is missing",
        ))?;
    if expected_length > MAX_DNS_MESSAGE {
        return Err(DnsError::InvalidMessage("DoH response is too large"));
    }
    let mut body = response.into_body();
    let mut message = Vec::with_capacity(expected_length);
    while let Some(frame) = tokio::time::timeout(UPSTREAM_TIMEOUT, body.frame())
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .transpose()
        .map_err(std::io::Error::other)?
    {
        if let Some(data) = frame.data_ref() {
            if message.len().saturating_add(data.len()) > expected_length {
                return Err(DnsError::InvalidMessage("DoH response is too large"));
            }
            message.extend_from_slice(data);
        }
    }
    if message.len() != expected_length {
        return Err(DnsError::InvalidMessage("DoH response body is truncated"));
    }
    Ok((status, location, message, reusable))
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

async fn return_http_sender(pool: &Mutex<HttpConnectionPool>, key: &[u8], sender: Http1Sender) {
    let mut pool = pool.lock().await;
    if pool.key != key {
        return;
    }
    if pool.senders.len() >= MAX_POOLED_TLS_CONNECTIONS {
        pool.senders.remove(0);
    }
    pool.senders.push(sender);
}

async fn query_http_reuse(
    query: &[u8],
    upstream: SocketAddr,
    http: &DnsTlsConfig,
    pool: Option<&Mutex<HttpConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let key = http_pool_key(upstream, http);
    if let Some(pool) = pool {
        let old_sender = {
            let mut pool = pool.lock().await;
            if pool.key != key {
                pool.senders.clear();
                pool.key.clone_from(&key);
            }
            pool.senders.pop()
        };
        if let Some(mut sender) = old_sender
            && let Ok((response, reusable)) =
                exchange_doh_http1(query, upstream, http, &mut sender).await
        {
            if reusable {
                return_http_sender(pool, &key, sender).await;
            }
            return Ok(response);
        }
    }

    let stream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| DnsError::UpstreamTimeout)??;
    let mut sender = start_http1(stream).await?;
    let (response, reusable) = exchange_doh_http1(query, upstream, http, &mut sender).await?;
    if reusable && let Some(pool) = pool {
        return_http_sender(pool, &key, sender).await;
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

async fn query_quic_verified_reuse(
    query: &[u8],
    upstream: SocketAddr,
    tls: &DnsTlsConfig,
    pool: Option<&Mutex<TlsConnectionPool>>,
) -> Result<Vec<u8>, DnsError> {
    let address = resolve_tls_endpoint(upstream, tls).await?;
    let Some(pool) = pool else {
        let endpoint = verified_quic_endpoint(tls, b"doq", true)?;
        let connection = connect_quic(&endpoint, address, tls).await?;
        let result = exchange_doq(query, &connection).await;
        connection.close(0_u32.into(), b"one-shot DoQ complete");
        return result;
    };
    let key = tls_pool_key(upstream, tls);
    let (mut connection, had_connection) = acquire_doq_connection(pool, &key, address, tls).await?;
    let attempts = if had_connection { 3 } else { 1 };
    for attempt in 0..attempts {
        match exchange_doq(query, &connection).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                discard_doq_connection(pool, &key, connection.stable_id(), true).await;
                if attempt + 1 == attempts {
                    return Err(error);
                }
                connection = acquire_doq_connection(pool, &key, address, tls).await?.0;
            }
        }
    }
    unreachable!("DoQ always performs at least one attempt")
}

async fn acquire_doq_connection(
    pool: &Mutex<TlsConnectionPool>,
    key: &[u8],
    address: SocketAddr,
    tls: &DnsTlsConfig,
) -> Result<(quinn::Connection, bool), DnsError> {
    let mut pool = pool.lock().await;
    if pool.doq_key != key {
        if let Some(connection) = pool.doq_connection.take() {
            connection.close(0_u32.into(), b"DoQ configuration changed");
        }
        pool.doq_endpoint = None;
        pool.doq_key.clear();
        pool.doq_key.extend_from_slice(key);
    }
    let had_connection = pool.doq_connection.is_some();
    if let Some(connection) = &pool.doq_connection
        && connection.close_reason().is_none()
    {
        return Ok((connection.clone(), had_connection));
    }
    pool.doq_connection = None;
    if pool.doq_endpoint.is_none() {
        // Go keeps QUIC address-validation tokens but has no TLS session cache,
        // so reconnects remain full TLS handshakes rather than 0-RTT.
        pool.doq_endpoint = Some(verified_quic_endpoint(tls, b"doq", true)?);
    }
    let connection = connect_quic(
        pool.doq_endpoint.as_ref().expect("DoQ endpoint"),
        address,
        tls,
    )
    .await?;
    pool.doq_connection = Some(connection.clone());
    Ok((connection, had_connection))
}

async fn discard_doq_connection(
    pool: &Mutex<TlsConnectionPool>,
    key: &[u8],
    stable_id: usize,
    internal_error: bool,
) {
    let mut pool = pool.lock().await;
    if pool.doq_key == key
        && pool
            .doq_connection
            .as_ref()
            .is_some_and(|connection| connection.stable_id() == stable_id)
        && let Some(connection) = pool.doq_connection.take()
    {
        let code = u32::from(internal_error);
        connection.close(code.into(), b"DoQ exchange failed");
    }
}

async fn exchange_doq(query: &[u8], connection: &quinn::Connection) -> Result<Vec<u8>, DnsError> {
    tokio::time::timeout(UPSTREAM_TIMEOUT, async {
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
    .map_err(|_| DnsError::UpstreamTimeout)?
}

async fn connect_quic(
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
        let connection = connect_quic(&endpoint, address, tls).await?;
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
        let connection = connect_quic(endpoint, address, tls).await?;
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

    let old_sender = {
        if let Some(pool) = pool {
            let mut pool = pool.lock().await;
            if pool.h1_key != key {
                pool.h1_senders.clear();
                pool.h1_key.clone_from(&key);
            }
            pool.h1_senders.pop()
        } else {
            None
        }
    };
    if let Some(mut sender) = old_sender
        && let Ok((response, reusable)) =
            exchange_doh_http1(query, upstream, tls, &mut sender).await
    {
        if reusable && let Some(pool) = pool {
            return_tls_http1_sender(pool, &key, sender).await;
        }
        return Ok(response);
    }

    let stream = connect_https_verified(upstream, tls).await?;
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
    let mut sender = start_http1(stream).await?;
    let (response, reusable) = exchange_doh_http1(query, upstream, tls, &mut sender).await?;
    if reusable && let Some(pool) = pool {
        return_tls_http1_sender(pool, &key, sender).await;
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

fn rest_record_data(
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

fn format_character_strings(data: &[u8]) -> Result<String, DnsError> {
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

fn format_rfc3597(data: &[u8]) -> String {
    let mut hex = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("\\# {} {hex}", data.len())
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
        DnsTransport::QuicVerifiedReuse => 8,
    });
    key.extend_from_slice(upstream.to_string().as_bytes());
    key.push(0);
    key.extend_from_slice(&[0, 0]);
    key.extend_from_slice(&query[2..]);
    key
}

fn resolution_cache_key(query: &[u8], config: &DnsConfig, domain: &str) -> Vec<u8> {
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

fn append_resolver_clients_cache_identity(key: &mut Vec<u8>, clients: &[DnsResolverClient]) {
    key.push(0xee);
    for client in clients {
        key.extend_from_slice(format!("{client:?}").as_bytes());
        key.push(0);
    }
}

fn append_query_options_cache_identity(
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

fn append_main_kind_cache_identity(key: &mut Vec<u8>, main_kind: &DnsMainKind) {
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

fn selected_policy<'a>(policies: &'a [DnsPolicy], domain: &str) -> Option<&'a [DnsResolverClient]> {
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

fn policy_matcher_matches(matcher: &DnsPolicyMatcher, domain: &str) -> bool {
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

async fn query_configured(
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

async fn query_main(
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

async fn query_resolver_set(
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

async fn query_resolver_client(
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

fn query_rcode(query: &[u8], rcode: SyntheticRcode) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] |= 0x80;
    response[3] = (response[3] & 0xf0) | rcode as u8;
    response
}

async fn query_tailscale(query: &[u8], name: &str) -> Result<Vec<u8>, DnsError> {
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

async fn query_dhcp(query: &[u8], interface: &str) -> Result<Vec<u8>, DnsError> {
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

fn active_dhcp_dns(interface: &str) -> std::io::Result<Vec<SocketAddr>> {
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

fn cached_dhcp_result(entry: &DhcpDnsCacheEntry) -> std::io::Result<Vec<SocketAddr>> {
    match &entry.error {
        Some((kind, message)) => Err(std::io::Error::new(*kind, message.clone())),
        None => Ok(entry.servers.clone()),
    }
}

async fn query_system(query: &[u8]) -> Result<Vec<u8>, DnsError> {
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

fn active_system_dns() -> Result<Vec<SocketAddr>, DnsError> {
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

async fn query_classic_group(
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

async fn query_classic_wrapped(
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

async fn query_classic(query: &[u8], upstream: &DnsClassicUpstream) -> Result<Vec<u8>, DnsError> {
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

async fn query_one(
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
                && !fallback
                    .geoip
                    .as_ref()
                    .is_some_and(|filter| geoip_requires_fallback(*address, filter))
        }))
}

fn geoip_requires_fallback(address: IpAddr, filter: &rewrite_config::DnsGeoIpFilter) -> bool {
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

fn is_lan_address(address: IpAddr) -> bool {
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

#[cfg(test)]
fn positive_ttl(response: &[u8]) -> Result<Option<u32>, DnsError> {
    if response[3] & 0x0f != 0 || u16::from_be_bytes([response[6], response[7]]) == 0 {
        return Ok(None);
    }
    Ok(resource_ttls(response)?
        .into_iter()
        .map(|(_, ttl)| ttl)
        .min())
}

fn cache_ttl(response: &[u8]) -> Result<Option<u32>, DnsError> {
    if response.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    if response[3] & 0x0f == 2 {
        return Ok(Some(5));
    }
    Ok(resource_ttls(response)?
        .into_iter()
        .map(|(_, ttl)| ttl)
        .min()
        .filter(|ttl| *ttl > 0))
}

fn age_ttls(response: &mut [u8], elapsed: u32) -> Result<(), DnsError> {
    for (offset, ttl) in resource_ttls(response)? {
        let aged = ttl.saturating_sub(elapsed).max(1).min(ttl);
        response[offset..offset + 4].copy_from_slice(&aged.to_be_bytes());
    }
    Ok(())
}

fn set_ttls(response: &mut [u8], ttl: u32) -> Result<(), DnsError> {
    for (offset, _) in resource_ttls(response)? {
        response[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
    }
    Ok(())
}

fn without_opt_records(message: &[u8]) -> Result<Vec<u8>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
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
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("question is truncated"))?;
    }
    let question_end = offset;
    let mut records = Vec::new();
    for (section, count) in section_counts.into_iter().enumerate() {
        for _ in 0..count {
            let start = offset;
            offset = skip_name(message, offset)?;
            if offset + 10 > message.len() {
                return Err(DnsError::InvalidMessage("resource record is truncated"));
            }
            let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
            let data_length = usize::from(u16::from_be_bytes([
                message[offset + 8],
                message[offset + 9],
            ]));
            offset = offset
                .checked_add(10 + data_length)
                .filter(|end| *end <= message.len())
                .ok_or(DnsError::InvalidMessage("resource data is truncated"))?;
            records.push((section, record_type, start, offset));
        }
    }
    if !records
        .iter()
        .any(|(_, record_type, _, _)| *record_type == 41)
    {
        return Ok(message.to_vec());
    }
    let first_opt = records
        .iter()
        .position(|(_, record_type, _, _)| *record_type == 41)
        .expect("OPT presence checked");
    if records[first_opt..]
        .iter()
        .any(|(_, record_type, _, _)| *record_type != 41)
    {
        return Ok(message.to_vec());
    }
    let mut response = message[..question_end].to_vec();
    let mut kept = [0_u16; 3];
    for (section, record_type, start, end) in records {
        if record_type != 41 {
            response.extend_from_slice(&message[start..end]);
            kept[section] = kept[section].saturating_add(1);
        }
    }
    for (index, count) in kept.into_iter().enumerate() {
        let count_offset = 6 + index * 2;
        response[count_offset..count_offset + 2].copy_from_slice(&count.to_be_bytes());
    }
    Ok(response)
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

    struct FixtureTailscaleResolver {
        marker: u8,
    }

    impl TailscaleDnsResolver for FixtureTailscaleResolver {
        fn exchange<'a>(
            &'a self,
            query: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DnsError>> + Send + 'a>> {
            Box::pin(async move {
                let mut response = query.to_vec();
                response[2] |= 0x80;
                response.push(self.marker);
                Ok(response)
            })
        }
    }

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

    fn response_with_record(record_type: u16, rdata: &[u8]) -> Vec<u8> {
        let mut message = 1_u16.to_be_bytes().to_vec();
        message.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        message.extend_from_slice(&[7]);
        message.extend_from_slice(b"example");
        message.extend_from_slice(&[4]);
        message.extend_from_slice(b"test");
        message.extend_from_slice(&[0]);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c]);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&30_u32.to_be_bytes());
        message.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test resource data fits DNS length")
                .to_be_bytes(),
        );
        message.extend_from_slice(rdata);
        message
    }

    #[test]
    fn renders_complex_rest_resource_records() {
        let mx = response_with_record(
            15,
            &[
                0, 10, 4, b'm', b'a', b'i', b'l', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4,
                b't', b'e', b's', b't', 0,
            ],
        );
        let parsed = rest_response(&mx).expect("MX response");
        assert_eq!(parsed.answer[0].data, "10 mail.example.test.");

        let txt = response_with_record(16, &[5, b'h', b'e', b'l', b'l', b'o']);
        let parsed = rest_response(&txt).expect("TXT response");
        assert_eq!(parsed.answer[0].data, "\"hello\"");

        let unknown = response_with_record(65400, &[0xde, 0xad, 0xbe, 0xef]);
        let parsed = rest_response(&unknown).expect("RFC3597 response");
        assert_eq!(parsed.answer[0].data, "\\# 4 deadbeef");
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
        let mut cache = Cache::new(DnsCacheAlgorithm::Lru, 2);
        cache.insert(vec![1], response(10, 2), 2, now);
        let CacheLookup::Fresh(cached) = cache
            .get(&[1], 20_u16.to_be_bytes(), now + Duration::from_secs(1))
            .expect("cache hit")
        else {
            panic!("response should still be fresh");
        };
        assert_eq!(&cached[..2], &20_u16.to_be_bytes());
        assert_eq!(positive_ttl(&cached).expect("valid response"), Some(1));
        let CacheLookup::Stale(cached) = cache
            .get(&[1], 30_u16.to_be_bytes(), now + Duration::from_secs(2))
            .expect("stale cache hit")
        else {
            panic!("response should be stale");
        };
        assert_eq!(&cached[..2], &30_u16.to_be_bytes());
        assert_eq!(positive_ttl(&cached).expect("valid response"), Some(1));
    }

    #[test]
    fn derives_positive_and_negative_cache_lifetimes() {
        let mut message = response(1, 60);
        message[3] = 0x83;
        assert_eq!(positive_ttl(&message).expect("valid response"), None);
        assert_eq!(cache_ttl(&message).expect("valid response"), Some(60));
    }

    #[test]
    fn lru_and_arc_have_go_compatible_scan_behavior() {
        let now = Instant::now();
        let value = |id| response(id, 60);
        let mut lru = Cache::new(DnsCacheAlgorithm::Lru, 2);
        let mut arc = Cache::new(DnsCacheAlgorithm::Arc, 2);
        for cache in [&mut lru, &mut arc] {
            cache.insert(vec![1], value(1), 60, now);
            cache.insert(vec![2], value(2), 60, now);
            assert!(cache.get(&[1], [0, 1], now).is_some());
            cache.insert(vec![3], value(3), 60, now);
            cache.insert(vec![4], value(4), 60, now);
        }
        assert!(lru.get(&[1], [0, 1], now).is_none());
        assert!(arc.get(&[1], [0, 1], now).is_some());
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
    fn parses_system_hosts_aliases_case_insensitively() {
        let hosts = parse_system_hosts(
            "192.0.2.1 Primary.Example Alias.Example # comment\n\
             2001:db8::1 alias.example.\n\
             invalid ignored.example\n",
        );

        assert_eq!(
            hosts.get("primary.example"),
            Some(&vec!["192.0.2.1".parse().expect("IPv4 address")])
        );
        assert_eq!(
            hosts.get("alias.example"),
            Some(&vec![
                "192.0.2.1".parse().expect("IPv4 address"),
                "2001:db8::1".parse().expect("IPv6 address"),
            ])
        );
        assert!(!hosts.contains_key("ignored.example"));
    }

    #[tokio::test]
    async fn tailscale_registry_replacement_guard_matches_go_contract() {
        const NAME: &str = "phase4f5-registry-contract";
        let query = response(0x4f05, 30);
        assert!(query_tailscale(&query, NAME).await.is_err());

        let first =
            register_tailscale_dns_resolver(NAME, Arc::new(FixtureTailscaleResolver { marker: 1 }));
        assert_eq!(
            query_tailscale(&query, NAME)
                .await
                .expect("first resolver")
                .last(),
            Some(&1)
        );

        let replacement =
            register_tailscale_dns_resolver(NAME, Arc::new(FixtureTailscaleResolver { marker: 2 }));
        assert_eq!(
            query_tailscale(&query, NAME)
                .await
                .expect("replacement resolver")
                .last(),
            Some(&2)
        );

        drop(first);
        assert_eq!(
            query_tailscale(&query, NAME)
                .await
                .expect("old guard must preserve replacement")
                .last(),
            Some(&2)
        );

        drop(replacement);
        assert!(query_tailscale(&query, NAME).await.is_err());
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
