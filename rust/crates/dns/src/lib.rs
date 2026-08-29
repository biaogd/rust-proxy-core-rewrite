use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use rewrite_platform::SystemDnsTracker;
use thiserror::Error;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

mod cache;
mod enhancer;
mod server;
mod service;
#[cfg(test)]
mod tests;
mod transport;
mod wire;

pub use enhancer::system_host_addresses;
pub use server::serve;
pub use service::{
    DnsService, RestDnsResponse, RestQuestion, RestRecord, lookup_domain,
    lookup_domain_primary_ipv4, resolve_default_domain, resolve_direct_domain, resolve_domain,
    resolve_ech, resolve_proxy_domain, resolve_proxy_ech,
};

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
