use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::SystemTime;

use ipnet::IpNet;
use rewrite_model::{AuthUser, ShadowsocksPluginConfig};
use rewrite_rules::{ProviderBehavior, RematchSpec, RuleSet};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Global,
    Rule,
    Direct,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

// This mirrors an external configuration schema: every boolean is an
// independent Mihomo field, so combining them would distort the model.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct ConfigSpec {
    pub port: i64,
    pub socks_port: i64,
    pub redir_port: i64,
    pub tproxy_port: i64,
    pub mixed_port: i64,
    pub allow_lan: bool,
    pub bind_address: String,
    pub skip_auth_prefixes: Vec<IpNet>,
    pub lan_allowed_ips: Vec<IpNet>,
    pub lan_disallowed_ips: Vec<IpNet>,
    pub inbound_tfo: bool,
    pub inbound_mptcp: bool,
    pub mode: Mode,
    pub unified_delay: bool,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub geodata_mode: bool,
    pub geodata_loader: String,
    pub geosite_matcher: String,
    pub geo_auto_update: bool,
    pub geo_update_interval: i64,
    pub geox_url: GeoXUrls,
    pub interface_name: String,
    pub routing_mark: i64,
    pub tcp_concurrent: bool,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
    pub etag_support: bool,
    pub authentication: Vec<AuthUser>,
    pub external_controller: String,
    pub external_controller_tls: String,
    pub external_controller_unix: String,
    pub external_controller_pipe: String,
    pub external_controller_routing_mark: i64,
    pub external_ui: String,
    pub external_ui_url: String,
    pub external_ui_name: String,
    pub external_doh_server: String,
    pub secret: String,
    pub controller_cors: ControllerCors,
    pub profile: ProfileConfig,
    pub ntp: NtpConfig,
    pub trust_certificates: Vec<String>,
    pub controller_tls: ControllerTls,
    pub dns: Option<DnsConfig>,
    pub hosts: HostTable,
    pub raw_rules: Vec<String>,
    pub raw_sub_rules: BTreeMap<String, Vec<String>>,
    pub rematches: Vec<RematchSpec>,
    pub proxies: Vec<ProxyConfig>,
    pub proxy_providers: Vec<ProxyProviderConfig>,
    pub rule_providers: BTreeMap<String, RuleProviderConfig>,
    pub proxy_groups: Vec<ProxyGroupConfig>,
    pub rules: RuleSet,
    pub shadowsocks_listeners: Vec<ShadowsocksInboundConfig>,
    pub(crate) unsupported_keys: Vec<String>,
    pub(crate) source_path: Option<PathBuf>,
    pub(crate) home_directory: Option<PathBuf>,
}

// This is the normalized executable view of the same external schema; each
// boolean retains an independent observable configuration meaning.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct Config {
    pub port: i64,
    pub socks_port: i64,
    pub mixed_port: i64,
    pub allow_lan: bool,
    pub bind_address: String,
    pub skip_auth_prefixes: Vec<IpNet>,
    pub lan_allowed_ips: Vec<IpNet>,
    pub lan_disallowed_ips: Vec<IpNet>,
    pub inbound_tfo: bool,
    pub inbound_mptcp: bool,
    pub interface_name: String,
    pub routing_mark: i64,
    pub tcp_concurrent: bool,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
    pub mode: Mode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub geodata_mode: bool,
    pub geodata_loader: String,
    pub geosite_matcher: String,
    pub geo_auto_update: bool,
    pub geo_update_interval: i64,
    pub geox_url: GeoXUrls,
    pub etag_support: bool,
    pub authentication: Vec<AuthUser>,
    pub external_controller: String,
    pub external_controller_tls: String,
    pub external_controller_unix: String,
    pub external_controller_pipe: String,
    pub external_controller_routing_mark: i64,
    pub external_ui: String,
    pub external_ui_url: String,
    pub external_ui_name: String,
    pub external_doh_server: String,
    pub secret: String,
    pub controller_cors: ControllerCors,
    pub profile: ProfileConfig,
    pub ntp: NtpConfig,
    pub trust_certificates: Vec<String>,
    pub controller_tls: ControllerTls,
    pub dns: Option<DnsConfig>,
    pub hosts: HostTable,
    pub proxies: Vec<ProxyConfig>,
    pub proxy_providers: Vec<ProxyProviderConfig>,
    pub rule_providers: BTreeMap<String, RuleProviderConfig>,
    pub proxy_groups: Vec<ProxyGroupConfig>,
    pub rules: RuleSet,
    pub(crate) raw_rules: Vec<String>,
    pub(crate) raw_sub_rules: BTreeMap<String, Vec<String>>,
    pub(crate) rematches: Vec<RematchSpec>,
    pub shadowsocks_listeners: Vec<ShadowsocksInboundConfig>,
    pub(crate) source_path: Option<PathBuf>,
    pub(crate) home_directory: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyKind {
    Http,
    Socks5,
    Shadowsocks,
    Vmess,
    Vless,
    Direct,
    Reject,
    Dns,
    Rematch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileConfig {
    pub store_fake_ip: bool,
    pub store_selected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtpConfig {
    pub enable: bool,
    pub server: String,
    pub port: i64,
    pub interval: i64,
    pub dialer_proxy: String,
    pub write_to_system: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoXUrls {
    pub geo_ip: String,
    pub mmdb: String,
    pub asn: String,
    pub geo_site: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProxyConfig {
    pub name: String,
    pub kind: ProxyKind,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cipher: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub name_cert_verify: Option<String>,
    pub fingerprint: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub client_fingerprint: Option<String>,
    pub reality: Option<RealityProxyConfig>,
    pub udp: bool,
    pub udp_over_tcp: bool,
    pub udp_over_tcp_version: u8,
    pub shadowsocks_plugin: Option<ShadowsocksPluginConfig>,
    pub vmess: Option<VmessProxyConfig>,
    pub vless: Option<VlessProxyConfig>,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityProxyConfig {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub support_x25519mlkem768: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessFlow {
    XtlsRprxVision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessProxyConfig {
    pub uuid: [u8; 16],
    pub flow: Option<VlessFlow>,
    pub xudp: bool,
    pub packet_mode: VlessPacketMode,
    pub transport: VlessTransport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessPacketMode {
    Standard,
    PacketAddr,
    Xudp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessXHttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlessXHttpReuseOptions {
    pub max_concurrency_min: usize,
    pub max_concurrency_max: usize,
    pub max_connections_min: usize,
    pub max_connections_max: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlessTransport {
    Tcp,
    Http {
        method: String,
        paths: Vec<String>,
        headers: BTreeMap<String, Vec<String>>,
    },
    Http2 {
        hosts: Vec<String>,
        path: String,
    },
    WebSocket {
        path: String,
        headers: BTreeMap<String, String>,
    },
    Grpc {
        service_name: String,
        user_agent: String,
        ping_interval: i64,
        max_connections: i64,
        min_streams: i64,
        max_streams: i64,
    },
    XHttp {
        mode: VlessXHttpMode,
        host: String,
        path: String,
        headers: BTreeMap<String, String>,
        no_grpc_header: bool,
        padding_min: usize,
        padding_max: usize,
        max_each_post_min: usize,
        max_each_post_max: usize,
        reuse: Option<VlessXHttpReuseOptions>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessProxyConfig {
    pub uuid: [u8; 16],
    pub alter_id: i64,
    pub security: VmessSecurity,
    pub packet_mode: VmessPacketMode,
    pub transport: VmessTransport,
    pub global_padding: bool,
    pub authenticated_length: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VmessTransport {
    Tcp,
    Mkcp(VmessMkcpOptions),
    Mekya(VmessMekyaOptions),
    Http {
        method: String,
        paths: Vec<String>,
        headers: BTreeMap<String, Vec<String>>,
    },
    Http2 {
        hosts: Vec<String>,
        path: String,
    },
    Grpc {
        service_name: String,
        user_agent: String,
        ping_interval: i64,
        max_connections: i64,
        min_streams: i64,
        max_streams: i64,
    },
    WebSocket {
        path: String,
        headers: BTreeMap<String, String>,
        max_early_data: usize,
        early_data_header_name: Option<String>,
        http_upgrade: bool,
        http_upgrade_fast_open: bool,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VmessMkcpOptions {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub write_buffer: u32,
    pub read_buffer: u32,
    pub seed: String,
    pub header: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VmessMekyaOptions {
    pub url: String,
    pub h2_pool_size: i64,
    pub max_write_delay: i64,
    pub max_request_size: i64,
    pub polling_interval_initial: i64,
    pub max_write_size: i64,
    pub max_write_duration_ms: i64,
    pub max_simultaneous_write_connection: i64,
    pub packet_writing_buffer: i64,
    pub kcp: VmessMkcpOptions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmessPacketMode {
    Standard,
    PacketAddr,
    Xudp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmessSecurity {
    Auto,
    None,
    Aes128Cfb,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl ProxyConfig {
    #[must_use]
    pub fn http_credentials(&self) -> Option<(&str, &str)> {
        let username = self
            .username
            .as_deref()
            .filter(|username| !username.is_empty())?;
        let password = self
            .password
            .as_deref()
            .filter(|password| !password.is_empty())?;
        Some((username, password))
    }

    /// Mirrors the Go SOCKS5 adapter's credential activation rule: a nonempty
    /// username enables RFC 1929, while an absent password becomes empty.
    #[must_use]
    pub fn socks5_credentials(&self) -> Option<(&str, &str)> {
        let username = self
            .username
            .as_deref()
            .filter(|username| !username.is_empty())?;
        Some((username, self.password.as_deref().unwrap_or_default()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyGroupConfig {
    pub name: String,
    pub kind: ProxyGroupKind,
    pub proxies: Vec<String>,
    pub compatible_proxies: Vec<String>,
    pub providers: Vec<String>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub exclude_types: Vec<String>,
    pub empty_fallback: String,
    pub default_selected: Option<String>,
    pub test_url: String,
    pub expected_status: String,
    pub hidden: bool,
    pub icon: String,
    pub disable_udp: bool,
    pub tolerance: u16,
    pub health: GroupHealthConfig,
    pub load_balance_strategy: Option<LoadBalanceStrategy>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupHealthConfig {
    pub interval: u64,
    pub timeout: u64,
    pub lazy: bool,
    pub max_failed_times: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyGroupKind {
    Select,
    Fallback,
    UrlTest,
    LoadBalance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadBalanceStrategy {
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyProviderConfig {
    pub name: String,
    pub vehicle: ProxyProviderVehicle,
    pub path: PathBuf,
    pub url: Option<String>,
    pub interval: u64,
    pub headers: BTreeMap<String, Vec<String>>,
    pub size_limit: usize,
    pub etag: Option<String>,
    pub cache_modified: Option<SystemTime>,
    pub proxies: Vec<ProxyConfig>,
    pub health_check: ProviderHealthConfig,
    pub(crate) transform: ProxyProviderTransform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProviderVehicle {
    Inline,
    File,
    Http,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHealthConfig {
    pub enabled: bool,
    pub url: String,
    pub expected_status: String,
    pub interval: u64,
    pub timeout: u64,
    pub lazy: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProxyProviderTransform {
    pub(crate) filters: Vec<String>,
    pub(crate) exclude_filters: Vec<String>,
    pub(crate) exclude_types: Vec<String>,
    pub(crate) additional_prefix: String,
    pub(crate) additional_suffix: String,
    pub(crate) name_replacements: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleProviderConfig {
    pub name: String,
    pub behavior: ProviderBehavior,
    pub vehicle: RuleProviderVehicle,
    pub format: RuleProviderFormat,
    pub path: PathBuf,
    pub url: Option<String>,
    pub interval: u64,
    pub headers: BTreeMap<String, Vec<String>>,
    pub size_limit: usize,
    pub cache_modified: Option<SystemTime>,
    pub etag: Option<String>,
    pub payload: Vec<String>,
    pub(crate) domains: Vec<RuleSetDomain>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleProviderVehicle {
    Inline,
    File,
    Http,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleProviderFormat {
    Yaml,
    Text,
    Mrs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerCors {
    pub allow_origins: Vec<String>,
    pub allow_private_network: bool,
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ControllerTls {
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsTransport {
    Udp,
    Tcp,
    TlsInsecureNoReuse,
    TlsInsecureReuse,
    TlsVerifiedNoReuse,
    TlsVerifiedReuse,
    HttpReuse,
    HttpsVerifiedReuse,
    QuicVerifiedReuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DohProtocol {
    Http,
    PreferHttp3,
    Http3Only,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsMode {
    RedirHost,
    FakeIp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsCacheAlgorithm {
    Lru,
    Arc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
    Rule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeIpRuleAction {
    FakeIp,
    RealIp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FakeIpRuleMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(String),
    DomainWildcard(String),
    Geosite {
        name: String,
        domains: Vec<GeositeDomain>,
    },
    RuleSet {
        name: String,
        domains: Vec<RuleSetDomain>,
    },
    Match,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeIpRule {
    pub matcher: FakeIpRuleMatcher,
    pub action: FakeIpRuleAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeIpConfig {
    pub ipv4_range: Option<IpNet>,
    pub ipv6_range: Option<IpNet>,
    pub filter: Vec<DnsPolicyMatcher>,
    pub rules: Vec<FakeIpRule>,
    pub filter_mode: FakeIpFilterMode,
    pub ttl: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub transport: DnsTransport,
    pub main_kind: DnsMainKind,
    pub classic_upstreams: Vec<DnsClassicUpstream>,
    pub main_resolvers: Vec<DnsResolverClient>,
    pub default_resolvers: Vec<DnsResolverClient>,
    pub proxy_resolvers: Vec<DnsResolverClient>,
    pub ipv6: bool,
    pub ipv6_timeout: std::time::Duration,
    pub cache_algorithm: DnsCacheAlgorithm,
    pub cache_max_size: usize,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub mode: DnsMode,
    pub fake_ip: Option<FakeIpConfig>,
    pub policies: Vec<DnsPolicy>,
    pub proxy_policies: Vec<DnsPolicy>,
    pub fallback: Option<DnsFallbackConfig>,
    pub direct: Option<DnsDirectConfig>,
    pub tls: Option<DnsTlsConfig>,
    pub query_options: DnsQueryOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsMainKind {
    Configured,
    System,
    Dhcp(String),
    Rcode(SyntheticRcode),
    Tailscale(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SyntheticRcode {
    Success = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl SyntheticRcode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "success" => Some(Self::Success),
            "format_error" => Some(Self::FormatError),
            "server_failure" => Some(Self::ServerFailure),
            "name_error" => Some(Self::NameError),
            "not_implemented" => Some(Self::NotImplemented),
            "refused" => Some(Self::Refused),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsQueryOptions {
    pub ecs: Option<EcsConfig>,
    pub disabled_types: Vec<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcsConfig {
    pub address: IpAddr,
    pub prefix: u8,
    pub override_existing: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsTlsConfig {
    pub server_name: String,
    pub tls_server_name: String,
    pub skip_certificate_verification: bool,
    pub trust_certificates: Vec<String>,
    pub doh_path: Option<String>,
    pub doh_basic_credentials: Option<String>,
    pub endpoint_host: Option<String>,
    pub bootstrap: Option<DnsUpstream>,
    pub doh_protocol: DohProtocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsUpstream {
    pub address: SocketAddr,
    pub transport: DnsTransport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsClassicUpstream {
    pub endpoint: DnsClassicEndpoint,
    pub transport: DnsTransport,
    pub query_options: DnsQueryOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsResolverClient {
    Classic(DnsClassicUpstream),
    Network {
        upstream: DnsUpstream,
        tls: Option<DnsTlsConfig>,
        query_options: DnsQueryOptions,
    },
    System,
    Dhcp(String),
    Rcode(SyntheticRcode),
    Tailscale(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsClassicEndpoint {
    Socket(SocketAddr),
    Domain {
        host: String,
        port: u16,
        bootstrap: DnsUpstream,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsFallbackConfig {
    pub resolvers: Vec<DnsResolverClient>,
    pub domains: Vec<String>,
    pub geosites: Vec<DnsPolicyMatcher>,
    pub ipcidr: Vec<IpNet>,
    pub geoip: Option<DnsGeoIpFilter>,
    pub lazy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsGeoIpFilter {
    pub code: String,
    pub networks: Vec<IpNet>,
    pub inverted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsDirectConfig {
    pub resolvers: Vec<DnsResolverClient>,
    pub follow_policy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsPolicy {
    pub matcher: DnsPolicyMatcher,
    pub resolvers: Vec<DnsResolverClient>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsPolicyMatcher {
    Domain(String),
    Geosite {
        name: String,
        domains: Vec<GeositeDomain>,
    },
    RuleSet {
        name: String,
        domains: Vec<RuleSetDomain>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeositeDomainKind {
    Plain,
    Regex,
    Domain,
    Full,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeositeDomain {
    pub kind: GeositeDomainKind,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetDomainKind {
    Trie,
    Keyword,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSetDomain {
    pub kind: RuleSetDomainKind,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEntry {
    Addresses(Vec<IpAddr>),
    Domain(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostTable {
    pub(crate) entries: BTreeMap<String, HostEntry>,
}

impl HostTable {
    #[must_use]
    pub fn get(&self, pattern: &str) -> Option<&HostEntry> {
        self.entries.get(pattern)
    }

    #[must_use]
    pub fn search(&self, name: &str) -> Option<&HostEntry> {
        self.entries
            .iter()
            .filter_map(|(pattern, entry)| {
                host_pattern_rank(pattern, name).map(|rank| (rank, entry))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(_, entry)| entry)
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<HostEntry> {
        let mut current = name.to_owned();
        let mut followed = false;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current.to_lowercase()) {
                return None;
            }
            match self.search(&current) {
                Some(HostEntry::Addresses(addresses)) => {
                    return Some(HostEntry::Addresses(addresses.clone()));
                }
                Some(HostEntry::Domain(target)) => {
                    current.clone_from(target);
                    followed = true;
                }
                None if followed => return Some(HostEntry::Domain(current)),
                None => return None,
            }
        }
    }

    pub(crate) fn insert(&mut self, pattern: String, entry: HostEntry) {
        self.entries.insert(pattern, entry);
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }
}

// Keep independent boolean fields in the normalized oracle observation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NormalizedConfig {
    pub port: i64,
    pub socks_port: i64,
    pub redir_port: i64,
    pub tproxy_port: i64,
    pub mixed_port: i64,
    pub allow_lan: bool,
    pub bind_address: String,
    pub mode: Mode,
    pub unified_delay: bool,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub interface_name: String,
    pub routing_mark: i64,
    pub tcp_concurrent: bool,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
    pub etag_support: bool,
    pub rules: Vec<String>,
    pub sub_rules: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksSimpleObfsConfig {
    pub mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowTlsUserConfig {
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowTlsHandshakeConfig {
    pub dest: String,
    pub proxy: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksShadowTlsConfig {
    pub version: u8,
    pub password: Option<String>,
    pub users: Vec<ShadowTlsUserConfig>,
    pub handshake: ShadowTlsHandshakeConfig,
    pub strict_mode: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowsocksInboundConfig {
    pub name: String,
    pub cipher: String,
    pub password: String,
    pub listen: SocketAddr,
    pub udp: bool,
    pub simple_obfs: Option<ShadowsocksSimpleObfsConfig>,
    pub shadow_tls: Option<ShadowsocksShadowTlsConfig>,
}

impl ShadowsocksInboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "name={}|cipher={}|password={}|listen={}|udp={}|obfs={:?}|shadow-tls={:?}",
            self.name,
            self.cipher,
            self.password,
            self.listen,
            self.udp,
            self.simple_obfs,
            self.shadow_tls
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ListenerKind {
    Http,
    Socks,
    Mixed,
    Shadowsocks,
}

fn host_pattern_rank(pattern: &str, name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.').to_lowercase();
    let name_labels: Vec<_> = name.split('.').collect();
    if name_labels.iter().any(|label| label.is_empty()) {
        return None;
    }
    let (suffix, include_root) = if let Some(suffix) = pattern.strip_prefix("+.") {
        (Some(suffix), true)
    } else if let Some(suffix) = pattern.strip_prefix('.') {
        (Some(suffix), false)
    } else {
        (None, false)
    };
    if let Some(suffix) = suffix {
        let suffix_labels: Vec<_> = suffix.split('.').collect();
        if name_labels.len() < suffix_labels.len()
            || (!include_root && name_labels.len() == suffix_labels.len())
            || name_labels[name_labels.len() - suffix_labels.len()..] != suffix_labels
        {
            return None;
        }
        let mut rank = vec![0; name_labels.len()];
        rank[..suffix_labels.len()].fill(2);
        return Some(rank);
    }
    let pattern_labels: Vec<_> = pattern.split('.').collect();
    if pattern_labels.len() != name_labels.len() {
        return None;
    }
    let mut rank = Vec::with_capacity(name_labels.len());
    for (pattern_label, name_label) in pattern_labels.iter().zip(&name_labels).rev() {
        if pattern_label == name_label {
            rank.push(2);
        } else if *pattern_label == "*" {
            rank.push(1);
        } else {
            return None;
        }
    }
    Some(rank)
}
