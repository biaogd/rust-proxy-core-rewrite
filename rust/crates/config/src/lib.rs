use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use md5::{Digest, Md5};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use prost::Message;
use regex::Regex;
use rewrite_model::AuthUser;
use rewrite_rules::{RematchSpec, RuleError, RuleSet};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};
use thiserror::Error;
use url::Url;

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
    pub mode: Mode,
    pub unified_delay: bool,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub geodata_mode: bool,
    pub interface_name: String,
    pub routing_mark: i64,
    pub tcp_concurrent: bool,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
    pub etag_support: bool,
    pub authentication: Vec<AuthUser>,
    pub external_controller: String,
    pub external_doh_server: String,
    pub secret: String,
    pub controller_cors: ControllerCors,
    pub profile: ProfileConfig,
    pub dns: Option<DnsConfig>,
    pub hosts: HostTable,
    pub raw_rules: Vec<String>,
    pub raw_sub_rules: BTreeMap<String, Vec<String>>,
    pub rematches: Vec<RematchSpec>,
    pub proxies: Vec<ProxyConfig>,
    pub proxy_providers: Vec<ProxyProviderConfig>,
    pub proxy_groups: Vec<ProxyGroupConfig>,
    pub rules: RuleSet,
    unsupported_keys: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub port: i64,
    pub socks_port: i64,
    pub mixed_port: i64,
    pub mode: Mode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub geodata_mode: bool,
    pub etag_support: bool,
    pub authentication: Vec<AuthUser>,
    pub external_controller: String,
    pub external_doh_server: String,
    pub secret: String,
    pub controller_cors: ControllerCors,
    pub profile: ProfileConfig,
    pub dns: Option<DnsConfig>,
    pub hosts: HostTable,
    pub proxies: Vec<ProxyConfig>,
    pub proxy_providers: Vec<ProxyProviderConfig>,
    pub proxy_groups: Vec<ProxyGroupConfig>,
    pub rules: RuleSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyKind {
    Http,
    Socks5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileConfig {
    pub store_fake_ip: bool,
    pub store_selected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyConfig {
    pub name: String,
    pub kind: ProxyKind,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
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
    pub proxies: Vec<ProxyConfig>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProviderVehicle {
    File,
    Http,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerCors {
    pub allow_origins: Vec<String>,
    pub allow_private_network: bool,
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
    fn parse(value: &str) -> Option<Self> {
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
    entries: BTreeMap<String, HostEntry>,
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

    fn insert(&mut self, pattern: String, entry: HostEntry) {
        self.entries.insert(pattern, entry);
    }

    fn keys(&self) -> impl Iterator<Item = &String> {
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

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawConfig {
    port: Option<i64>,
    socks_port: Option<i64>,
    redir_port: Option<i64>,
    tproxy_port: Option<i64>,
    mixed_port: Option<i64>,
    allow_lan: Option<bool>,
    bind_address: Option<String>,
    mode: Option<String>,
    unified_delay: Option<bool>,
    log_level: Option<String>,
    ipv6: Option<bool>,
    geodata_mode: Option<bool>,
    interface_name: Option<String>,
    routing_mark: Option<i64>,
    tcp_concurrent: Option<bool>,
    keep_alive_idle: Option<i64>,
    keep_alive_interval: Option<i64>,
    disable_keep_alive: Option<bool>,
    etag_support: Option<bool>,
    authentication: Option<Vec<String>>,
    external_controller: Option<String>,
    external_doh_server: Option<String>,
    secret: Option<String>,
    external_controller_cors: Option<RawControllerCors>,
    profile: Option<RawProfile>,
    tls: Option<RawTls>,
    dns: Option<RawDns>,
    hosts: Option<BTreeMap<String, RawHostValue>>,
    rules: Option<Vec<String>>,
    sub_rules: Option<BTreeMap<String, Vec<String>>>,
    proxies: Option<Vec<RawProxy>>,
    proxy_providers: Option<BTreeMap<String, RawProxyProvider>>,
    proxy_groups: Option<Vec<RawProxyGroup>>,
    rule_providers: Option<BTreeMap<String, RawRuleProvider>>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawControllerCors {
    allow_origins: Option<Vec<String>>,
    allow_private_network: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawTls {
    custom_certifactes: Option<Vec<String>>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawHostValue {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawDns {
    enable: Option<bool>,
    listen: Option<String>,
    ipv6: Option<bool>,
    ipv6_timeout: Option<i64>,
    cache_algorithm: Option<String>,
    cache_max_size: Option<i64>,
    prefer_h3: Option<bool>,
    use_hosts: Option<bool>,
    use_system_hosts: Option<bool>,
    enhanced_mode: Option<String>,
    fake_ip_range: Option<String>,
    fake_ip_range6: Option<String>,
    fake_ip_filter: Option<Vec<String>>,
    fake_ip_filter_mode: Option<String>,
    fake_ip_ttl: Option<i64>,
    default_nameserver: Option<Vec<String>>,
    nameserver: Option<Vec<String>>,
    nameserver_policy: Option<Mapping>,
    fallback: Option<Vec<String>>,
    fallback_filter: Option<RawFallbackFilter>,
    fallback_lazy_query: Option<bool>,
    direct_nameserver: Option<Vec<String>>,
    direct_nameserver_follow_policy: Option<bool>,
    proxy_server_nameserver: Option<Vec<String>>,
    proxy_server_nameserver_policy: Option<Mapping>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawFallbackFilter {
    geoip: Option<bool>,
    geoip_code: Option<String>,
    ipcidr: Option<Vec<String>>,
    domain: Option<Vec<String>>,
    geosite: Option<Vec<String>>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
struct RawRuleProvider {
    #[serde(rename = "type")]
    kind: Option<String>,
    behavior: Option<String>,
    payload: Option<Vec<String>>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawProfile {
    store_fake_ip: Option<bool>,
    store_selected: Option<bool>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawProxy {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    target_rematch_name: Option<String>,
    target_sub_rule: Option<String>,
    server: Option<String>,
    port: Option<i64>,
    username: Option<String>,
    password: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawProxyGroup {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    strategy: Option<String>,
    proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    providers: Option<Vec<String>>,
    filter: Option<String>,
    exclude_filter: Option<String>,
    exclude_type: Option<String>,
    include_all: Option<bool>,
    include_all_proxies: Option<bool>,
    include_all_providers: Option<bool>,
    empty_fallback: Option<String>,
    default_selected: Option<String>,
    url: Option<String>,
    expected_status: Option<String>,
    hidden: Option<bool>,
    icon: Option<String>,
    disable_udp: Option<bool>,
    tolerance: Option<u16>,
    interval: Option<u64>,
    timeout: Option<u64>,
    lazy: Option<bool>,
    max_failed_times: Option<u64>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawProxyProvider {
    #[serde(rename = "type")]
    kind: Option<String>,
    path: Option<String>,
    url: Option<String>,
    interval: Option<u64>,
    header: Option<BTreeMap<String, Vec<String>>>,
    size_limit: Option<usize>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
struct RawProxyProviderFile {
    proxies: Option<Vec<RawProxy>>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration YAML error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("cannot read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid mode")]
    InvalidMode,
    #[error("invalid log-level")]
    InvalidLogLevel,
    #[error("rule error: {0}")]
    Rule(#[from] RuleError),
    #[error("unsupported configuration key for the current rewrite phase: {0}")]
    UnsupportedKey(String),
    #[error("unsupported Phase 2 proxy specification: {0}")]
    UnsupportedProxy(String),
    #[error("invalid mixed-port for listener: {0}")]
    InvalidRuntimePort(i64),
    #[error("invalid external-controller address: {0}")]
    InvalidControllerAddress(String),
    #[error("invalid Phase 4A DNS configuration: {0}")]
    InvalidDns(String),
    #[error("invalid Phase 4B hosts configuration: {0}")]
    InvalidHosts(String),
    #[error("configuration is parsed but not executable in the current rewrite runtime: {0}")]
    UnsupportedRuntime(String),
}

impl ConfigSpec {
    /// Parses the Phase 2 specification layer and overlays Go-compatible
    /// defaults for the declared general fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for malformed YAML, invalid enums, unsupported
    /// proxy specifications or invalid pure rules.
    pub fn from_yaml(source: &str) -> Result<Self, ConfigError> {
        Self::from_source(source, None, None, false)
    }

    /// Parses YAML with the process-level geodata-mode default selected by
    /// the CLI. An explicit YAML value still takes precedence.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_with_geodata_mode(
        source: &str,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        Self::from_source(source, None, None, geodata_mode)
    }

    /// Parses YAML with provider paths rooted at the supplied home directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_with_provider_directory(
        source: &str,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        Self::from_source(source, None, Some(provider_directory), geodata_mode)
    }

    /// Parses YAML while resolving relative resources from a configuration path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_at_path_with_geodata_mode(
        source: &str,
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        Self::from_source(source, path.parent(), path.parent(), geodata_mode)
    }

    /// Parses YAML with separate configuration-resource and provider-home directories.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_yaml`].
    pub fn from_yaml_at_path_with_provider_directory(
        source: &str,
        path: &Path,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        Self::from_source(
            source,
            path.parent(),
            Some(provider_directory),
            geodata_mode,
        )
    }

    fn from_source(
        source: &str,
        config_directory: Option<&Path>,
        provider_directory: Option<&Path>,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        let raw = serde_yaml_ng::from_str::<Option<RawConfig>>(source)?.unwrap_or_default();
        let mode = parse_mode(raw.mode.as_deref().unwrap_or("rule"))?;
        let log_level = parse_log_level(raw.log_level.as_deref().unwrap_or("info"))?;
        let raw_rules = raw.rules.unwrap_or_default();
        let raw_sub_rules = raw.sub_rules.unwrap_or_default();
        let (rematches, proxies) = parse_proxies(raw.proxies.unwrap_or_default())?;
        let proxy_providers = parse_proxy_providers(
            raw.proxy_providers.unwrap_or_default(),
            provider_directory,
            &proxies,
        )?;
        let proxy_groups = parse_proxy_groups(
            raw.proxy_groups.unwrap_or_default(),
            &proxies,
            &proxy_providers,
        )?;
        let proxy_targets = proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .chain(proxy_groups.iter().map(|group| group.name.clone()))
            .collect();
        let rules =
            RuleSet::parse_with_targets(&raw_rules, &raw_sub_rules, &rematches, &proxy_targets)?;
        let profile = parse_profile(raw.profile)?;
        let trust_certificates = parse_tls(raw.tls)?;
        let rule_providers = parse_rule_providers(raw.rule_providers.unwrap_or_default())?;
        let geodata_mode = raw.geodata_mode.unwrap_or(geodata_mode);
        let controller_cors = parse_controller_cors(raw.external_controller_cors);
        let dns = parse_dns(
            raw.dns,
            &trust_certificates,
            &rule_providers,
            config_directory,
            geodata_mode,
        )?;
        validate_rule_provider_usage(&rule_providers, dns.as_ref())?;

        Ok(Self {
            port: raw.port.unwrap_or(0),
            socks_port: raw.socks_port.unwrap_or(0),
            redir_port: raw.redir_port.unwrap_or(0),
            tproxy_port: raw.tproxy_port.unwrap_or(0),
            mixed_port: raw.mixed_port.unwrap_or(0),
            allow_lan: raw.allow_lan.unwrap_or(false),
            bind_address: raw.bind_address.unwrap_or_else(|| "*".to_owned()),
            mode,
            unified_delay: raw.unified_delay.unwrap_or(false),
            log_level,
            ipv6: raw.ipv6.unwrap_or(true),
            geodata_mode,
            interface_name: raw.interface_name.unwrap_or_default(),
            routing_mark: raw.routing_mark.unwrap_or(0),
            tcp_concurrent: raw.tcp_concurrent.unwrap_or(false),
            keep_alive_idle: raw.keep_alive_idle.unwrap_or(0),
            keep_alive_interval: raw.keep_alive_interval.unwrap_or(0),
            disable_keep_alive: raw.disable_keep_alive.unwrap_or(false),
            etag_support: raw.etag_support.unwrap_or(true),
            authentication: parse_authentication(raw.authentication.unwrap_or_default()),
            external_controller: raw.external_controller.unwrap_or_default(),
            external_doh_server: raw.external_doh_server.unwrap_or_default(),
            secret: raw.secret.unwrap_or_default(),
            controller_cors,
            profile,
            dns,
            hosts: parse_hosts(raw.hosts.unwrap_or_default())?,
            raw_rules,
            raw_sub_rules,
            rematches,
            proxies,
            proxy_providers,
            proxy_groups,
            rules,
            unsupported_keys: raw.extra.into_keys().collect(),
        })
    }

    /// Reads and parses a Phase 2 configuration specification.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file I/O or specification errors.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        Self::from_source(
            &std::fs::read_to_string(path)?,
            path.parent(),
            path.parent(),
            false,
        )
    }

    /// Reads YAML with the process-level geodata-mode default selected by the
    /// CLI. An explicit YAML value still takes precedence.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] under the same conditions as [`Self::from_path`].
    pub fn from_path_with_geodata_mode(
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        Self::from_source(
            &std::fs::read_to_string(path)?,
            path.parent(),
            path.parent(),
            geodata_mode,
        )
    }

    /// Ensures no top-level feature outside the declared Phase 2 parser surface
    /// was silently ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::UnsupportedKey`] for the first unsupported key.
    pub fn validate_declared_surface(&self) -> Result<(), ConfigError> {
        if let Some(key) = self.unsupported_keys.first() {
            Err(ConfigError::UnsupportedKey(key.clone()))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn normalized(&self) -> NormalizedConfig {
        NormalizedConfig {
            port: self.port,
            socks_port: self.socks_port,
            redir_port: self.redir_port,
            tproxy_port: self.tproxy_port,
            mixed_port: self.mixed_port,
            allow_lan: self.allow_lan,
            bind_address: self.bind_address.clone(),
            mode: self.mode,
            unified_delay: self.unified_delay,
            log_level: self.log_level,
            ipv6: self.ipv6,
            interface_name: self.interface_name.clone(),
            routing_mark: self.routing_mark,
            tcp_concurrent: self.tcp_concurrent,
            keep_alive_idle: self.keep_alive_idle,
            keep_alive_interval: self.keep_alive_interval,
            disable_keep_alive: self.disable_keep_alive,
            etag_support: self.etag_support,
            rules: self.raw_rules.clone(),
            sub_rules: self.raw_sub_rules.clone(),
        }
    }
}

impl TryFrom<ConfigSpec> for Config {
    type Error = ConfigError;

    fn try_from(spec: ConfigSpec) -> Result<Self, Self::Error> {
        spec.validate_declared_surface()?;
        let proxy_targets = spec
            .proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .chain(spec.proxy_groups.iter().map(|group| group.name.clone()))
            .collect();
        let unsupported = [
            (spec.redir_port != 0, "redir-port"),
            (spec.tproxy_port != 0, "tproxy-port"),
            (spec.allow_lan, "allow-lan"),
            (spec.bind_address != "*", "bind-address"),
            (spec.unified_delay, "unified-delay"),
            (!spec.interface_name.is_empty(), "interface-name"),
            (spec.routing_mark != 0, "routing-mark"),
            (spec.tcp_concurrent, "tcp-concurrent"),
            (spec.keep_alive_idle != 0, "keep-alive-idle"),
            (spec.keep_alive_interval != 0, "keep-alive-interval"),
            (spec.disable_keep_alive, "disable-keep-alive"),
            (
                !spec.rules.is_phase_three_tcp_with_targets(&proxy_targets),
                "rules outside Phase 3A TCP",
            ),
        ];
        if let Some((_, feature)) = unsupported.into_iter().find(|(active, _)| *active) {
            return Err(ConfigError::UnsupportedRuntime(feature.to_owned()));
        }

        Ok(Self {
            port: spec.port,
            socks_port: spec.socks_port,
            mixed_port: spec.mixed_port,
            mode: spec.mode,
            log_level: spec.log_level,
            ipv6: spec.ipv6,
            geodata_mode: spec.geodata_mode,
            etag_support: spec.etag_support,
            authentication: spec.authentication,
            external_controller: spec.external_controller,
            external_doh_server: spec.external_doh_server,
            secret: spec.secret,
            controller_cors: spec.controller_cors,
            profile: spec.profile,
            dns: spec.dns,
            hosts: spec.hosts,
            proxies: spec.proxies,
            proxy_providers: spec.proxy_providers,
            proxy_groups: spec.proxy_groups,
            rules: spec.rules,
        })
    }
}

impl Config {
    /// Parses a configuration and converts it to the current executable
    /// runtime subset.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification errors or any setting that the
    /// narrow runtime cannot apply.
    pub fn from_yaml(source: &str) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml(source)?.try_into()
    }

    /// Parses runtime YAML using the CLI geodata-mode default.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_with_geodata_mode(
        source: &str,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_with_geodata_mode(source, geodata_mode)?.try_into()
    }

    /// Parses runtime YAML with provider paths rooted at the supplied home directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_with_provider_directory(
        source: &str,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_with_provider_directory(source, provider_directory, geodata_mode)?
            .try_into()
    }

    /// Parses runtime YAML while resolving relative resources from a path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_at_path_with_geodata_mode(
        source: &str,
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_at_path_with_geodata_mode(source, path, geodata_mode)?.try_into()
    }

    /// Parses runtime YAML with provider paths rooted at the CLI home directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for specification or runtime-scope errors.
    pub fn from_yaml_at_path_with_provider_directory(
        source: &str,
        path: &Path,
        provider_directory: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_yaml_at_path_with_provider_directory(
            source,
            path,
            provider_directory,
            geodata_mode,
        )?
        .try_into()
    }

    /// Reads, parses and converts a configuration for the current runtime.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file, specification or runtime-scope errors.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        ConfigSpec::from_path(path)?.try_into()
    }

    /// Reads runtime YAML using the CLI geodata-mode default.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file, specification or runtime-scope errors.
    pub fn from_path_with_geodata_mode(
        path: &Path,
        geodata_mode: bool,
    ) -> Result<Self, ConfigError> {
        ConfigSpec::from_path_with_geodata_mode(path, geodata_mode)?.try_into()
    }

    /// Re-reads one configured local proxy-provider and rebuilds dependent
    /// selector membership without changing the active value on failure.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for missing providers, file/YAML failures,
    /// unsupported proxy records or duplicate names.
    pub fn reload_proxy_provider(&self, name: &str) -> Result<Self, ConfigError> {
        let index = self
            .proxy_providers
            .iter()
            .position(|provider| provider.name == name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
        let path = self.proxy_providers[index].path.clone();
        let proxies = load_proxy_provider_file(name, &path)?;
        self.replace_proxy_provider(index, proxies)
    }

    /// Parses downloaded provider YAML and rebuilds every dependent group.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] without changing this generation when the
    /// payload is invalid or introduces duplicate proxy names.
    pub fn replace_proxy_provider_source(
        &self,
        name: &str,
        source: &str,
    ) -> Result<Self, ConfigError> {
        let index = self
            .proxy_providers
            .iter()
            .position(|provider| provider.name == name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
        let proxies = parse_proxy_provider_source(name, source)?;
        self.replace_proxy_provider(index, proxies)
    }

    fn replace_proxy_provider(
        &self,
        index: usize,
        proxies: Vec<ProxyConfig>,
    ) -> Result<Self, ConfigError> {
        let mut next = self.clone();
        let name = next.proxy_providers[index].name.clone();
        let mut occupied: BTreeSet<_> = next
            .proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .chain(
                next.proxy_providers
                    .iter()
                    .enumerate()
                    .filter(|(candidate, _)| *candidate != index)
                    .flat_map(|(_, provider)| {
                        provider.proxies.iter().map(|proxy| proxy.name.clone())
                    }),
            )
            .collect();
        if proxies
            .iter()
            .any(|proxy| !occupied.insert(proxy.name.clone()))
        {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        next.proxy_providers[index].proxies = proxies;
        let providers = next.proxy_providers.clone();
        let group_types: BTreeMap<_, _> = next
            .proxy_groups
            .iter()
            .map(|group| {
                let kind = match group.kind {
                    ProxyGroupKind::Select => "Selector",
                    ProxyGroupKind::Fallback => "Fallback",
                    ProxyGroupKind::UrlTest => "URLTest",
                    ProxyGroupKind::LoadBalance => "LoadBalance",
                };
                (group.name.clone(), kind.to_owned())
            })
            .collect();
        let proxy_types = proxy_member_types(&next.proxies, &providers, &group_types);
        for group in &mut next.proxy_groups {
            group.proxies = expand_proxy_group(group, &providers, &proxy_types)?;
        }
        Ok(next)
    }

    /// Converts the parsed integer into a bindable runtime port.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidRuntimePort`] for zero or values outside
    /// the unsigned 16-bit port range.
    pub fn listener_port(&self) -> Result<u16, ConfigError> {
        u16::try_from(self.mixed_port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or(ConfigError::InvalidRuntimePort(self.mixed_port))
    }

    /// Returns every configured Phase 3A TCP listener after validating ports.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidRuntimePort`] for a nonzero port outside
    /// the unsigned 16-bit range or when no local listener is configured.
    pub fn listener_ports(&self) -> Result<Vec<(ListenerKind, u16)>, ConfigError> {
        let mut listeners = Vec::new();
        for (kind, value) in [
            (ListenerKind::Http, self.port),
            (ListenerKind::Socks, self.socks_port),
            (ListenerKind::Mixed, self.mixed_port),
        ] {
            if value == 0 {
                continue;
            }
            let port = u16::try_from(value)
                .ok()
                .filter(|port| *port != 0)
                .ok_or(ConfigError::InvalidRuntimePort(value))?;
            listeners.push((kind, port));
        }
        if listeners.is_empty() && self.dns.is_none() {
            return Err(ConfigError::InvalidRuntimePort(0));
        }
        Ok(listeners)
    }

    /// Parses the optional Phase 3B TCP controller address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidControllerAddress`] when the configured
    /// address is not an explicit socket address.
    pub fn controller_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        if self.external_controller.is_empty() {
            return Ok(None);
        }
        self.external_controller
            .parse()
            .map(Some)
            .map_err(|_| ConfigError::InvalidControllerAddress(self.external_controller.clone()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ListenerKind {
    Http,
    Socks,
    Mixed,
}

fn parse_mode(value: &str) -> Result<Mode, ConfigError> {
    match value.to_lowercase().as_str() {
        "global" => Ok(Mode::Global),
        "rule" => Ok(Mode::Rule),
        "direct" => Ok(Mode::Direct),
        _ => Err(ConfigError::InvalidMode),
    }
}

fn parse_log_level(value: &str) -> Result<LogLevel, ConfigError> {
    match value.to_lowercase().as_str() {
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warning" => Ok(LogLevel::Warning),
        "error" => Ok(LogLevel::Error),
        "silent" => Ok(LogLevel::Silent),
        _ => Err(ConfigError::InvalidLogLevel),
    }
}

fn parse_authentication(records: Vec<String>) -> Vec<AuthUser> {
    records
        .into_iter()
        .filter_map(|record| {
            let (username, password) = record.split_once(':')?;
            Some(AuthUser {
                username: username.to_owned(),
                password: password.to_owned(),
            })
        })
        .collect()
}

fn parse_controller_cors(raw: Option<RawControllerCors>) -> ControllerCors {
    let raw = raw.unwrap_or_default();
    ControllerCors {
        allow_origins: raw.allow_origins.unwrap_or_else(|| vec!["*".to_owned()]),
        allow_private_network: raw.allow_private_network.unwrap_or(true),
    }
}

fn parse_profile(raw: Option<RawProfile>) -> Result<ProfileConfig, ConfigError> {
    let Some(raw) = raw else {
        return Ok(ProfileConfig {
            store_fake_ip: false,
            store_selected: true,
        });
    };
    if let Some(key) = raw.extra.into_keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("profile.{key}")));
    }
    Ok(ProfileConfig {
        store_fake_ip: raw.store_fake_ip.unwrap_or(false),
        store_selected: raw.store_selected.unwrap_or(true),
    })
}

fn parse_tls(raw: Option<RawTls>) -> Result<Vec<String>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if let Some(key) = raw.extra.into_keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("tls.{key}")));
    }
    let certificates = raw.custom_certifactes.unwrap_or_default();
    if certificates
        .iter()
        .any(|certificate| !certificate.contains("-----BEGIN CERTIFICATE-----"))
    {
        return Err(ConfigError::UnsupportedRuntime(
            "Phase 4E accepts only inline tls.custom-certifactes PEM roots".to_owned(),
        ));
    }
    Ok(certificates)
}

fn parse_dns(
    raw: Option<RawDns>,
    trust_certificates: &[String],
    rule_providers: &BTreeMap<String, ParsedRuleProvider>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleProviderBehavior {
    Domain,
    Classical,
    IpCidr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRuleProvider {
    behavior: RuleProviderBehavior,
    domains: Vec<RuleSetDomain>,
}

fn parse_rule_providers(
    raw: BTreeMap<String, RawRuleProvider>,
) -> Result<BTreeMap<String, ParsedRuleProvider>, ConfigError> {
    raw.into_iter()
        .map(|(name, provider)| {
            if provider.kind.as_deref() != Some("inline") {
                return Err(ConfigError::InvalidDns(format!(
                    "Phase 4F8 rule provider {name} must use type inline"
                )));
            }
            if let Some(key) = provider.extra.keys().next() {
                return Err(ConfigError::InvalidDns(format!(
                    "unsupported Phase 4F8 rule provider field {name}.{key}"
                )));
            }
            let behavior = match provider.behavior.as_deref() {
                Some("domain") => RuleProviderBehavior::Domain,
                Some("classical") => RuleProviderBehavior::Classical,
                Some("ipcidr") => RuleProviderBehavior::IpCidr,
                _ => {
                    return Err(ConfigError::InvalidDns(format!(
                        "Phase 4F8 rule provider {name} has unsupported behavior"
                    )));
                }
            };
            let domains = provider
                .payload
                .unwrap_or_default()
                .into_iter()
                .filter_map(|entry| parse_rule_provider_domain(behavior, &entry).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            Ok((name, ParsedRuleProvider { behavior, domains }))
        })
        .collect()
}

fn validate_rule_provider_usage(
    providers: &BTreeMap<String, ParsedRuleProvider>,
    dns: Option<&DnsConfig>,
) -> Result<(), ConfigError> {
    let mut used = dns
        .into_iter()
        .flat_map(|dns| dns.policies.iter().chain(&dns.proxy_policies))
        .filter_map(|policy| match &policy.matcher {
            DnsPolicyMatcher::RuleSet { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if let Some(fake) = dns.and_then(|dns| dns.fake_ip.as_ref()) {
        for matcher in &fake.filter {
            if let DnsPolicyMatcher::RuleSet { name, .. } = matcher {
                used.insert(name);
            }
        }
        for rule in &fake.rules {
            if let FakeIpRuleMatcher::RuleSet { name, .. } = &rule.matcher {
                used.insert(name);
            }
        }
    }
    if let Some(name) = providers.keys().find(|name| !used.contains(name.as_str())) {
        return Err(ConfigError::UnsupportedKey(format!(
            "rule-providers.{name} outside DNS policy"
        )));
    }
    Ok(())
}

fn parse_rule_provider_domain(
    behavior: RuleProviderBehavior,
    entry: &str,
) -> Result<Option<RuleSetDomain>, ConfigError> {
    match behavior {
        RuleProviderBehavior::Domain => Ok(Some(RuleSetDomain {
            kind: RuleSetDomainKind::Trie,
            value: normalize_policy_pattern(entry)?,
        })),
        RuleProviderBehavior::IpCidr => Ok(None),
        RuleProviderBehavior::Classical => {
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
    rule_providers: &BTreeMap<String, ParsedRuleProvider>,
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
    rule_providers: &BTreeMap<String, ParsedRuleProvider>,
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
                if provider.behavior == RuleProviderBehavior::IpCidr {
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
struct GeoSiteListWire {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<GeoSiteWire>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteWire {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domains: Vec<GeoSiteDomainWire>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteDomainWire {
    #[prost(enumeration = "GeoSiteDomainTypeWire", tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpListWire {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<GeoIpWire>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpWire {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    networks: Vec<GeoIpCidrWire>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpCidrWire {
    #[prost(bytes = "vec", tag = "1")]
    address: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
enum GeoSiteDomainTypeWire {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
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
    rule_providers: &BTreeMap<String, ParsedRuleProvider>,
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
    providers: &BTreeMap<String, ParsedRuleProvider>,
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
    providers: &BTreeMap<String, ParsedRuleProvider>,
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
    providers: &BTreeMap<String, ParsedRuleProvider>,
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
            if provider.behavior == RuleProviderBehavior::IpCidr {
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

fn parse_hosts(raw: BTreeMap<String, RawHostValue>) -> Result<HostTable, ConfigError> {
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

fn parse_proxies(
    proxies: Vec<RawProxy>,
) -> Result<(Vec<RematchSpec>, Vec<ProxyConfig>), ConfigError> {
    let mut rematches = Vec::new();
    let mut outbounds = Vec::new();
    let mut names = BTreeSet::new();
    for proxy in proxies {
        let name = proxy
            .name
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ConfigError::UnsupportedProxy("missing name".to_owned()))?;
        if !names.insert(name.clone())
            || matches!(
                name.as_str(),
                "DIRECT"
                    | "REJECT"
                    | "REJECT-DROP"
                    | "COMPATIBLE"
                    | "PASS"
                    | "PASS-RULE"
                    | "GLOBAL"
            )
        {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        match proxy.kind.as_deref() {
            Some("rematch") => {
                if proxy.server.is_some()
                    || proxy.port.is_some()
                    || proxy.username.is_some()
                    || proxy.password.is_some()
                    || !proxy.extra.is_empty()
                {
                    return Err(ConfigError::UnsupportedProxy(name));
                }
                rematches.push(RematchSpec {
                    name,
                    target_rematch_name: proxy.target_rematch_name,
                    target_sub_rule: proxy.target_sub_rule,
                });
            }
            Some(kind @ ("http" | "socks5")) => {
                if proxy.target_rematch_name.is_some()
                    || proxy.target_sub_rule.is_some()
                    || proxy.username.is_some() != proxy.password.is_some()
                    || !proxy.extra.is_empty()
                {
                    return Err(ConfigError::UnsupportedProxy(name));
                }
                let server = proxy
                    .server
                    .filter(|server| !server.is_empty())
                    .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                let port = proxy
                    .port
                    .and_then(|port| u16::try_from(port).ok())
                    .filter(|port| *port != 0)
                    .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                outbounds.push(ProxyConfig {
                    name,
                    kind: if kind == "http" {
                        ProxyKind::Http
                    } else {
                        ProxyKind::Socks5
                    },
                    server,
                    port,
                    username: proxy.username,
                    password: proxy.password,
                });
            }
            _ => return Err(ConfigError::UnsupportedProxy(name)),
        }
    }
    Ok((rematches, outbounds))
}

fn parse_proxy_groups(
    groups: Vec<RawProxyGroup>,
    proxies: &[ProxyConfig],
    providers: &[ProxyProviderConfig],
) -> Result<Vec<ProxyGroupConfig>, ConfigError> {
    let mut proxy_names: BTreeSet<_> = proxies
        .iter()
        .chain(
            providers
                .iter()
                .flat_map(|provider| provider.proxies.iter()),
        )
        .map(|proxy| proxy.name.clone())
        .collect();
    let top_level_names: BTreeSet<_> = proxies.iter().map(|proxy| proxy.name.clone()).collect();
    let mut all_proxies: Vec<_> = proxies.iter().map(|proxy| proxy.name.clone()).collect();
    all_proxies.sort();
    let all_providers: Vec<_> = providers
        .iter()
        .map(|provider| provider.name.clone())
        .collect();
    let mut group_names = BTreeSet::new();
    for group in &groups {
        let name = group
            .name
            .as_deref()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ConfigError::UnsupportedProxy("missing group name".to_owned()))?;
        if !matches!(
            group.kind.as_deref(),
            Some("select" | "fallback" | "url-test" | "load-balance")
        ) || !group.extra.is_empty()
            || !group_names.insert(name.to_owned())
            || proxy_names.contains(name)
            || is_reserved_proxy_name(name)
        {
            return Err(ConfigError::UnsupportedProxy(name.to_owned()));
        }
    }
    validate_proxy_group_cycles(&groups, &group_names)?;
    let group_types: BTreeMap<_, _> = groups
        .iter()
        .filter_map(|group| {
            let name = group.name.as_ref()?;
            let kind = match group.kind.as_deref()? {
                "select" => "Selector",
                "fallback" => "Fallback",
                "url-test" => "URLTest",
                "load-balance" => "LoadBalance",
                _ => return None,
            };
            Some((name.clone(), kind.to_owned()))
        })
        .collect();
    proxy_names.extend(group_names.iter().cloned());
    let proxy_types = proxy_member_types(proxies, providers, &group_types);
    let catalog = ProxyGroupCatalog {
        proxy_names: &proxy_names,
        top_level_names: &top_level_names,
        all_proxies: &all_proxies,
        all_providers: &all_providers,
        providers,
        proxy_types: &proxy_types,
    };

    let mut parsed = Vec::new();
    for group in groups {
        let name = group
            .name
            .as_ref()
            .filter(|name| !name.is_empty())
            .cloned()
            .ok_or_else(|| ConfigError::UnsupportedProxy("missing group name".to_owned()))?;
        parsed.push(parse_proxy_group(group, name, &catalog)?);
    }
    Ok(parsed)
}

fn validate_proxy_group_cycles(
    groups: &[RawProxyGroup],
    group_names: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    let mapping: BTreeMap<_, _> = groups
        .iter()
        .filter_map(|group| group.name.as_deref().map(|name| (name, group)))
        .collect();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for name in group_names {
        visit_proxy_group(name, &mapping, group_names, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_proxy_group<'a>(
    name: &'a str,
    groups: &BTreeMap<&'a str, &'a RawProxyGroup>,
    group_names: &BTreeSet<String>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), ConfigError> {
    if visited.contains(name) {
        return Ok(());
    }
    if !visiting.insert(name) {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let group = groups
        .get(name)
        .ok_or_else(|| ConfigError::UnsupportedProxy(name.to_owned()))?;
    for dependency in group.proxies.iter().flatten() {
        if group_names.contains(dependency.as_str()) {
            visit_proxy_group(dependency, groups, group_names, visiting, visited)?;
        }
    }
    visiting.remove(name);
    visited.insert(name);
    Ok(())
}

fn is_reserved_proxy_name(name: &str) -> bool {
    matches!(
        name,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS" | "PASS-RULE" | "GLOBAL"
    )
}

struct ProxyGroupCatalog<'a> {
    proxy_names: &'a BTreeSet<String>,
    top_level_names: &'a BTreeSet<String>,
    all_proxies: &'a [String],
    all_providers: &'a [String],
    providers: &'a [ProxyProviderConfig],
    proxy_types: &'a BTreeMap<String, String>,
}

fn parse_proxy_group(
    group: RawProxyGroup,
    name: String,
    catalog: &ProxyGroupCatalog<'_>,
) -> Result<ProxyGroupConfig, ConfigError> {
    let kind = parse_proxy_group_kind(group.kind.as_deref(), &name)?;
    let load_balance_strategy =
        parse_load_balance_strategy(kind, group.strategy.as_deref(), &name)?;
    let health = normalize_group_health(kind, &group);
    let filter = group.filter.filter(|value| !value.is_empty());
    let exclude_filter = group.exclude_filter.filter(|value| !value.is_empty());
    let exclude_types: Vec<_> = group
        .exclude_type
        .filter(|value| !value.is_empty())
        .into_iter()
        .flat_map(|value| value.split('|').map(str::to_owned).collect::<Vec<String>>())
        .collect();
    let filter_regexes = compile_group_regexes(filter.as_deref(), &name)?;
    compile_group_regexes(exclude_filter.as_deref(), &name)?;
    let empty_fallback = group
        .empty_fallback
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "COMPATIBLE".to_owned());
    if !catalog.top_level_names.contains(empty_fallback.as_str())
        && !is_group_builtin(&empty_fallback)
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }

    let include_all = group.include_all.unwrap_or(false);
    let include_all_proxies = include_all || group.include_all_proxies.unwrap_or(false);
    let include_all_providers = include_all || group.include_all_providers.unwrap_or(false);
    let mut compatible_proxies = group.proxies.unwrap_or_default();
    if include_all_proxies {
        if filter_regexes.is_empty() {
            compatible_proxies.extend(catalog.all_proxies.iter().cloned());
        } else {
            for proxy in catalog.all_proxies {
                for pattern in &filter_regexes {
                    if group_regex_matches(pattern, proxy) {
                        compatible_proxies.push(proxy.clone());
                    }
                }
            }
        }
    }
    let provider_names = if include_all_providers {
        catalog.all_providers.to_vec()
    } else {
        group.providers.unwrap_or_default()
    };
    for provider_name in &provider_names {
        catalog
            .providers
            .iter()
            .find(|provider| provider.name == *provider_name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
    }
    if compatible_proxies.is_empty() && provider_names.is_empty() {
        compatible_proxies.push(empty_fallback.clone());
    }
    if compatible_proxies
        .iter()
        .any(|member| !catalog.proxy_names.contains(member.as_str()) && !is_group_builtin(member))
    {
        return Err(ConfigError::UnsupportedProxy(name));
    }
    let mut parsed = ProxyGroupConfig {
        name,
        kind,
        proxies: Vec::new(),
        compatible_proxies,
        providers: provider_names,
        filter,
        exclude_filter,
        exclude_types,
        empty_fallback,
        default_selected: group.default_selected,
        test_url: normalize_group_test_url(group.url),
        expected_status: normalize_group_expected_status(group.expected_status),
        hidden: group.hidden.unwrap_or(false),
        icon: group.icon.unwrap_or_default(),
        disable_udp: group.disable_udp.unwrap_or(false),
        tolerance: group.tolerance.unwrap_or(0),
        health,
        load_balance_strategy,
    };
    parsed.proxies = expand_proxy_group(&parsed, catalog.providers, catalog.proxy_types)?;
    if parsed
        .proxies
        .iter()
        .any(|member| !catalog.proxy_names.contains(member.as_str()) && !is_group_builtin(member))
        || (parsed.kind == ProxyGroupKind::Select
            && parsed
                .default_selected
                .as_ref()
                .is_some_and(|default| !parsed.proxies.contains(default)))
    {
        return Err(ConfigError::UnsupportedProxy(parsed.name));
    }
    Ok(parsed)
}

fn parse_proxy_group_kind(kind: Option<&str>, name: &str) -> Result<ProxyGroupKind, ConfigError> {
    match kind {
        Some("select") => Ok(ProxyGroupKind::Select),
        Some("fallback") => Ok(ProxyGroupKind::Fallback),
        Some("url-test") => Ok(ProxyGroupKind::UrlTest),
        Some("load-balance") => Ok(ProxyGroupKind::LoadBalance),
        _ => Err(ConfigError::UnsupportedProxy(name.to_owned())),
    }
}

fn parse_load_balance_strategy(
    kind: ProxyGroupKind,
    strategy: Option<&str>,
    name: &str,
) -> Result<Option<LoadBalanceStrategy>, ConfigError> {
    match (kind, strategy) {
        (ProxyGroupKind::LoadBalance, None | Some("consistent-hashing")) => {
            Ok(Some(LoadBalanceStrategy::ConsistentHashing))
        }
        (ProxyGroupKind::LoadBalance, Some("round-robin")) => {
            Ok(Some(LoadBalanceStrategy::RoundRobin))
        }
        (ProxyGroupKind::LoadBalance, Some("sticky-sessions")) => {
            Ok(Some(LoadBalanceStrategy::StickySessions))
        }
        (_, Some(_)) => Err(ConfigError::UnsupportedProxy(name.to_owned())),
        (_, None) => Ok(None),
    }
}

fn normalize_group_health(kind: ProxyGroupKind, group: &RawProxyGroup) -> GroupHealthConfig {
    GroupHealthConfig {
        interval: match (kind, group.interval.unwrap_or(0)) {
            (ProxyGroupKind::Select, interval) | (_, interval @ 1..) => interval,
            (_, 0) => 300,
        },
        timeout: match group.timeout.unwrap_or(0) {
            0 => 5000,
            timeout => timeout,
        },
        lazy: group.lazy.unwrap_or(true),
        max_failed_times: match group.max_failed_times.unwrap_or(0) {
            0 => 5,
            max_failed_times => max_failed_times,
        },
    }
}

fn normalize_group_test_url(value: Option<String>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_owned())
}

fn normalize_group_expected_status(value: Option<String>) -> String {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "*".to_owned())
}

fn is_group_builtin(name: &str) -> bool {
    matches!(
        name,
        "DIRECT" | "REJECT" | "REJECT-DROP" | "COMPATIBLE" | "PASS" | "PASS-RULE"
    )
}

fn compile_group_regexes(
    value: Option<&str>,
    group_name: &str,
) -> Result<Vec<fancy_regex::Regex>, ConfigError> {
    value
        .into_iter()
        .flat_map(|value| value.split('`'))
        .map(|pattern| {
            fancy_regex::Regex::new(pattern)
                .map_err(|_| ConfigError::UnsupportedProxy(group_name.to_owned()))
        })
        .collect()
}

fn group_regex_matches(pattern: &fancy_regex::Regex, name: &str) -> bool {
    pattern.is_match(name).unwrap_or(false)
}

fn proxy_member_types(
    proxies: &[ProxyConfig],
    providers: &[ProxyProviderConfig],
    group_types: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut types: BTreeMap<_, _> = [
        ("DIRECT", "Direct"),
        ("REJECT", "Reject"),
        ("REJECT-DROP", "RejectDrop"),
        ("COMPATIBLE", "Compatible"),
        ("PASS", "Pass"),
        ("PASS-RULE", "Pass"),
    ]
    .into_iter()
    .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
    .collect();
    for proxy in proxies.iter().chain(
        providers
            .iter()
            .flat_map(|provider| provider.proxies.iter()),
    ) {
        let kind = match proxy.kind {
            ProxyKind::Http => "Http",
            ProxyKind::Socks5 => "Socks5",
        };
        types.insert(proxy.name.clone(), kind.to_owned());
    }
    types.extend(group_types.clone());
    types
}

fn expand_proxy_group(
    group: &ProxyGroupConfig,
    providers: &[ProxyProviderConfig],
    proxy_types: &BTreeMap<String, String>,
) -> Result<Vec<String>, ConfigError> {
    let filter_regexes = compile_group_regexes(group.filter.as_deref(), &group.name)?;
    let exclude_regexes = compile_group_regexes(group.exclude_filter.as_deref(), &group.name)?;
    let mut members = group.compatible_proxies.clone();
    let mut component_count = usize::from(!group.compatible_proxies.is_empty());

    for provider_name in &group.providers {
        let provider = providers
            .iter()
            .find(|provider| provider.name == *provider_name)
            .ok_or_else(|| ConfigError::UnsupportedProxy(group.name.clone()))?;
        component_count += 1;
        if filter_regexes.is_empty() {
            members.extend(provider.proxies.iter().map(|proxy| proxy.name.clone()));
            continue;
        }
        let mut provider_members = BTreeSet::new();
        for pattern in &filter_regexes {
            for proxy in &provider.proxies {
                if group_regex_matches(pattern, &proxy.name) {
                    provider_members.insert(proxy.name.clone());
                }
            }
        }
        for pattern in &filter_regexes {
            for proxy in &provider.proxies {
                if group_regex_matches(pattern, &proxy.name) && provider_members.remove(&proxy.name)
                {
                    members.push(proxy.name.clone());
                }
            }
        }
    }

    if component_count > 1 && filter_regexes.len() > 1 {
        let original = std::mem::take(&mut members);
        let mut remaining: BTreeSet<_> = original.iter().cloned().collect();
        for pattern in &filter_regexes {
            for member in &original {
                if group_regex_matches(pattern, member) && remaining.remove(member) {
                    members.push(member.clone());
                }
            }
        }
        for member in original {
            if remaining.remove(&member) {
                members.push(member);
            }
        }
    }

    members.retain(|member| {
        !exclude_regexes
            .iter()
            .any(|pattern| group_regex_matches(pattern, member))
    });
    members.retain(|member| {
        proxy_types.get(member).is_none_or(|kind| {
            !group
                .exclude_types
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(kind))
        })
    });
    if members.is_empty() {
        members.push(group.empty_fallback.clone());
    }
    Ok(members)
}

fn parse_proxy_providers(
    providers: BTreeMap<String, RawProxyProvider>,
    config_directory: Option<&Path>,
    top_level: &[ProxyConfig],
) -> Result<Vec<ProxyProviderConfig>, ConfigError> {
    let mut names: BTreeSet<_> = top_level.iter().map(|proxy| proxy.name.clone()).collect();
    let mut parsed = Vec::new();
    for (name, provider) in providers {
        if name.is_empty() || !provider.extra.is_empty() {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        let directory =
            config_directory.ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
        let (vehicle, url, path, proxies) = match provider.kind.as_deref() {
            Some("file") if provider.url.is_none() => {
                let configured_path = provider
                    .path
                    .filter(|path| !path.is_empty())
                    .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                let path = directory.join(configured_path);
                (
                    ProxyProviderVehicle::File,
                    None,
                    path.clone(),
                    load_proxy_provider_file(&name, &path)?,
                )
            }
            Some("http") => {
                let url = provider
                    .url
                    .filter(|url| !url.is_empty())
                    .ok_or_else(|| ConfigError::UnsupportedProxy(name.clone()))?;
                let parsed_url =
                    Url::parse(&url).map_err(|_| ConfigError::UnsupportedProxy(name.clone()))?;
                if parsed_url.scheme() != "http" || parsed_url.host_str().is_none() {
                    return Err(ConfigError::UnsupportedProxy(name));
                }
                let path = provider.path.filter(|path| !path.is_empty()).map_or_else(
                    || {
                        directory
                            .join("proxies")
                            .join(format!("{:x}", Md5::digest(url.as_bytes())))
                    },
                    |path| directory.join(path),
                );
                let cached = load_proxy_provider_file(&name, &path).unwrap_or_default();
                (ProxyProviderVehicle::Http, Some(url), path, cached)
            }
            _ => return Err(ConfigError::UnsupportedProxy(name)),
        };
        if proxies
            .iter()
            .any(|proxy| !names.insert(proxy.name.clone()))
        {
            return Err(ConfigError::UnsupportedProxy(name));
        }
        parsed.push(ProxyProviderConfig {
            name,
            vehicle,
            path,
            url,
            interval: provider.interval.unwrap_or(0),
            headers: provider.header.unwrap_or_default(),
            size_limit: provider.size_limit.unwrap_or(0),
            etag: None,
            proxies,
        });
    }
    Ok(parsed)
}

fn load_proxy_provider_file(name: &str, path: &Path) -> Result<Vec<ProxyConfig>, ConfigError> {
    let source = std::fs::read_to_string(path)?;
    parse_proxy_provider_source(name, &source)
}

fn parse_proxy_provider_source(name: &str, source: &str) -> Result<Vec<ProxyConfig>, ConfigError> {
    let file = serde_yaml_ng::from_str::<RawProxyProviderFile>(source)?;
    if !file.extra.is_empty() {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    let (rematches, proxies) = parse_proxies(file.proxies.unwrap_or_default())?;
    if !rematches.is_empty() || proxies.is_empty() {
        return Err(ConfigError::UnsupportedProxy(name.to_owned()));
    }
    Ok(proxies)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r"
mixed-port: 7890
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
";

    #[test]
    fn overlays_oracle_defaults() {
        let config = ConfigSpec::from_yaml("").expect("empty config overlays defaults");
        let normalized = config.normalized();
        assert_eq!(normalized.bind_address, "*");
        assert_eq!(normalized.mode, Mode::Rule);
        assert_eq!(normalized.log_level, LogLevel::Info);
        assert!(normalized.ipv6);
        assert!(normalized.etag_support);
        assert!(normalized.rules.is_empty());
    }

    #[test]
    fn parses_minimal_runtime_config() {
        let config = Config::from_yaml(MINIMAL).expect("minimal config must parse");
        assert_eq!(config.mixed_port, 7890);
        assert_eq!(config.mode, Mode::Rule);
        assert_eq!(config.listener_port().expect("valid port"), 7890);
    }

    #[test]
    fn accepts_controller_mutable_log_levels_in_runtime_config() {
        for (value, expected) in [
            ("debug", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("warning", LogLevel::Warning),
            ("error", LogLevel::Error),
            ("silent", LogLevel::Silent),
        ] {
            let source = MINIMAL.replace("log-level: info", &format!("log-level: {value}"));
            let config = Config::from_yaml(&source).expect("controller log level is executable");
            assert_eq!(config.log_level, expected);
        }
    }

    #[test]
    fn accepts_all_live_routing_modes() {
        for (value, expected) in [
            ("rule", Mode::Rule),
            ("direct", Mode::Direct),
            ("global", Mode::Global),
        ] {
            let source = MINIMAL.replace("mode: rule", &format!("mode: {value}"));
            let config = Config::from_yaml(&source).expect("routing mode is executable");
            assert_eq!(config.mode, expected);
        }
    }

    #[test]
    fn accepts_rematch_proxies_for_runtime_rules() {
        let source = r"
mixed-port: 7890
proxies:
  - name: SET-NAME
    type: rematch
    target-rematch-name: after
rules:
  - REMATCH-NAME,after,DIRECT
  - MATCH,SET-NAME
";
        let config = Config::from_yaml(source).expect("rematch is a runtime scan action");
        assert_eq!(config.listener_port().expect("valid port"), 7890);
    }

    #[test]
    fn accepts_external_doh_mount_for_controller_runtime() {
        let source = format!(
            "{MINIMAL}\nexternal-controller: 127.0.0.1:9090\nexternal-doh-server: /dns-query\n"
        );
        let config = Config::from_yaml(&source).expect("external DoH mount must parse");
        assert_eq!(config.external_doh_server, "/dns-query");
    }

    #[test]
    fn mirrors_oracle_test_mode_port_acceptance() {
        let source = MINIMAL.replace("7890", "70000");
        let spec = ConfigSpec::from_yaml(&source).expect("oracle -t accepts this integer");
        spec.validate_declared_surface().expect("declared surface");
        let config: Config = spec.try_into().expect("runtime shape is otherwise valid");
        assert!(matches!(
            config.listener_port(),
            Err(ConfigError::InvalidRuntimePort(70000))
        ));
    }

    #[test]
    fn separates_specification_from_runtime_scope() {
        let source = format!("{MINIMAL}\nredir-port: 8080\n");
        let spec = ConfigSpec::from_yaml(&source).expect("Phase 2 specification parses");
        assert_eq!(spec.normalized().redir_port, 8080);
        assert!(matches!(
            Config::try_from(spec),
            Err(ConfigError::UnsupportedRuntime(feature)) if feature == "redir-port"
        ));
    }

    #[test]
    fn builds_phase_three_listener_set_and_authentication() {
        let source = r#"
port: 8080
socks-port: 1080
mixed-port: 7890
authentication:
  - alice:secret
  - ignored-without-colon
  - "socks4:"
rules:
  - MATCH,DIRECT
"#;
        let config = Config::from_yaml(source).expect("Phase 3A config");
        assert_eq!(config.authentication.len(), 2);
        assert_eq!(config.authentication[0].username, "alice");
        assert_eq!(config.authentication[1].password, "");
        assert_eq!(
            config.listener_ports().expect("valid listeners"),
            vec![
                (ListenerKind::Http, 8080),
                (ListenerKind::Socks, 1080),
                (ListenerKind::Mixed, 7890),
            ]
        );
    }

    #[test]
    fn refuses_undeclared_features() {
        let source = format!("{MINIMAL}\ntun:\n  enable: true\n");
        let spec = ConfigSpec::from_yaml(&source).expect("spec preserves unknown keys");
        assert!(matches!(
            spec.validate_declared_surface(),
            Err(ConfigError::UnsupportedKey(key)) if key == "tun"
        ));
    }

    #[test]
    fn parses_phase_four_a_dns_subset() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: redir-host
  nameserver:
    - tcp://127.0.0.1:15353
";
        let config = Config::from_yaml(source).expect("Phase 4A DNS-only config");
        assert!(
            config
                .listener_ports()
                .expect("DNS-only runtime")
                .is_empty()
        );
        assert_eq!(
            config.dns,
            Some(DnsConfig {
                listen: "127.0.0.1:5353".parse().expect("literal"),
                upstream: "127.0.0.1:15353".parse().expect("literal"),
                transport: DnsTransport::Tcp,
                main_kind: DnsMainKind::Configured,
                classic_upstreams: vec![DnsClassicUpstream {
                    endpoint: DnsClassicEndpoint::Socket(
                        "127.0.0.1:15353".parse().expect("literal"),
                    ),
                    transport: DnsTransport::Tcp,
                    query_options: DnsQueryOptions::default(),
                }],
                main_resolvers: vec![DnsResolverClient::Classic(DnsClassicUpstream {
                    endpoint: DnsClassicEndpoint::Socket(
                        "127.0.0.1:15353".parse().expect("literal"),
                    ),
                    transport: DnsTransport::Tcp,
                    query_options: DnsQueryOptions::default(),
                })],
                default_resolvers: Vec::new(),
                proxy_resolvers: Vec::new(),
                ipv6: false,
                ipv6_timeout: std::time::Duration::from_millis(100),
                cache_algorithm: DnsCacheAlgorithm::Lru,
                cache_max_size: 4096,
                use_hosts: false,
                use_system_hosts: false,
                mode: DnsMode::RedirHost,
                fake_ip: None,
                policies: Vec::new(),
                proxy_policies: Vec::new(),
                fallback: None,
                direct: None,
                tls: None,
                query_options: DnsQueryOptions::default(),
            })
        );
    }

    #[test]
    fn parses_phase_four_f_three_system_resolver_spellings() {
        for nameserver in ["system", "system://", "dhcp://system"] {
            let source = format!(
                "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - {nameserver}\n"
            );
            let dns = Config::from_yaml(&source)
                .expect("Phase 4F3 system resolver config")
                .dns
                .expect("enabled DNS");
            assert_eq!(dns.main_kind, DnsMainKind::System);
            assert!(dns.classic_upstreams.is_empty());
        }
    }

    #[test]
    fn parses_phase_four_f_four_dhcp_interface() {
        let source = "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - dhcp://fixture0\n";
        let dns = Config::from_yaml(source)
            .expect("Phase 4F4 DHCP resolver config")
            .dns
            .expect("enabled DNS");
        assert_eq!(dns.main_kind, DnsMainKind::Dhcp("fixture0".to_owned()));
        assert!(dns.classic_upstreams.is_empty());
    }

    #[test]
    fn parses_phase_four_f_five_synthetic_rcodes() {
        for (name, expected) in [
            ("success", SyntheticRcode::Success),
            ("format_error", SyntheticRcode::FormatError),
            ("server_failure", SyntheticRcode::ServerFailure),
            ("name_error", SyntheticRcode::NameError),
            ("not_implemented", SyntheticRcode::NotImplemented),
            ("refused", SyntheticRcode::Refused),
        ] {
            let source = format!(
                "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - rcode://{name}\n"
            );
            let dns = Config::from_yaml(&source)
                .expect("Phase 4F5 RCODE resolver config")
                .dns
                .expect("enabled DNS");
            assert_eq!(dns.main_kind, DnsMainKind::Rcode(expected));
            assert!(dns.classic_upstreams.is_empty());
        }
    }

    #[test]
    fn parses_phase_four_f_five_tailscale_aliases() {
        for nameserver in ["tailscale://fixture", "ts://fixture"] {
            let source = format!(
                "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - {nameserver}\n"
            );
            let dns = Config::from_yaml(&source)
                .expect("Phase 4F5 Tailscale resolver config")
                .dns
                .expect("enabled DNS");
            assert_eq!(dns.main_kind, DnsMainKind::Tailscale("fixture".to_owned()));
            assert!(dns.classic_upstreams.is_empty());
        }
    }

    #[test]
    fn rejects_invalid_phase_four_f_five_nameservers() {
        for nameserver in ["rcode://unknown", "tailscale://", "ts://"] {
            let source = format!(
                "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - {nameserver}\n"
            );
            assert!(Config::from_yaml(&source).is_err(), "accepted {nameserver}");
        }
    }

    #[test]
    fn parses_phase_four_f_six_classic_wrapper_identity() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - udp://127.0.0.1:15353#ecs=203.0.113.129/24
    - udp://127.0.0.1:15353#ecs=203.0.113.129/24
    - udp://127.0.0.1:15353#disable-ipv4=true&disable-qtype-65=true
";
        let upstreams = Config::from_yaml(source)
            .expect("Phase 4F6 classic wrapper config")
            .dns
            .expect("enabled DNS")
            .classic_upstreams;
        assert_eq!(upstreams.len(), 2, "exact wrapper duplicate must collapse");
        assert_eq!(upstreams[0].endpoint, upstreams[1].endpoint);
        assert_eq!(upstreams[0].transport, upstreams[1].transport);
        assert_eq!(
            upstreams[0].query_options.ecs,
            Some(EcsConfig {
                address: "203.0.113.129".parse().expect("address"),
                prefix: 24,
                override_existing: false,
            })
        );
        assert_eq!(upstreams[1].query_options.disabled_types, vec![1, 65]);
    }

    #[test]
    fn ignores_phase_four_f_six_false_and_invalid_wrapper_values() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - tcp://127.0.0.1:15353#ecs=203.0.113.1/33&ecs-override=true&disable-ipv4=false&disable-qtype-invalid=true&disable-qtype-65535=true
";
        let options = Config::from_yaml(source)
            .expect("Go ignores false and invalid wrapper values")
            .dns
            .expect("enabled DNS")
            .classic_upstreams
            .remove(0)
            .query_options;
        assert_eq!(options, DnsQueryOptions::default());

        let proxy_fragment = source.replace(
            "#ecs=203.0.113.1/33&ecs-override=true&disable-ipv4=false&disable-qtype-invalid=true&disable-qtype-65535=true",
            "#proxy-outbound",
        );
        assert!(Config::from_yaml(&proxy_fragment).is_err());
    }

    #[test]
    fn parses_phase_four_f_seven_resolver_sets() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  default-nameserver:
    - udp://127.0.0.1:1053
    - tcp://127.0.0.1:1054
  nameserver:
    - udp://127.0.0.1:2053
    - tcp://127.0.0.1:2054
  fallback:
    - udp://127.0.0.1:3053
    - tcp://127.0.0.1:3054
  fallback-filter:
    geoip: false
  direct-nameserver:
    - udp://127.0.0.1:4053
    - tcp://127.0.0.1:4054
  direct-nameserver-follow-policy: true
  proxy-server-nameserver:
    - udp://127.0.0.1:5053
    - tcp://127.0.0.1:5054
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4F7 resolver sets")
            .dns
            .expect("enabled DNS");
        assert_eq!(dns.default_resolvers.len(), 2);
        assert_eq!(dns.main_resolvers.len(), 2);
        assert_eq!(dns.fallback.as_ref().expect("fallback").resolvers.len(), 2);
        assert_eq!(dns.direct.as_ref().expect("direct").resolvers.len(), 2);
        assert!(dns.direct.as_ref().expect("direct").follow_policy);
        assert_eq!(dns.proxy_resolvers.len(), 2);
    }

    #[test]
    fn accepts_phase_four_b_hosts_switch() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  use-hosts: true
  use-system-hosts: false
  nameserver:
    - udp://127.0.0.1:15353
";
        assert!(Config::from_yaml(source).is_ok());
    }

    #[test]
    fn parses_phase_four_b_hosts_and_rejects_cycles() {
        let source = r"
hosts:
  fixed.phase4.test: [192.0.2.10, 2001:db8::10]
  alias.phase4.test: target.phase4.test
";
        let config = ConfigSpec::from_yaml(source).expect("Phase 4B hosts");
        assert!(matches!(
            config.hosts.get("fixed.phase4.test"),
            Some(HostEntry::Addresses(addresses)) if addresses.len() == 2
        ));
        assert_eq!(
            config.hosts.get("alias.phase4.test"),
            Some(&HostEntry::Domain("target.phase4.test".to_owned()))
        );

        let cycle = r"
hosts:
  one.phase4.test: two.phase4.test
  two.phase4.test: one.phase4.test
";
        assert!(matches!(
            ConfigSpec::from_yaml(cycle),
            Err(ConfigError::InvalidHosts(message)) if message.contains("cycle")
        ));
    }

    #[test]
    fn phase_four_f_twelve_hosts_follow_trie_priority_and_aliases() {
        let config = ConfigSpec::from_yaml(
            r#"
hosts:
  "+.example.test": 192.0.2.1
  "*.example.test": 192.0.2.2
  exact.example.test: 192.0.2.3
  ".suffix.test": 192.0.2.4
  alias.example.test: target.external.test
"#,
        )
        .expect("wildcard hosts");
        assert!(matches!(
            config.hosts.search("example.test"),
            Some(HostEntry::Addresses(addresses)) if addresses[0].to_string() == "192.0.2.1"
        ));
        assert!(matches!(
            config.hosts.search("one.example.test"),
            Some(HostEntry::Addresses(addresses)) if addresses[0].to_string() == "192.0.2.2"
        ));
        assert!(matches!(
            config.hosts.search("EXACT.EXAMPLE.TEST"),
            Some(HostEntry::Addresses(addresses)) if addresses[0].to_string() == "192.0.2.3"
        ));
        assert!(config.hosts.search("suffix.test").is_none());
        assert!(config.hosts.search("deep.suffix.test").is_some());
        assert_eq!(
            config.hosts.resolve("alias.example.test"),
            Some(HostEntry::Domain("target.external.test".to_owned()))
        );
    }

    #[test]
    fn parses_phase_four_c_fake_ip_settings() {
        let source = r"
profile:
  store-fake-ip: true
dns:
  enable: true
  listen: 127.0.0.1:5353
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.19.0.1/24
  fake-ip-range6: fd00:198:19::1/120
  fake-ip-filter: [real.phase4.test]
  fake-ip-filter-mode: whitelist
  fake-ip-ttl: 7
  nameserver:
    - udp://127.0.0.1:15353
";
        let config = Config::from_yaml(source).expect("Phase 4C config");
        assert!(config.profile.store_fake_ip);
        assert!(config.profile.store_selected);
        let dns = config.dns.expect("DNS config");
        assert_eq!(dns.mode, DnsMode::FakeIp);
        assert!(dns.ipv6);
        let fake = dns.fake_ip.expect("fake-IP config");
        assert_eq!(fake.ipv4_range.expect("IPv4").to_string(), "198.19.0.1/24");
        assert_eq!(
            fake.ipv6_range.expect("IPv6").to_string(),
            "fd00:198:19::1/120"
        );
        assert_eq!(fake.filter_mode, FakeIpFilterMode::Whitelist);
        assert_eq!(fake.ttl, 7);
    }

    #[test]
    fn parses_selector_persistence_profile_setting() {
        let default = Config::from_yaml("mixed-port: 7890\nrules: ['MATCH,DIRECT']\n")
            .expect("default profile");
        assert!(default.profile.store_selected);

        let disabled = Config::from_yaml(
            "mixed-port: 7890\nprofile:\n  store-selected: false\nrules: ['MATCH,DIRECT']\n",
        )
        .expect("disabled selector persistence");
        assert!(!disabled.profile.store_selected);
    }

    #[test]
    fn parses_manual_health_fallback_group() {
        let config = Config::from_yaml(&format!(
            "{MINIMAL}\nproxy-groups:\n  - name: recovery\n    type: fallback\n    proxies: [REJECT, DIRECT]\n    url: http://127.0.0.1:18080/health\n    expected-status: '204'\n    interval: 7\n    timeout: 250\n    max-failed-times: 2\n    lazy: false\n    hidden: true\n    icon: fallback.svg\n    disable-udp: true\n"
        ))
        .expect("fallback group");
        let group = &config.proxy_groups[0];
        assert_eq!(group.kind, ProxyGroupKind::Fallback);
        assert_eq!(group.proxies, ["REJECT", "DIRECT"]);
        assert_eq!(group.expected_status, "204");
        assert!(group.hidden);
        assert_eq!(group.icon, "fallback.svg");
        assert!(group.disable_udp);
        assert_eq!(group.health.interval, 7);
        assert_eq!(group.health.timeout, 250);
        assert_eq!(group.health.max_failed_times, 2);
        assert!(!group.health.lazy);
    }

    #[test]
    fn parses_url_test_group_policy() {
        let config = Config::from_yaml(&format!(
            "{MINIMAL}\nproxy-groups:\n  - name: fastest\n    type: url-test\n    proxies: [DIRECT, REJECT]\n    url: http://127.0.0.1:18080/health\n    expected-status: '204'\n    tolerance: 25\n"
        ))
        .expect("URL-test group");
        let group = &config.proxy_groups[0];
        assert_eq!(group.kind, ProxyGroupKind::UrlTest);
        assert_eq!(group.tolerance, 25);
        assert_eq!(group.expected_status, "204");
    }

    #[test]
    fn parses_load_balance_strategies() {
        let config = Config::from_yaml(&format!(
            "{MINIMAL}\nproxy-groups:\n  - name: balanced\n    type: load-balance\n    strategy: round-robin\n    proxies: [DIRECT, REJECT]\n    url: http://127.0.0.1:18080/health\n"
        ))
        .expect("round-robin group");
        let group = &config.proxy_groups[0];
        assert_eq!(group.kind, ProxyGroupKind::LoadBalance);
        assert_eq!(
            group.load_balance_strategy,
            Some(LoadBalanceStrategy::RoundRobin)
        );

        let default = Config::from_yaml(&format!(
            "{MINIMAL}\nproxy-groups:\n  - name: balanced\n    type: load-balance\n    proxies: [DIRECT, REJECT]\n"
        ))
        .expect("default consistent-hashing group");
        assert_eq!(
            default.proxy_groups[0].load_balance_strategy,
            Some(LoadBalanceStrategy::ConsistentHashing)
        );

        let sticky = Config::from_yaml(&format!(
            "{MINIMAL}\nproxy-groups:\n  - name: balanced\n    type: load-balance\n    strategy: sticky-sessions\n    proxies: [DIRECT, REJECT]\n"
        ))
        .expect("sticky-sessions group");
        assert_eq!(
            sticky.proxy_groups[0].load_balance_strategy,
            Some(LoadBalanceStrategy::StickySessions)
        );
    }

    #[test]
    fn parses_phase_four_d_one_nameserver_policy() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - udp://127.0.0.1:15353
  nameserver-policy:
    '+.suffix.phase4.test': tcp://127.0.0.1:25353
    '*.one.phase4.test':
      - udp://127.0.0.1:35353
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4D1 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.policies.len(), 2);
        assert!(dns.policies.iter().any(|policy| {
            policy.matcher == DnsPolicyMatcher::Domain("+.suffix.phase4.test".to_owned())
                && matches!(
                    policy.resolvers.as_slice(),
                    [DnsResolverClient::Classic(DnsClassicUpstream {
                        transport: DnsTransport::Tcp,
                        ..
                    })]
                )
        }));
        assert!(dns.policies.iter().any(|policy| {
            policy.matcher == DnsPolicyMatcher::Domain("*.one.phase4.test".to_owned())
                && matches!(
                    policy.resolvers.as_slice(),
                    [DnsResolverClient::Classic(DnsClassicUpstream {
                        transport: DnsTransport::Udp,
                        ..
                    })]
                )
        }));
    }

    #[test]
    fn parses_phase_four_d_two_fallback_subset() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - udp://127.0.0.1:15353
  fallback:
    - tcp://127.0.0.1:25353
  fallback-lazy-query: true
  fallback-filter:
    geoip: false
    ipcidr: [198.51.100.0/24]
    domain: ['+.fallback.phase4.test']
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4D2 config")
            .dns
            .expect("DNS");
        assert_eq!(
            dns.fallback,
            Some(DnsFallbackConfig {
                resolvers: vec![DnsResolverClient::Classic(DnsClassicUpstream {
                    endpoint: DnsClassicEndpoint::Socket(
                        "127.0.0.1:25353".parse().expect("literal"),
                    ),
                    transport: DnsTransport::Tcp,
                    query_options: DnsQueryOptions::default(),
                })],
                domains: vec!["+.fallback.phase4.test".to_owned()],
                geosites: Vec::new(),
                ipcidr: vec!["198.51.100.0/24".parse().expect("CIDR")],
                geoip: None,
                lazy: true,
            })
        );
    }

    #[test]
    fn parses_phase_four_d_three_a_direct_resolver_subset() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - udp://127.0.0.1:15353
  direct-nameserver:
    - tcp://127.0.0.1:25353
  direct-nameserver-follow-policy: true
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4D3A config")
            .dns
            .expect("DNS");
        assert_eq!(
            dns.direct,
            Some(DnsDirectConfig {
                resolvers: vec![DnsResolverClient::Classic(DnsClassicUpstream {
                    endpoint: DnsClassicEndpoint::Socket(
                        "127.0.0.1:25353".parse().expect("literal"),
                    ),
                    transport: DnsTransport::Tcp,
                    query_options: DnsQueryOptions::default(),
                })],
                follow_policy: true,
            })
        );
    }

    #[test]
    fn parses_phase_four_e_one_dot_subset() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - tls://127.0.0.1:8530#skip-cert-verify=true&disable-reuse=true
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E1 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.transport, DnsTransport::TlsInsecureNoReuse);
        assert_eq!(dns.upstream, "127.0.0.1:8530".parse().expect("literal"));

        let reuse = source.replace("&disable-reuse=true", "");
        assert_eq!(
            Config::from_yaml(&reuse)
                .expect("Phase 4E10 insecure reuse config")
                .dns
                .expect("DNS")
                .transport,
            DnsTransport::TlsInsecureReuse
        );
        let proxy_fragment = source.replace("&disable-reuse=true", "&disable-reuse=true&DIRECT");
        assert!(matches!(
            Config::from_yaml(&proxy_fragment),
            Err(ConfigError::InvalidDns(message)) if message.contains("Phase 4E10")
        ));
    }

    #[test]
    fn parses_phase_four_e_two_verified_dot_subset() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      test-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - tls://127.0.0.1:8530#name-cert-verify=dot.phase4.test&disable-reuse=true
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E2 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.transport, DnsTransport::TlsVerifiedNoReuse);
        let tls = dns.tls.expect("verification settings");
        assert_eq!(tls.server_name, "dot.phase4.test");
        assert_eq!(tls.trust_certificates.len(), 1);

        let system_roots = source.replace(
            "tls:\n  custom-certifactes:\n    - |-\n      -----BEGIN CERTIFICATE-----\n      test-root\n      -----END CERTIFICATE-----\n",
            "",
        );
        assert!(Config::from_yaml(&system_roots).is_ok());
    }

    #[test]
    fn parses_phase_four_e_ten_dot_verification_matrix() {
        let source = |fragment: &str| {
            format!(
                "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - tls://127.0.0.1:8530{fragment}\n"
            )
        };
        for (fragment, transport, server_name) in [
            ("", DnsTransport::TlsVerifiedReuse, Some("127.0.0.1")),
            (
                "#disable-reuse=true",
                DnsTransport::TlsVerifiedNoReuse,
                Some("127.0.0.1"),
            ),
            (
                "#skip-cert-verify=true",
                DnsTransport::TlsInsecureReuse,
                None,
            ),
            (
                "#skip-cert-verify=true&disable-reuse=true",
                DnsTransport::TlsInsecureNoReuse,
                None,
            ),
            (
                "#name-cert-verify=dot.phase4.test",
                DnsTransport::TlsVerifiedReuse,
                Some("dot.phase4.test"),
            ),
            (
                "#name-cert-verify=dot.phase4.test&disable-reuse=true",
                DnsTransport::TlsVerifiedNoReuse,
                Some("dot.phase4.test"),
            ),
            (
                "#skip-cert-verify=true&name-cert-verify=dot.phase4.test",
                DnsTransport::TlsVerifiedReuse,
                Some("dot.phase4.test"),
            ),
        ] {
            let dns = Config::from_yaml(&source(fragment))
                .expect("Phase 4E10 matrix config")
                .dns
                .expect("DNS");
            assert_eq!(dns.transport, transport);
            assert_eq!(
                dns.tls.as_ref().map(|tls| tls.server_name.as_str()),
                server_name
            );
        }
    }

    #[test]
    fn parses_phase_four_e_three_multiple_inline_roots() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      decoy-root
      -----END CERTIFICATE-----
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - tls://127.0.0.1:8530#name-cert-verify=dot.phase4.test&disable-reuse=true
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E3 config")
            .dns
            .expect("DNS");
        assert_eq!(
            dns.tls
                .expect("verification settings")
                .trust_certificates
                .len(),
            2
        );
    }

    #[test]
    fn parses_phase_four_e_four_verified_reuse() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - tls://127.0.0.1:8530#name-cert-verify=dot.phase4.test
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E4 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.transport, DnsTransport::TlsVerifiedReuse);
        assert_eq!(
            dns.tls.expect("verification settings").server_name,
            "dot.phase4.test"
        );
    }

    #[test]
    fn parses_phase_four_e_five_verified_https_doh() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - https://127.0.0.1:8443/dns-query#name-cert-verify=dot.phase4.test
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E5 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.transport, DnsTransport::HttpsVerifiedReuse);
        assert_eq!(dns.upstream, "127.0.0.1:8443".parse().expect("address"));
        let tls = dns.tls.expect("verification settings");
        assert_eq!(tls.server_name, "dot.phase4.test");
        assert_eq!(tls.doh_path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn parses_phase_four_e_twelve_plaintext_http_doh_defaults() {
        for (url, port, path) in [
            ("http://127.0.0.1", 80, "/"),
            ("http://127.0.0.1/", 80, "/"),
            ("http://127.0.0.1:8080", 8080, "/"),
            ("http://127.0.0.1:8080/dns-query", 8080, "/dns-query"),
        ] {
            let source = format!(
                "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - {url}\n"
            );
            let dns = Config::from_yaml(&source)
                .expect("Phase 4E12 config")
                .dns
                .expect("DNS");
            assert_eq!(dns.transport, DnsTransport::HttpReuse);
            assert_eq!(dns.upstream, SocketAddr::from(([127, 0, 0, 1], port)));
            assert_eq!(
                dns.tls.expect("DoH settings").doh_path.as_deref(),
                Some(path)
            );
        }
    }

    #[test]
    fn parses_phase_four_e_seven_custom_doh_path_subset() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - https://127.0.0.1:8443/custom/dns-query#name-cert-verify=dot.phase4.test
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E7 config")
            .dns
            .expect("DNS");
        assert_eq!(
            dns.tls.expect("verification settings").doh_path.as_deref(),
            Some("/custom/dns-query")
        );

        let root_path = source.replace("/custom/dns-query#", "/#");
        assert_eq!(
            Config::from_yaml(&root_path)
                .expect("Phase 4E13 root path")
                .dns
                .expect("DNS")
                .tls
                .expect("verification settings")
                .doh_path
                .as_deref(),
            Some("/")
        );
    }

    #[test]
    fn parses_phase_four_e_thirteen_https_url_semantics() {
        for (url, port, credentials) in [
            (
                "https://127.0.0.1#name-cert-verify=dot.phase4.test",
                443,
                None,
            ),
            (
                "https://phase:secret@127.0.0.1:8443?legacy=1#name-cert-verify=dot.phase4.test",
                8443,
                Some("phase:secret"),
            ),
        ] {
            let source = format!(
                "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - {url}\n"
            );
            let dns = Config::from_yaml(&source)
                .expect("Phase 4E13 config")
                .dns
                .expect("DNS");
            assert_eq!(dns.upstream, SocketAddr::from(([127, 0, 0, 1], port)));
            let tls = dns.tls.expect("DoH settings");
            assert_eq!(tls.doh_path.as_deref(), Some("/"));
            assert_eq!(tls.doh_basic_credentials.as_deref(), credentials);
        }

        let encoded_userinfo = "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - https://ph%61se:secret@127.0.0.1#name-cert-verify=dot.phase4.test\n";
        assert!(matches!(
            Config::from_yaml(encoded_userinfo),
            Err(ConfigError::InvalidDns(message)) if message.contains("percent-encoded")
        ));
    }

    #[test]
    fn parses_phase_four_e_fourteen_domain_https_bootstrap_and_trust() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  default-nameserver:
    - udp://127.0.0.1:5354
  nameserver:
    - https://bootstrap.doh.phase4.test:8443/dns-query#skip-cert-verify=true&name-cert-verify=dot.phase4.test
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E14 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.transport, DnsTransport::HttpsVerifiedReuse);
        assert_eq!(dns.upstream, SocketAddr::from(([0, 0, 0, 0], 8443)));
        let tls = dns.tls.expect("DoH settings");
        assert_eq!(tls.server_name, "dot.phase4.test");
        assert_eq!(tls.tls_server_name, "bootstrap.doh.phase4.test");
        assert!(!tls.skip_certificate_verification);
        assert_eq!(
            tls.endpoint_host.as_deref(),
            Some("bootstrap.doh.phase4.test")
        );
        assert_eq!(
            tls.bootstrap.expect("bootstrap").address,
            SocketAddr::from(([127, 0, 0, 1], 5354))
        );

        let without_bootstrap =
            source.replace("  default-nameserver:\n    - udp://127.0.0.1:5354\n", "");
        assert!(matches!(
            Config::from_yaml(&without_bootstrap),
            Err(ConfigError::InvalidDns(message)) if message.contains("default-nameserver")
        ));
    }

    #[test]
    fn parses_phase_four_e_eight_encoded_unreserved_doh_path_subset() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - https://127.0.0.1:8443/custom/dns%2Dquery#name-cert-verify=dot.phase4.test
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E8 config")
            .dns
            .expect("DNS");
        assert_eq!(
            dns.tls.expect("verification settings").doh_path.as_deref(),
            Some("/custom/dns-query")
        );

        let encoded_slash = source.replace("dns%2Dquery", "dns%2Fquery");
        assert!(matches!(
            Config::from_yaml(&encoded_slash),
            Err(ConfigError::InvalidDns(message)) if message.contains("supported absolute path")
        ));
    }

    #[test]
    fn parses_phase_four_e_nine_domain_dot_bootstrap_and_default_port() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  default-nameserver:
    - udp://127.0.0.1:5354
  nameserver:
    - tls://bootstrap.dot.phase4.test#name-cert-verify=dot.phase4.test&disable-reuse=true
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E9 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.transport, DnsTransport::TlsVerifiedNoReuse);
        assert_eq!(dns.upstream, "0.0.0.0:853".parse().expect("sentinel"));
        let tls = dns.tls.expect("verification settings");
        assert_eq!(
            tls.endpoint_host.as_deref(),
            Some("bootstrap.dot.phase4.test")
        );
        assert_eq!(
            tls.bootstrap,
            Some(DnsUpstream {
                address: "127.0.0.1:5354".parse().expect("bootstrap"),
                transport: DnsTransport::Udp,
            })
        );

        let invalid = source.replace("udp://127.0.0.1:5354", "udp://bootstrap.invalid:5354");
        assert!(matches!(
            Config::from_yaml(&invalid),
            Err(ConfigError::InvalidDns(_))
        ));
    }

    #[test]
    fn parses_phase_four_e_seventeen_verified_doq() {
        let source = r"
tls:
  custom-certifactes:
    - |-
      -----BEGIN CERTIFICATE-----
      issuing-root
      -----END CERTIFICATE-----
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - quic://127.0.0.1:8853#name-cert-verify=dot.phase4.test
";
        let dns = Config::from_yaml(source)
            .expect("Phase 4E17 config")
            .dns
            .expect("DNS");
        assert_eq!(dns.transport, DnsTransport::QuicVerifiedReuse);
        assert_eq!(dns.upstream, "127.0.0.1:8853".parse().expect("address"));
        let tls = dns.tls.expect("verification settings");
        assert_eq!(tls.server_name, "dot.phase4.test");
        assert_eq!(tls.tls_server_name, "127.0.0.1");
        assert_eq!(tls.trust_certificates.len(), 1);

        let missing_name = source.replace("#name-cert-verify=dot.phase4.test", "");
        assert!(matches!(
            Config::from_yaml(&missing_name),
            Err(ConfigError::InvalidDns(message)) if message.contains("Phase 4E17")
        ));
    }

    #[test]
    fn parses_phase_four_e_nineteen_encrypted_query_options() {
        let source = r"
dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver:
    - quic://127.0.0.1:8853#name-cert-verify=dot.phase4.test&ecs=203.0.113.129/24&ecs-override=true&disable-ipv4=true&disable-ipv6=true&disable-qtype-65=true
";
        let options = Config::from_yaml(source)
            .expect("Phase 4E19 config")
            .dns
            .expect("DNS")
            .query_options;
        assert_eq!(options.disabled_types, vec![1, 28, 65]);
        assert_eq!(
            options.ecs,
            Some(EcsConfig {
                address: "203.0.113.129".parse().expect("address"),
                prefix: 24,
                override_existing: true,
            })
        );
    }

    #[test]
    fn applies_controller_cors_defaults_and_partial_overrides() {
        let defaults = Config::from_yaml(MINIMAL).expect("default controller CORS");
        assert_eq!(defaults.controller_cors.allow_origins, ["*"]);
        assert!(defaults.controller_cors.allow_private_network);

        let configured = Config::from_yaml(&format!(
            "{MINIMAL}\nexternal-controller-cors:\n  allow-origins:\n    - https://*.example.test\n"
        ))
        .expect("configured controller CORS");
        assert_eq!(
            configured.controller_cors.allow_origins,
            ["https://*.example.test"]
        );
        assert!(configured.controller_cors.allow_private_network);

        let disabled = Config::from_yaml(&format!(
            "{MINIMAL}\nexternal-controller-cors:\n  allow-origins: []\n  allow-private-network: false\n"
        ))
        .expect("empty origins retain Go allow-all behavior");
        assert!(disabled.controller_cors.allow_origins.is_empty());
        assert!(!disabled.controller_cors.allow_private_network);
    }

    #[test]
    fn expands_filtered_provider_members_in_pattern_order() {
        let provider = ProxyProviderConfig {
            name: "local-file".to_owned(),
            vehicle: ProxyProviderVehicle::File,
            path: PathBuf::from("provider.yaml"),
            url: None,
            interval: 0,
            headers: BTreeMap::new(),
            size_limit: 0,
            etag: None,
            proxies: ["provider-alpha", "provider-beta", "provider-omit"]
                .into_iter()
                .map(|name| ProxyConfig {
                    name: name.to_owned(),
                    kind: ProxyKind::Http,
                    server: "127.0.0.1".to_owned(),
                    port: 8080,
                    username: None,
                    password: None,
                })
                .collect(),
        };
        let group = ProxyGroupConfig {
            name: "filtered".to_owned(),
            kind: ProxyGroupKind::Select,
            proxies: Vec::new(),
            compatible_proxies: vec!["REJECT".to_owned()],
            providers: vec!["local-file".to_owned()],
            filter: Some("provider-beta`provider-alpha".to_owned()),
            exclude_filter: Some("omit".to_owned()),
            exclude_types: Vec::new(),
            empty_fallback: "DIRECT".to_owned(),
            default_selected: None,
            test_url: "https://www.gstatic.com/generate_204".to_owned(),
            expected_status: "*".to_owned(),
            hidden: false,
            icon: String::new(),
            disable_udp: false,
            tolerance: 0,
            health: GroupHealthConfig {
                interval: 0,
                timeout: 5000,
                lazy: true,
                max_failed_times: 5,
            },
            load_balance_strategy: None,
        };
        let types = proxy_member_types(&[], std::slice::from_ref(&provider), &BTreeMap::new());
        assert_eq!(
            expand_proxy_group(&group, &[provider], &types).expect("group expansion"),
            ["provider-beta", "provider-alpha", "REJECT"]
        );
    }

    #[test]
    fn filtered_empty_provider_uses_configured_fallback() {
        let provider = ProxyProviderConfig {
            name: "local-file".to_owned(),
            vehicle: ProxyProviderVehicle::File,
            path: PathBuf::from("provider.yaml"),
            url: None,
            interval: 0,
            headers: BTreeMap::new(),
            size_limit: 0,
            etag: None,
            proxies: vec![ProxyConfig {
                name: "provider-alpha".to_owned(),
                kind: ProxyKind::Http,
                server: "127.0.0.1".to_owned(),
                port: 8080,
                username: None,
                password: None,
            }],
        };
        let group = ProxyGroupConfig {
            name: "empty".to_owned(),
            kind: ProxyGroupKind::Select,
            proxies: Vec::new(),
            compatible_proxies: Vec::new(),
            providers: vec!["local-file".to_owned()],
            filter: Some("^missing$".to_owned()),
            exclude_filter: None,
            exclude_types: Vec::new(),
            empty_fallback: "REJECT".to_owned(),
            default_selected: Some("REJECT".to_owned()),
            test_url: "https://www.gstatic.com/generate_204".to_owned(),
            expected_status: "*".to_owned(),
            hidden: false,
            icon: String::new(),
            disable_udp: false,
            tolerance: 0,
            health: GroupHealthConfig {
                interval: 0,
                timeout: 5000,
                lazy: true,
                max_failed_times: 5,
            },
            load_balance_strategy: None,
        };
        let types = proxy_member_types(&[], std::slice::from_ref(&provider), &BTreeMap::new());
        assert_eq!(
            expand_proxy_group(&group, &[provider], &types).expect("empty fallback"),
            ["REJECT"]
        );
    }

    #[test]
    fn parses_and_populates_initial_http_proxy_provider() {
        let source = "mixed-port: 7890\nmode: rule\nlog-level: info\nipv6: false\nproxy-providers:\n  remote:\n    type: http\n    url: http://127.0.0.1:18080/provider.yaml\n    path: providers/remote.yaml\n    interval: 60\n    size-limit: 1024\n    header:\n      X-Phase: [first, second]\nproxy-groups:\n  - name: provider-group\n    type: select\n    proxies: [REJECT]\n    use: [remote]\nrules:\n  - MATCH,provider-group\n";
        let path = std::env::temp_dir().join("mihomo-http-provider-config.yaml");
        let config = Config::from_yaml_at_path_with_geodata_mode(source, &path, false)
            .expect("HTTP provider declaration");
        assert_eq!(
            config.proxy_providers[0].vehicle,
            ProxyProviderVehicle::Http
        );
        assert!(config.proxy_providers[0].proxies.is_empty());
        assert_eq!(config.proxy_providers[0].interval, 60);
        assert_eq!(config.proxy_providers[0].size_limit, 1024);
        assert_eq!(
            config.proxy_providers[0].headers["X-Phase"],
            ["first", "second"]
        );
        assert!(config.proxy_providers[0].etag.is_none());
        assert_eq!(config.proxy_groups[0].proxies, ["REJECT"]);

        let populated = config
            .replace_proxy_provider_source(
                "remote",
                "proxies:\n  - name: provider-http\n    type: http\n    server: 127.0.0.1\n    port: 8080\n",
            )
            .expect("downloaded provider payload");
        assert_eq!(
            populated.proxy_providers[0].proxies[0].name,
            "provider-http"
        );
        assert_eq!(
            populated.proxy_groups[0].proxies,
            ["REJECT", "provider-http"]
        );

        let provider_directory = std::env::temp_dir().join("mihomo-provider-home");
        let without_path = source.replace("    path: providers/remote.yaml\n", "");
        let defaulted = Config::from_yaml_at_path_with_provider_directory(
            &without_path,
            &path,
            &provider_directory,
            false,
        )
        .expect("default HTTP provider cache path");
        assert_eq!(
            defaulted.proxy_providers[0].path,
            provider_directory.join("proxies").join(format!(
                "{:x}",
                Md5::digest(b"http://127.0.0.1:18080/provider.yaml")
            ))
        );
    }

    #[test]
    fn accepts_forward_nested_groups_and_rejects_cycles() {
        let nested = Config::from_yaml(&format!(
            "{MINIMAL}\nproxy-groups:\n  - name: outer\n    type: select\n    proxies: [inner, DIRECT]\n  - name: inner\n    type: select\n    proxies: [REJECT, DIRECT]\n"
        ))
        .expect("forward nested groups");
        assert_eq!(nested.proxy_groups[0].proxies, ["inner", "DIRECT"]);

        let cycle = Config::from_yaml(&format!(
            "{MINIMAL}\nproxy-groups:\n  - name: cycle-a\n    type: select\n    proxies: [cycle-b]\n  - name: cycle-b\n    type: select\n    proxies: [cycle-a]\n"
        ));
        assert!(matches!(cycle, Err(ConfigError::UnsupportedProxy(_))));
    }
}
