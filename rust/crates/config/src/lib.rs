use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use ipnet::IpNet;
use rewrite_model::AuthUser;
use rewrite_rules::{RematchSpec, RuleError, RuleSet};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Global,
    Rule,
    Direct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
    pub interface_name: String,
    pub routing_mark: i64,
    pub tcp_concurrent: bool,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
    pub etag_support: bool,
    pub authentication: Vec<AuthUser>,
    pub external_controller: String,
    pub secret: String,
    pub store_fake_ip: bool,
    pub dns: Option<DnsConfig>,
    pub hosts: BTreeMap<String, HostEntry>,
    pub raw_rules: Vec<String>,
    pub raw_sub_rules: BTreeMap<String, Vec<String>>,
    pub rematches: Vec<RematchSpec>,
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
    pub authentication: Vec<AuthUser>,
    pub external_controller: String,
    pub secret: String,
    pub store_fake_ip: bool,
    pub dns: Option<DnsConfig>,
    pub hosts: BTreeMap<String, HostEntry>,
    pub rules: RuleSet,
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
pub enum FakeIpFilterMode {
    Blacklist,
    Whitelist,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeIpConfig {
    pub ipv4_range: Option<IpNet>,
    pub ipv6_range: Option<IpNet>,
    pub filter: Vec<String>,
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
    pub ipv6: bool,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub mode: DnsMode,
    pub fake_ip: Option<FakeIpConfig>,
    pub policies: Vec<DnsPolicy>,
    pub fallback: Option<DnsFallbackConfig>,
    pub direct: Option<DnsDirectConfig>,
    pub tls: Option<DnsTlsConfig>,
    pub query_options: DnsQueryOptions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsMainKind {
    Configured,
    System,
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
    pub upstream: DnsUpstream,
    pub domains: Vec<String>,
    pub ipcidr: Vec<IpNet>,
    pub lazy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsDirectConfig {
    pub upstream: DnsUpstream,
    pub follow_policy: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsPolicy {
    pub pattern: String,
    pub upstream: SocketAddr,
    pub transport: DnsTransport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEntry {
    Addresses(Vec<IpAddr>),
    Domain(String),
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
    interface_name: Option<String>,
    routing_mark: Option<i64>,
    tcp_concurrent: Option<bool>,
    keep_alive_idle: Option<i64>,
    keep_alive_interval: Option<i64>,
    disable_keep_alive: Option<bool>,
    etag_support: Option<bool>,
    authentication: Option<Vec<String>>,
    external_controller: Option<String>,
    secret: Option<String>,
    profile: Option<RawProfile>,
    tls: Option<RawTls>,
    dns: Option<RawDns>,
    hosts: Option<BTreeMap<String, RawHostValue>>,
    rules: Option<Vec<String>>,
    sub_rules: Option<BTreeMap<String, Vec<String>>>,
    proxies: Option<Vec<RawProxy>>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
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
    nameserver_policy: Option<BTreeMap<String, RawNameserverValue>>,
    fallback: Option<Vec<String>>,
    fallback_filter: Option<RawFallbackFilter>,
    fallback_lazy_query: Option<bool>,
    direct_nameserver: Option<Vec<String>>,
    direct_nameserver_follow_policy: Option<bool>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawFallbackFilter {
    geoip: Option<bool>,
    ipcidr: Option<Vec<String>>,
    domain: Option<Vec<String>>,
    geosite: Option<Vec<String>>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawNameserverValue {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawProfile {
    store_fake_ip: Option<bool>,
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
        let raw = serde_yaml_ng::from_str::<Option<RawConfig>>(source)?.unwrap_or_default();
        let mode = parse_mode(raw.mode.as_deref().unwrap_or("rule"))?;
        let log_level = parse_log_level(raw.log_level.as_deref().unwrap_or("info"))?;
        let raw_rules = raw.rules.unwrap_or_default();
        let raw_sub_rules = raw.sub_rules.unwrap_or_default();
        let rematches = parse_rematches(raw.proxies.unwrap_or_default())?;
        let rules = RuleSet::parse(&raw_rules, &raw_sub_rules, &rematches)?;
        let store_fake_ip = parse_profile(raw.profile)?;
        let trust_certificates = parse_tls(raw.tls)?;

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
            interface_name: raw.interface_name.unwrap_or_default(),
            routing_mark: raw.routing_mark.unwrap_or(0),
            tcp_concurrent: raw.tcp_concurrent.unwrap_or(false),
            keep_alive_idle: raw.keep_alive_idle.unwrap_or(0),
            keep_alive_interval: raw.keep_alive_interval.unwrap_or(0),
            disable_keep_alive: raw.disable_keep_alive.unwrap_or(false),
            etag_support: raw.etag_support.unwrap_or(true),
            authentication: parse_authentication(raw.authentication.unwrap_or_default()),
            external_controller: raw.external_controller.unwrap_or_default(),
            secret: raw.secret.unwrap_or_default(),
            store_fake_ip,
            dns: parse_dns(raw.dns, &trust_certificates)?,
            hosts: parse_hosts(raw.hosts.unwrap_or_default())?,
            raw_rules,
            raw_sub_rules,
            rematches,
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
        Self::from_yaml(&std::fs::read_to_string(path)?)
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
        let unsupported = [
            (spec.redir_port != 0, "redir-port"),
            (spec.tproxy_port != 0, "tproxy-port"),
            (spec.allow_lan, "allow-lan"),
            (spec.bind_address != "*", "bind-address"),
            (spec.mode != Mode::Rule, "mode"),
            (spec.unified_delay, "unified-delay"),
            (spec.log_level != LogLevel::Info, "log-level"),
            (!spec.interface_name.is_empty(), "interface-name"),
            (spec.routing_mark != 0, "routing-mark"),
            (spec.tcp_concurrent, "tcp-concurrent"),
            (spec.keep_alive_idle != 0, "keep-alive-idle"),
            (spec.keep_alive_interval != 0, "keep-alive-interval"),
            (spec.disable_keep_alive, "disable-keep-alive"),
            (!spec.etag_support, "etag-support"),
            (!spec.rematches.is_empty(), "rematch proxies"),
            (
                !spec.rules.is_phase_three_tcp(),
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
            authentication: spec.authentication,
            external_controller: spec.external_controller,
            secret: spec.secret,
            store_fake_ip: spec.store_fake_ip,
            dns: spec.dns,
            hosts: spec.hosts,
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

    /// Reads, parses and converts a configuration for the current runtime.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file, specification or runtime-scope errors.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        ConfigSpec::from_path(path)?.try_into()
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

fn parse_profile(raw: Option<RawProfile>) -> Result<bool, ConfigError> {
    let Some(raw) = raw else {
        return Ok(false);
    };
    if let Some(key) = raw.extra.into_keys().next() {
        return Err(ConfigError::UnsupportedKey(format!("profile.{key}")));
    }
    Ok(raw.store_fake_ip.unwrap_or(false))
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

    let fake_ip = parse_fake_ip_config(&mut raw, mode)?;

    let listen_text = raw
        .listen
        .take()
        .ok_or_else(|| ConfigError::InvalidDns("dns.listen is required".to_owned()))?;
    let listen = parse_loopback_dns_addr(&listen_text, "dns.listen")?;
    let nameservers = raw.nameserver.take().unwrap_or_default();
    if nameservers.is_empty() {
        return Err(ConfigError::InvalidDns(
            "at least one dns.nameserver is required".to_owned(),
        ));
    }
    let default_nameservers = raw.default_nameserver.take().unwrap_or_default();
    let main = parse_main_nameservers(
        &nameservers,
        &default_nameservers,
        raw.prefer_h3.unwrap_or(false),
        trust_certificates,
    )?;
    let policies = parse_dns_policies(raw.nameserver_policy.take().unwrap_or_default())?;
    let fallback = parse_fallback(&mut raw)?;
    let direct_servers = raw.direct_nameserver.take().unwrap_or_default();
    let direct =
        parse_optional_dns_upstream(&direct_servers, "dns.direct-nameserver", "Phase 4D3A")?.map(
            |upstream| DnsDirectConfig {
                upstream,
                follow_policy: raw.direct_nameserver_follow_policy.unwrap_or(false),
            },
        );
    Ok(Some(DnsConfig {
        listen,
        upstream: main.upstream,
        transport: main.transport,
        main_kind: main.main_kind,
        classic_upstreams: main.classic_upstreams,
        ipv6,
        use_hosts,
        use_system_hosts,
        mode,
        fake_ip,
        policies,
        fallback,
        direct,
        tls: main.tls,
        query_options: main.query_options,
    }))
}

struct ParsedMainNameservers {
    transport: DnsTransport,
    upstream: SocketAddr,
    main_kind: DnsMainKind,
    classic_upstreams: Vec<DnsClassicUpstream>,
    tls: Option<DnsTlsConfig>,
    query_options: DnsQueryOptions,
}

fn parse_main_nameservers(
    nameservers: &[String],
    default_nameservers: &[String],
    prefer_h3: bool,
    trust_certificates: &[String],
) -> Result<ParsedMainNameservers, ConfigError> {
    if nameservers.len() == 1 && matches!(nameservers[0].as_str(), "system" | "system://") {
        return Ok(ParsedMainNameservers {
            transport: DnsTransport::Udp,
            upstream: "0.0.0.0:53".parse().expect("system DNS sentinel"),
            main_kind: DnsMainKind::System,
            classic_upstreams: Vec::new(),
            tls: None,
            query_options: DnsQueryOptions::default(),
        });
    }
    let all_classic = nameservers
        .iter()
        .all(|server| server.starts_with("udp://") || server.starts_with("tcp://"));
    if all_classic {
        let bootstrap = parse_optional_dns_upstream(
            default_nameservers,
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
    let query_options = parse_dns_query_options(&nameservers[0])?;
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
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(ConfigError::InvalidDns(
                "Phase 4F2 classic upstream must contain only host and optional port".to_owned(),
            ));
        }
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
        };
        if !upstreams.contains(&upstream) {
            upstreams.push(upstream);
        }
    }
    Ok(upstreams)
}

fn is_dns_wrapper_parameter(name: &str) -> bool {
    matches!(
        name,
        "ecs" | "ecs-override" | "disable-ipv4" | "disable-ipv6"
    ) || name.starts_with("disable-qtype-")
}

fn parse_dns_query_options(value: &str) -> Result<DnsQueryOptions, ConfigError> {
    if !value.starts_with("tls://")
        && !value.starts_with("https://")
        && !value.starts_with("quic://")
    {
        return Ok(DnsQueryOptions::default());
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
        .map(|value| parse_ecs_config(value, parameters.get("ecs-override") == Some(&"true")))
        .transpose()?;
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
        {
            disabled_types.push(record_type);
        }
    }
    disabled_types.sort_unstable();
    disabled_types.dedup();
    Ok(DnsQueryOptions {
        ecs,
        disabled_types,
    })
}

fn parse_ecs_config(value: &str, override_existing: bool) -> Result<EcsConfig, ConfigError> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address = address.parse::<IpAddr>().map_err(|_| {
        ConfigError::InvalidDns("Phase 4E19 requires a valid ECS address or prefix".to_owned())
    })?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix
        .map(str::parse::<u8>)
        .transpose()
        .map_err(|_| ConfigError::InvalidDns("Phase 4E19 ECS prefix is invalid".to_owned()))?
        .unwrap_or(maximum);
    if prefix > maximum {
        return Err(ConfigError::InvalidDns(
            "Phase 4E19 ECS prefix exceeds its address width".to_owned(),
        ));
    }
    Ok(EcsConfig {
        address,
        prefix,
        override_existing,
    })
}

fn parse_main_dns_tls(
    parsed: ParsedDnsUpstream,
    prefer_h3: bool,
    default_nameservers: &[String],
    trust_certificates: &[String],
) -> Result<(DnsTransport, SocketAddr, Option<DnsTlsConfig>), ConfigError> {
    let domain_endpoint = parsed.endpoint_host.is_some();
    if !default_nameservers.is_empty()
        && !matches!(
            parsed.transport,
            DnsTransport::TlsVerifiedNoReuse
                | DnsTransport::TlsVerifiedReuse
                | DnsTransport::HttpsVerifiedReuse
        )
    {
        return Err(ConfigError::InvalidDns(
            "Phase 4E14 permits explicit dns.default-nameserver only with verified DoT or HTTPS DoH"
                .to_owned(),
        ));
    }
    let bootstrap =
        parse_optional_dns_upstream(default_nameservers, "dns.default-nameserver", "Phase 4E9")?;
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

fn parse_fallback(raw: &mut RawDns) -> Result<Option<DnsFallbackConfig>, ConfigError> {
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
    if filter.geoip.unwrap_or(true) {
        return Err(ConfigError::InvalidDns(
            "dns.fallback-filter.geoip must be false in Phase 4D2".to_owned(),
        ));
    }
    if filter.geosite.is_some_and(|entries| !entries.is_empty()) {
        return Err(ConfigError::InvalidDns(
            "dns.fallback-filter.geosite is outside Phase 4D2".to_owned(),
        ));
    }
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
    if servers.is_empty() {
        return Ok(None);
    }
    if servers.len() != 1 {
        return Err(ConfigError::InvalidDns(
            "Phase 4D2 requires exactly one dns.fallback upstream".to_owned(),
        ));
    }
    let parsed = parse_dns_upstream(&servers[0], "dns.fallback")?;
    debug_assert!(parsed.server_name.is_none());
    debug_assert!(parsed.doh_path.is_none());
    debug_assert!(parsed.doh_basic_credentials.is_none());
    debug_assert!(parsed.endpoint_host.is_none());
    Ok(Some(DnsFallbackConfig {
        upstream: DnsUpstream {
            address: parsed.address,
            transport: parsed.transport,
        },
        domains,
        ipcidr,
        lazy: raw.fallback_lazy_query.unwrap_or(false),
    }))
}

fn parse_dns_policies(
    raw: BTreeMap<String, RawNameserverValue>,
) -> Result<Vec<DnsPolicy>, ConfigError> {
    raw.into_iter()
        .map(|(pattern, value)| {
            let pattern = normalize_policy_pattern(&pattern)?;
            let servers = match value {
                RawNameserverValue::One(server) => vec![server],
                RawNameserverValue::Many(servers) => servers,
            };
            if servers.len() != 1 {
                return Err(ConfigError::InvalidDns(format!(
                    "dns.nameserver-policy {pattern} requires exactly one upstream in Phase 4D1"
                )));
            }
            let parsed = parse_dns_upstream(&servers[0], "dns.nameserver-policy")?;
            debug_assert!(parsed.server_name.is_none());
            debug_assert!(parsed.doh_path.is_none());
            debug_assert!(parsed.doh_basic_credentials.is_none());
            debug_assert!(parsed.endpoint_host.is_none());
            Ok(DnsPolicy {
                pattern,
                upstream: parsed.address,
                transport: parsed.transport,
            })
        })
        .collect()
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
        "rule" => {
            return Err(ConfigError::InvalidDns(
                "dns.fake-ip-filter-mode rule is outside Phase 4C".to_owned(),
            ));
        }
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
    let filter = filter
        .into_iter()
        .map(|name| {
            normalize_host_name(&name, "dns.fake-ip-filter").map_err(|error| {
                ConfigError::InvalidDns(format!("invalid dns.fake-ip-filter: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ttl = u32::try_from(raw.fake_ip_ttl.unwrap_or(1).max(1)).unwrap_or(u32::MAX);
    Ok(Some(FakeIpConfig {
        ipv4_range,
        ipv6_range,
        filter,
        filter_mode,
        ttl,
    }))
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

fn parse_hosts(
    raw: BTreeMap<String, RawHostValue>,
) -> Result<BTreeMap<String, HostEntry>, ConfigError> {
    let mut hosts = BTreeMap::from([(
        "localhost".to_owned(),
        HostEntry::Addresses(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]),
    )]);
    for (name, raw_value) in raw {
        let name = normalize_host_name(&name, "hosts key")?;
        let values = match raw_value {
            RawHostValue::One(value) => vec![value],
            RawHostValue::Many(values) => values,
        };
        if values.is_empty() {
            return Err(ConfigError::InvalidHosts(format!("{name} has no values")));
        }
        let entry = if values.len() == 1 {
            match values[0].parse::<IpAddr>() {
                Ok(address) => HostEntry::Addresses(vec![address.to_canonical()]),
                Err(_) => HostEntry::Domain(normalize_host_name(&values[0], "hosts target")?),
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

fn normalize_host_name(value: &str, field: &str) -> Result<String, ConfigError> {
    let value = value.trim_matches('.').to_lowercase();
    let valid = !value.is_empty()
        && (field != "hosts target" || value.contains('.'))
        && !value.starts_with("*.")
        && !value.starts_with("+.")
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(ConfigError::InvalidHosts(format!(
            "{field} is outside the exact-name Phase 4B subset"
        )));
    }
    Ok(value)
}

fn validate_host_cycles(hosts: &BTreeMap<String, HostEntry>) -> Result<(), ConfigError> {
    for origin in hosts.keys() {
        let mut seen = std::collections::BTreeSet::new();
        let mut current = origin.as_str();
        while let Some(HostEntry::Domain(next)) = hosts.get(current) {
            if !seen.insert(current.to_owned()) {
                return Err(ConfigError::InvalidHosts(format!(
                    "{origin} has a domain mapping cycle"
                )));
            }
            current = next;
        }
    }
    Ok(())
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

fn parse_rematches(proxies: Vec<RawProxy>) -> Result<Vec<RematchSpec>, ConfigError> {
    proxies
        .into_iter()
        .map(|proxy| {
            let name = proxy
                .name
                .filter(|name| !name.is_empty())
                .ok_or_else(|| ConfigError::UnsupportedProxy("missing name".to_owned()))?;
            if proxy.kind.as_deref().is_none_or(|kind| kind != "rematch") {
                return Err(ConfigError::UnsupportedProxy(name));
            }
            if !proxy.extra.is_empty() {
                return Err(ConfigError::UnsupportedProxy(name));
            }
            Ok(RematchSpec {
                name,
                target_rematch_name: proxy.target_rematch_name,
                target_sub_rule: proxy.target_sub_rule,
            })
        })
        .collect()
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
                }],
                ipv6: false,
                use_hosts: false,
                use_system_hosts: false,
                mode: DnsMode::RedirHost,
                fake_ip: None,
                policies: Vec::new(),
                fallback: None,
                direct: None,
                tls: None,
                query_options: DnsQueryOptions::default(),
            })
        );
    }

    #[test]
    fn parses_phase_four_f_three_system_resolver_spellings() {
        for nameserver in ["system", "system://"] {
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
        assert!(config.store_fake_ip);
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
            policy.pattern == "+.suffix.phase4.test" && policy.transport == DnsTransport::Tcp
        }));
        assert!(dns.policies.iter().any(|policy| {
            policy.pattern == "*.one.phase4.test" && policy.transport == DnsTransport::Udp
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
                upstream: DnsUpstream {
                    address: "127.0.0.1:25353".parse().expect("literal"),
                    transport: DnsTransport::Tcp,
                },
                domains: vec!["+.fallback.phase4.test".to_owned()],
                ipcidr: vec!["198.51.100.0/24".parse().expect("CIDR")],
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
                upstream: DnsUpstream {
                    address: "127.0.0.1:25353".parse().expect("literal"),
                    transport: DnsTransport::Tcp,
                },
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
}
