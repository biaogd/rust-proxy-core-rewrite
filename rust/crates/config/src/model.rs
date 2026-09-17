use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

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
    pub trojan_listeners: Vec<TrojanInboundConfig>,
    pub vless_listeners: Vec<VlessInboundConfig>,
    pub vmess_listeners: Vec<VmessInboundConfig>,
    pub hysteria2_listeners: Vec<Hysteria2InboundConfig>,
    pub tuic_listeners: Vec<TuicInboundConfig>,
    pub anytls_listeners: Vec<AnyTlsInboundConfig>,
    pub tunnel_listeners: Vec<TunnelInboundConfig>,
    pub tun: Option<TunConfig>,
    pub sniffer: SnifferConfig,
    pub find_process_mode: FindProcessMode,
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
    pub redir_port: i64,
    pub tproxy_port: i64,
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
    pub trojan_listeners: Vec<TrojanInboundConfig>,
    pub vless_listeners: Vec<VlessInboundConfig>,
    pub vmess_listeners: Vec<VmessInboundConfig>,
    pub hysteria2_listeners: Vec<Hysteria2InboundConfig>,
    pub tuic_listeners: Vec<TuicInboundConfig>,
    pub anytls_listeners: Vec<AnyTlsInboundConfig>,
    pub tunnel_listeners: Vec<TunnelInboundConfig>,
    pub tun: Option<TunConfig>,
    pub sniffer: SnifferConfig,
    pub find_process_mode: FindProcessMode,
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
    Trojan,
    AnyTls,
    Hysteria2,
    ShadowsocksR,
    Direct,
    Reject,
    Dns,
    Rematch,
    Tuic,
    WireGuard,
    Snell,
    Ssh,
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
    pub trojan: Option<TrojanProxyConfig>,
    pub anytls: Option<AnyTlsProxyConfig>,
    pub hysteria2: Option<Hysteria2ProxyConfig>,
    pub tuic: Option<TuicProxyConfig>,
    pub ssr: Option<SsrProxyConfig>,
    pub wireguard: Option<WireGuardProxyConfig>,
    pub snell: Option<SnellProxyConfig>,
    pub ssh: Option<SshProxyConfig>,
    /// Optional upstream used only to reach this proxy's `server:port`.
    ///
    /// Empty / `None` keeps the historical DIRECT dial. Phase 7T1-A accepts
    /// the field on TCP leaf adapters; SSH and UDP-server protocols reject it.
    pub dialer_proxy: Option<String>,
    pub headers: BTreeMap<String, String>,
}

/// Clash `type: ssr` options accepted in SSR-A/B.
///
/// `auth_sha1_v4`, `auth_chain_*`, `random_head`, UDP, AEAD/SS2022, and other
/// stream ciphers remain rejected until later SSR phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsrProxyConfig {
    pub protocol: String,
    pub protocol_param: String,
    pub obfs: String,
    pub obfs_param: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsProxyConfig {
    pub password: String,
    pub alpn: Vec<String>,
    pub client_metadata: String,
    pub idle_session_check_interval: u64,
    pub idle_session_timeout: u64,
    pub min_idle_session: usize,
    pub disable_reuse: bool,
    /// Outer security carrier replacing native TLS when set (Go-compatible).
    pub carrier: AnyTlsCarrier,
}

/// Clash `type: wireguard` options accepted in 6I-C (single-peer TCP+UDP).
///
/// `AmneziaWG`, `peers`, `ip-stack`, `dialer-proxy` and `workers` remain
/// rejected. Empty `peers` still implies `allowed_ip=0.0.0.0/0` and `::/0`
/// from the configured inner families.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardProxyConfig {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub local_addr: Ipv4Addr,
    pub local_prefix_len: u8,
    pub local_ipv6: Option<(Ipv6Addr, u8)>,
    /// `0` means the Go/Clash default `1408`.
    pub mtu: u16,
    pub persistent_keepalive: Option<u16>,
    pub reserved: [u8; 3],
    pub allowed_ips: Vec<String>,
    pub remote_dns_resolve: bool,
    pub dns_servers: Vec<String>,
    /// Seconds; `0` means resolve the peer hostname only at first connect (Go).
    pub refresh_server_ip_interval: u64,
}

/// Clash `type: snell` options accepted in 7E-A/B/C/D (versions 1–3 TCP, v3 UDP,
/// simple-obfs HTTP/TLS, v2 `ConnectV2` reuse).
///
/// Remaining `obfs-opts` (shadow-tls/restls/jls), v4/v5 and inbound remain
/// rejected. `dialer-proxy` is accepted for TCP; combining it with `udp: true`
/// fails closed in 7T1-A. `reuse: true` is stored on any version; pooling is
/// only enabled when `version == 2` (Go: v2 always pools).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnellProxyConfig {
    pub psk: String,
    /// Clash `version`. Omitted or `0` is stored as `1` (Go `DefaultSnellVersion`).
    pub version: u8,
    pub obfs: Option<SnellObfs>,
    /// Clash `reuse`. Accepted on any version; pooling is v2-only.
    pub reuse: bool,
}

/// Clash `obfs-opts` modes accepted in 7E-C. Host defaults to `bing.com` (Go).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnellObfs {
    Http { host: String },
    Tls { host: String },
}

/// Clash `type: ssh` options accepted in 6J-A/B (TCP outbound, session reuse).
///
/// UDP, `dialer-proxy`, TFO/MPTCP and inbound remain rejected. Host-key
/// algorithms are applied at handshake; transport keepalive comes from the
/// global config, not these fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshProxyConfig {
    pub username: String,
    pub password: Option<String>,
    /// Inline PEM or a home-resolved filesystem path.
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    /// `authorized_keys` lines for the SSH server host key.
    pub host_keys: Vec<String>,
    pub host_key_algorithms: Vec<String>,
}

/// Clash `type: tuic` options accepted in 6H-A/B (v5 TCP + UDP outbound).
///
/// v4 `token`, `reduce-rtt` / 0-RTT, ECH, UDP-over-stream, Brutal/`cwnd` /
/// `bbr-profile`, client certificates and inbound remain rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicProxyConfig {
    pub uuid: [u8; 16],
    pub password: String,
    pub alpn: Vec<String>,
    pub congestion_controller: String,
    pub udp_relay_mode: String,
    pub request_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub max_open_streams: u64,
    pub disable_sni: bool,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    /// YAML `max-udp-relay-packet-size`; `0` means Go's default 1252 before caps.
    pub max_udp_relay_packet_size: u64,
}

/// Clash `type: hysteria2` options accepted in HY2-B (TCP + UDP outbound).
///
/// Gecko obfs, Realm, ECH, `cwnd` / `bbr-profile`, client cert / fingerprint,
/// dialer-proxy, and MTU-discovery overrides remain rejected until later phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2ProxyConfig {
    pub password: String,
    pub alpn: Vec<String>,
    pub disable_reuse: bool,
    pub up_bps: u64,
    pub down_bps: u64,
    /// `"salamander"` when set; `None` means cleartext QUIC.
    pub obfs: Option<String>,
    pub obfs_password: String,
    pub hop_ports: Vec<u16>,
    pub hop_interval_min_secs: u64,
    pub hop_interval_max_secs: u64,
    /// Default `1197` when unset / zero in YAML.
    pub udp_mtu: u16,
    /// Milliseconds; `0` means client default (`10000`).
    pub handshake_timeout_ms: u64,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
}

/// Clash `shadow-tls-opts` / `restls-opts` / `jls-opts` (mutually exclusive).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnyTlsCarrier {
    NativeTls,
    ShadowTls {
        password: String,
        version: u8,
    },
    Restls {
        password: String,
        version_hint: String,
        restls_script: String,
    },
    Jls {
        username: String,
        password: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanProxyConfig {
    pub password: String,
    /// Precomputed SHA-224 hex key (Go `hexPassword`); avoids hashing every dial.
    pub password_key: [u8; 56],
    pub alpn: Vec<String>,
    pub transport: TrojanTransport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrojanTransport {
    Tcp,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunStack {
    Smoltcp,
}

// First-round TUN surface for Phase 8A. Deferred Go-only knobs — including
// `strict-route`, `endpoint-independent-nat`, `udp-timeout`, and
// `disable-icmp-forwarding` — are rejected at parse time rather than stored
// and silently ignored. Omitted / false / 0 remain accepted defaults.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunConfig {
    pub enable: bool,
    pub device: String,
    pub stack: TunStack,
    pub dns_hijack: Vec<String>,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub mtu: u32,
    pub inet4_address: Vec<IpNet>,
    pub inet6_address: Vec<IpNet>,
    pub route_address: Vec<IpNet>,
    pub route_exclude_address: Vec<IpNet>,
    pub inet4_route_address: Vec<IpNet>,
    pub inet6_route_address: Vec<IpNet>,
    pub inet4_route_exclude_address: Vec<IpNet>,
    pub inet6_route_exclude_address: Vec<IpNet>,
    pub strict_route: bool,
    pub endpoint_independent_nat: bool,
    pub udp_timeout: i64,
    pub file_descriptor: i64,
    pub disable_icmp_forwarding: bool,
}

impl TunStack {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smoltcp => "smoltcp",
        }
    }
}

impl TunConfig {
    /// Go uses `Inet4Address[0].Addr().Next()` as the TUN DNS / Darwin system DNS.
    #[must_use]
    pub fn tun_dns_server(&self) -> Option<IpAddr> {
        match self.inet4_address.first().map(IpNet::addr)? {
            IpAddr::V4(address) => Some(IpAddr::V4(Ipv4Addr::from(
                u32::from(address).wrapping_add(1),
            ))),
            IpAddr::V6(_) => None,
        }
    }

    /// Returns true when `destination` matches a configured `dns-hijack` entry
    /// or the TUN DNS next address (port 53).
    #[must_use]
    pub fn hijacks_dns(&self, destination: SocketAddr) -> bool {
        if self
            .dns_hijack
            .iter()
            .any(|entry| dns_hijack_matches(entry, destination))
        {
            return true;
        }
        self.tun_dns_server()
            .is_some_and(|dns| destination.ip() == dns && destination.port() == 53)
    }
}

fn dns_hijack_matches(entry: &str, destination: SocketAddr) -> bool {
    let trimmed = entry.trim();
    if trimmed.eq_ignore_ascii_case("any") {
        return destination.port() == 53;
    }
    if let Ok(address) = trimmed.parse::<std::net::IpAddr>() {
        return wildcard_or_exact_ip(address, destination.ip()) && destination.port() == 53;
    }
    if let Ok(socket) = trimmed.parse::<SocketAddr>() {
        return wildcard_or_exact_ip(socket.ip(), destination.ip())
            && socket.port() == destination.port();
    }
    if let Some((host, port)) = trimmed.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
        && let Ok(address) = host.parse::<std::net::IpAddr>()
    {
        return wildcard_or_exact_ip(address, destination.ip()) && port == destination.port();
    }
    false
}

fn wildcard_or_exact_ip(configured: std::net::IpAddr, actual: std::net::IpAddr) -> bool {
    match configured {
        std::net::IpAddr::V4(address) if address.is_unspecified() => actual.is_ipv4(),
        std::net::IpAddr::V6(address) if address.is_unspecified() => actual.is_ipv6(),
        other => other == actual,
    }
}

/// Go `find-process-mode` (default `strict`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FindProcessMode {
    Always,
    #[default]
    Strict,
    Off,
}

impl FindProcessMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Strict => "strict",
            Self::Off => "off",
        }
    }
}

/// Top-level `sniffer:` runtime policy (CFG-16).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnifferConfig {
    pub enable: bool,
    pub force_dns_mapping: bool,
    pub parse_pure_ip: bool,
    pub protocols: BTreeMap<SniffProtocol, SnifferProtocolConfig>,
    pub force_domain: Vec<SnifferDomainMatcher>,
    pub skip_domain: Vec<SnifferDomainMatcher>,
    pub skip_src_address: Vec<IpNet>,
    pub skip_dst_address: Vec<IpNet>,
}

impl SnifferConfig {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enable: false,
            force_dns_mapping: true,
            parse_pure_ip: true,
            protocols: BTreeMap::new(),
            force_domain: Vec::new(),
            skip_domain: Vec::new(),
            skip_src_address: Vec::new(),
            skip_dst_address: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SniffProtocol {
    Tls,
    Http,
    Quic,
}

impl SniffProtocol {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "TLS",
            Self::Http => "HTTP",
            Self::Quic => "QUIC",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnifferProtocolConfig {
    /// Inclusive port ranges. Empty means protocol defaults (TLS/QUIC 443, HTTP 80).
    pub ports: Vec<(u16, u16)>,
    pub override_destination: bool,
}

impl SnifferProtocolConfig {
    #[must_use]
    pub fn supports_port(&self, port: u16, protocol: SniffProtocol) -> bool {
        if self.ports.is_empty() {
            return match protocol {
                SniffProtocol::Tls | SniffProtocol::Quic => port == 443,
                SniffProtocol::Http => port == 80,
            };
        }
        self.ports
            .iter()
            .any(|&(start, end)| port >= start && port <= end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnifferDomainMatcher {
    Exact(String),
    Suffix(String),
    Wildcard(String),
}

impl SnifferDomainMatcher {
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        match self {
            Self::Exact(value) => host == *value,
            Self::Suffix(suffix) => {
                host == *suffix
                    || host
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            Self::Wildcard(pattern) => domain_wildcard_matches(pattern, &host),
        }
    }
}

fn domain_wildcard_matches(pattern: &str, host: &str) -> bool {
    // Minimal `*` glob: one `*` matches any run of labels/chars.
    let Some((left, right)) = pattern.split_once('*') else {
        return pattern == host;
    };
    if pattern.matches('*').count() != 1 {
        return false;
    }
    host.starts_with(left) && host.ends_with(right) && host.len() >= left.len() + right.len()
}

/// One expanded static tunnel listener (`tunnels:` entry × network).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelInboundConfig {
    pub listen: SocketAddr,
    pub target: rewrite_model::Destination,
    pub network: TunnelNetwork,
    pub proxy: String,
}

impl TunnelInboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "{}/{}/{}",
            self.network.as_str(),
            self.target.authority(),
            self.proxy
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelNetwork {
    Tcp,
    Udp,
}

impl TunnelNetwork {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanInboundUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrojanInboundConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub users: Vec<TrojanInboundUser>,
    pub certificate: String,
    pub private_key: String,
    /// When set, clients must WebSocket-upgrade on this path before Trojan bytes.
    pub ws_path: Option<String>,
    /// When set, clients must open a Gun/gRPC stream on this service before Trojan bytes.
    pub grpc_service_name: Option<String>,
}

impl TrojanInboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "name={}|listen={}|users={:?}|certificate={}|private-key={}|ws-path={}|grpc-service-name={}",
            self.name,
            self.listen,
            self.users,
            self.certificate,
            self.private_key,
            self.ws_path.as_deref().unwrap_or(""),
            self.grpc_service_name.as_deref().unwrap_or("")
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessInboundUser {
    pub username: String,
    pub uuid: String,
    pub flow: Option<VlessFlow>,
}

/// Named `reality-config` for VLESS REALITY inbound (mutually exclusive with PEM TLS).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealityInboundConfig {
    /// Camouflage dial target (`host:port`); required for Go parity, used later for fallback.
    pub dest: String,
    /// X25519 private key (32 bytes).
    pub private_key: [u8; 32],
    /// Accepted short IDs (at most 8 bytes each, zero-padded).
    pub short_ids: Vec<[u8; 8]>,
    /// Accepted TLS SNI values.
    pub server_names: Vec<String>,
    /// Optional absolute timestamp skew bound (from `max-time-difference` microseconds).
    pub max_time_difference: Option<Duration>,
    /// Optional inner dialer proxy name for dest fallback (stored; dial path TBD).
    pub proxy: Option<String>,
}

/// Named `type: vless` TLS inbound accepted in IN-D.
///
/// Optional `ws-path` / `grpc-service-name` select the Trojan-style carriers.
/// Per-user `flow: xtls-rprx-vision` is accepted on certificate TLS.
/// `reality-config` selects REALITY (XOR with `certificate` / `private-key`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessInboundConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub users: Vec<VlessInboundUser>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub reality: Option<RealityInboundConfig>,
    /// When set, clients must WebSocket-upgrade on this path before VLESS bytes.
    pub ws_path: Option<String>,
    /// When set, clients must open a Gun/gRPC stream on this service before VLESS bytes.
    pub grpc_service_name: Option<String>,
}

impl VlessInboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "name={}|listen={}|users={:?}|certificate={}|private-key={}|reality={:?}|ws-path={}|grpc-service-name={}",
            self.name,
            self.listen,
            self.users,
            self.certificate.as_deref().unwrap_or(""),
            self.private_key.as_deref().unwrap_or(""),
            self.reality,
            self.ws_path.as_deref().unwrap_or(""),
            self.grpc_service_name.as_deref().unwrap_or("")
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessInboundUser {
    pub username: String,
    pub uuid: String,
}

/// Named `type: vmess` TLS inbound accepted in IN-E.
///
/// AEAD only (`alterId` must be absent or `0`). Optional `ws-path` /
/// `grpc-service-name` select the Trojan-style carriers (not both).
/// Plain TLS (`certificate` + `private-key`) is required; Reality/mKCP/Mekya
/// stay rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessInboundConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub users: Vec<VmessInboundUser>,
    pub certificate: String,
    pub private_key: String,
    /// When set, clients must WebSocket-upgrade on this path before VMess bytes.
    pub ws_path: Option<String>,
    /// When set, clients must open a Gun/gRPC stream on this service before VMess bytes.
    pub grpc_service_name: Option<String>,
}

impl VmessInboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "name={}|listen={}|users={:?}|certificate={}|private-key={}|ws-path={}|grpc-service-name={}",
            self.name,
            self.listen,
            self.users,
            self.certificate,
            self.private_key,
            self.ws_path.as_deref().unwrap_or(""),
            self.grpc_service_name.as_deref().unwrap_or("")
        )
    }
}

/// Named `type: hysteria2` QUIC inbound accepted in IN-F (first slice).
///
/// Clash-style `users` is name→password. Optional Salamander obfs; stock BBR.
/// Realm/gecko/ECH/masquerade/Brutal knobs stay rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2InboundUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2InboundConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub users: Vec<Hysteria2InboundUser>,
    pub certificate: String,
    pub private_key: String,
    /// ALPN list; empty means default `["h3"]` at runtime.
    pub alpn: Vec<String>,
    /// When set, Salamander obfuscation PSK (`obfs: salamander`).
    pub obfs_password: Option<String>,
}

impl Hysteria2InboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "name={}|listen={}|users={:?}|certificate={}|private-key={}|alpn={:?}|obfs-password={}",
            self.name,
            self.listen,
            self.users,
            self.certificate,
            self.private_key,
            self.alpn,
            self.obfs_password.as_deref().unwrap_or("")
        )
    }
}

/// Named `type: tuic` QUIC inbound accepted in IN-F (TUIC v5 slice).
///
/// Clash-style `users` is uuid→password. v4 `token`, ECH, client-auth, Brutal/`cwnd`
/// stay rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicInboundUser {
    pub uuid: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicInboundConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub users: Vec<TuicInboundUser>,
    pub certificate: String,
    pub private_key: String,
    /// ALPN list; empty means default `["h3"]` at runtime.
    pub alpn: Vec<String>,
    /// `cubic` (default), `bbr`, or `new_reno`.
    pub congestion_controller: String,
    /// Idle timeout in milliseconds (Go default 15000).
    pub max_idle_time_ms: u64,
    /// Auth timeout in milliseconds (Go default 1000).
    pub authentication_timeout_ms: u64,
    /// Clash `max-udp-relay-packet-size` (0 = Go default path).
    pub max_udp_relay_packet_size: u64,
}

impl TuicInboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "name={}|listen={}|users={:?}|certificate={}|private-key={}|alpn={:?}|cc={}|idle={}|auth-timeout={}|udp-pkt={}",
            self.name,
            self.listen,
            self.users,
            self.certificate,
            self.private_key,
            self.alpn,
            self.congestion_controller,
            self.max_idle_time_ms,
            self.authentication_timeout_ms,
            self.max_udp_relay_packet_size
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsInboundUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsInboundConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub users: Vec<AnyTlsInboundUser>,
    pub certificate: String,
    pub private_key: String,
    /// Optional padding scheme; empty/`None` means Go default at bind.
    pub padding_scheme: Option<String>,
}

impl AnyTlsInboundConfig {
    /// Stable identity used to decide whether a reload must rebind this inbound.
    #[must_use]
    pub fn reload_identity(&self) -> String {
        format!(
            "name={}|listen={}|users={:?}|certificate={}|private-key={}|padding={:?}",
            self.name,
            self.listen,
            self.users,
            self.certificate,
            self.private_key,
            self.padding_scheme
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ListenerKind {
    Http,
    Socks,
    Mixed,
    Redir,
    Tproxy,
    Tunnel,
    Shadowsocks,
    Trojan,
    Vless,
    Vmess,
    Hysteria2,
    Tuic,
    AnyTls,
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
