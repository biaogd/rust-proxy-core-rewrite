use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawConfig {
    pub(crate) port: Option<i64>,
    pub(crate) socks_port: Option<i64>,
    pub(crate) redir_port: Option<i64>,
    pub(crate) tproxy_port: Option<i64>,
    pub(crate) mixed_port: Option<i64>,
    pub(crate) ss_config: Option<String>,
    pub(crate) listeners: Option<Vec<Mapping>>,
    pub(crate) allow_lan: Option<bool>,
    pub(crate) bind_address: Option<String>,
    pub(crate) skip_auth_prefixes: Option<Vec<String>>,
    pub(crate) lan_allowed_ips: Option<Vec<String>>,
    pub(crate) lan_disallowed_ips: Option<Vec<String>>,
    pub(crate) inbound_tfo: Option<bool>,
    pub(crate) inbound_mptcp: Option<bool>,
    pub(crate) mode: Option<String>,
    pub(crate) unified_delay: Option<bool>,
    pub(crate) log_level: Option<String>,
    pub(crate) ipv6: Option<bool>,
    pub(crate) geodata_mode: Option<bool>,
    pub(crate) geodata_loader: Option<String>,
    pub(crate) geosite_matcher: Option<String>,
    pub(crate) geo_auto_update: Option<bool>,
    pub(crate) geo_update_interval: Option<i64>,
    pub(crate) geox_url: Option<RawGeoXUrls>,
    pub(crate) interface_name: Option<String>,
    pub(crate) routing_mark: Option<i64>,
    pub(crate) tcp_concurrent: Option<bool>,
    pub(crate) keep_alive_idle: Option<i64>,
    pub(crate) keep_alive_interval: Option<i64>,
    pub(crate) disable_keep_alive: Option<bool>,
    pub(crate) etag_support: Option<bool>,
    pub(crate) authentication: Option<Vec<String>>,
    pub(crate) external_controller: Option<String>,
    pub(crate) external_controller_tls: Option<String>,
    pub(crate) external_controller_unix: Option<String>,
    pub(crate) external_controller_pipe: Option<String>,
    pub(crate) external_controller_routing_mark: Option<i64>,
    pub(crate) external_ui: Option<String>,
    pub(crate) external_ui_url: Option<String>,
    pub(crate) external_ui_name: Option<String>,
    pub(crate) external_doh_server: Option<String>,
    pub(crate) secret: Option<String>,
    pub(crate) external_controller_cors: Option<RawControllerCors>,
    pub(crate) profile: Option<RawProfile>,
    pub(crate) ntp: Option<RawNtp>,
    pub(crate) tls: Option<RawTls>,
    pub(crate) dns: Option<RawDns>,
    pub(crate) hosts: Option<BTreeMap<String, RawHostValue>>,
    pub(crate) rules: Option<Vec<String>>,
    pub(crate) sub_rules: Option<BTreeMap<String, Vec<String>>>,
    pub(crate) proxies: Option<Vec<RawProxy>>,
    pub(crate) proxy_providers: Option<BTreeMap<String, RawProxyProvider>>,
    pub(crate) proxy_groups: Option<Vec<RawProxyGroup>>,
    pub(crate) rule_providers: Option<BTreeMap<String, RawRuleProvider>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawNtp {
    pub(crate) enable: Option<bool>,
    pub(crate) server: Option<String>,
    pub(crate) port: Option<i64>,
    pub(crate) interval: Option<i64>,
    pub(crate) dialer_proxy: Option<String>,
    pub(crate) write_to_system: Option<bool>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawGeoXUrls {
    #[serde(rename = "geoip")]
    pub(crate) geo_ip: Option<String>,
    pub(crate) mmdb: Option<String>,
    pub(crate) asn: Option<String>,
    #[serde(rename = "geosite")]
    pub(crate) geo_site: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawControllerCors {
    pub(crate) allow_origins: Option<Vec<String>>,
    pub(crate) allow_private_network: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawTls {
    pub(crate) certificate: Option<String>,
    pub(crate) private_key: Option<String>,
    pub(crate) client_auth_type: Option<String>,
    pub(crate) client_auth_cert: Option<String>,
    pub(crate) ech_key: Option<String>,
    pub(crate) custom_certifactes: Option<Vec<String>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum RawHostValue {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawDns {
    pub(crate) enable: Option<bool>,
    pub(crate) listen: Option<String>,
    pub(crate) ipv6: Option<bool>,
    pub(crate) ipv6_timeout: Option<i64>,
    pub(crate) cache_algorithm: Option<String>,
    pub(crate) cache_max_size: Option<i64>,
    pub(crate) prefer_h3: Option<bool>,
    pub(crate) use_hosts: Option<bool>,
    pub(crate) use_system_hosts: Option<bool>,
    pub(crate) enhanced_mode: Option<String>,
    pub(crate) fake_ip_range: Option<String>,
    pub(crate) fake_ip_range6: Option<String>,
    pub(crate) fake_ip_filter: Option<Vec<String>>,
    pub(crate) fake_ip_filter_mode: Option<String>,
    pub(crate) fake_ip_ttl: Option<i64>,
    pub(crate) default_nameserver: Option<Vec<String>>,
    pub(crate) nameserver: Option<Vec<String>>,
    pub(crate) nameserver_policy: Option<Mapping>,
    pub(crate) fallback: Option<Vec<String>>,
    pub(crate) fallback_filter: Option<RawFallbackFilter>,
    pub(crate) fallback_lazy_query: Option<bool>,
    pub(crate) direct_nameserver: Option<Vec<String>>,
    pub(crate) direct_nameserver_follow_policy: Option<bool>,
    pub(crate) proxy_server_nameserver: Option<Vec<String>>,
    pub(crate) proxy_server_nameserver_policy: Option<Mapping>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawFallbackFilter {
    pub(crate) geoip: Option<bool>,
    pub(crate) geoip_code: Option<String>,
    pub(crate) ipcidr: Option<Vec<String>>,
    pub(crate) domain: Option<Vec<String>>,
    pub(crate) geosite: Option<Vec<String>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawRuleProvider {
    #[serde(rename = "type")]
    pub(crate) kind: Option<String>,
    pub(crate) behavior: Option<String>,
    pub(crate) format: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) interval: Option<u64>,
    pub(crate) header: Option<BTreeMap<String, Vec<String>>>,
    pub(crate) size_limit: Option<usize>,
    pub(crate) proxy: Option<String>,
    pub(crate) payload: Option<Vec<String>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawRuleProviderFile {
    pub(crate) payload: Option<Vec<String>>,
    pub(crate) rules: Option<Vec<String>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawProfile {
    pub(crate) store_fake_ip: Option<bool>,
    pub(crate) store_selected: Option<bool>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawProxy {
    pub(crate) name: Option<String>,
    #[serde(rename = "type")]
    pub(crate) kind: Option<String>,
    pub(crate) target_rematch_name: Option<String>,
    pub(crate) target_sub_rule: Option<String>,
    pub(crate) server: Option<String>,
    pub(crate) port: Option<i64>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) cipher: Option<String>,
    pub(crate) uuid: Option<String>,
    pub(crate) flow: Option<String>,
    pub(crate) encryption: Option<String>,
    #[serde(rename = "alterId", alias = "alter-id")]
    pub(crate) alter_id: Option<i64>,
    pub(crate) network: Option<String>,
    pub(crate) global_padding: Option<bool>,
    pub(crate) authenticated_length: Option<bool>,
    pub(crate) tls: Option<bool>,
    pub(crate) udp: Option<bool>,
    pub(crate) packet_addr: Option<bool>,
    pub(crate) xudp: Option<bool>,
    pub(crate) packet_encoding: Option<String>,
    pub(crate) ws_opts: Option<RawVmessWebSocketOptions>,
    pub(crate) http_opts: Option<RawVmessHttpOptions>,
    pub(crate) h2_opts: Option<RawVmessHttp2Options>,
    pub(crate) grpc_opts: Option<RawVmessGrpcOptions>,
    pub(crate) xhttp_opts: Option<RawXHttpOptions>,
    pub(crate) mkcp_opts: Option<RawVmessMkcpOptions>,
    pub(crate) mekya_opts: Option<RawVmessMekyaOptions>,
    pub(crate) udp_over_tcp: Option<bool>,
    pub(crate) udp_over_tcp_version: Option<i64>,
    pub(crate) plugin: Option<String>,
    pub(crate) plugin_opts: Option<BTreeMap<String, Value>>,
    #[serde(alias = "servername")]
    pub(crate) sni: Option<String>,
    pub(crate) skip_cert_verify: Option<bool>,
    pub(crate) name_cert_verify: Option<String>,
    pub(crate) fingerprint: Option<String>,
    pub(crate) certificate: Option<String>,
    pub(crate) private_key: Option<String>,
    #[serde(rename = "client-fingerprint")]
    pub(crate) client_fingerprint: Option<String>,
    #[serde(rename = "reality-opts")]
    pub(crate) reality_opts: Option<RawRealityOptions>,
    pub(crate) headers: Option<BTreeMap<String, String>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawRealityOptions {
    #[serde(rename = "public-key")]
    pub(crate) public_key: Option<String>,
    #[serde(rename = "short-id")]
    pub(crate) short_id: Option<String>,
    pub(crate) support_x25519mlkem768: Option<bool>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawVmessWebSocketOptions {
    pub(crate) path: Option<String>,
    pub(crate) headers: Option<BTreeMap<String, String>>,
    pub(crate) max_early_data: Option<i64>,
    pub(crate) early_data_header_name: Option<String>,
    pub(crate) v2ray_http_upgrade: Option<bool>,
    pub(crate) v2ray_http_upgrade_fast_open: Option<bool>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawVmessHttpOptions {
    pub(crate) method: Option<String>,
    pub(crate) path: Option<Vec<String>>,
    pub(crate) headers: Option<BTreeMap<String, Vec<String>>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawVmessHttp2Options {
    pub(crate) host: Option<Vec<String>>,
    pub(crate) path: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawVmessGrpcOptions {
    pub(crate) grpc_service_name: Option<String>,
    pub(crate) grpc_user_agent: Option<String>,
    pub(crate) ping_interval: Option<i64>,
    pub(crate) max_connections: Option<i64>,
    pub(crate) min_streams: Option<i64>,
    pub(crate) max_streams: Option<i64>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawXHttpOptions {
    pub(crate) path: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) mode: Option<String>,
    pub(crate) headers: Option<BTreeMap<String, String>>,
    pub(crate) no_grpc_header: Option<bool>,
    pub(crate) x_padding_bytes: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawVmessMkcpOptions {
    pub(crate) mtu: Option<i64>,
    pub(crate) tti: Option<i64>,
    pub(crate) uplink_capacity: Option<i64>,
    pub(crate) downlink_capacity: Option<i64>,
    pub(crate) congestion: Option<bool>,
    pub(crate) write_buffer: Option<i64>,
    pub(crate) read_buffer: Option<i64>,
    pub(crate) seed: Option<String>,
    pub(crate) header: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawVmessMekyaOptions {
    pub(crate) url: Option<String>,
    pub(crate) h2_pool_size: Option<i64>,
    pub(crate) max_write_delay: Option<i64>,
    pub(crate) max_request_size: Option<i64>,
    pub(crate) polling_interval_initial: Option<i64>,
    pub(crate) max_write_size: Option<i64>,
    pub(crate) max_write_duration_ms: Option<i64>,
    pub(crate) max_simultaneous_write_connection: Option<i64>,
    pub(crate) packet_writing_buffer: Option<i64>,
    pub(crate) kcp: Option<RawVmessMkcpOptions>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawProxyGroup {
    pub(crate) name: Option<String>,
    #[serde(rename = "type")]
    pub(crate) kind: Option<String>,
    pub(crate) strategy: Option<String>,
    pub(crate) proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub(crate) providers: Option<Vec<String>>,
    pub(crate) filter: Option<String>,
    pub(crate) exclude_filter: Option<String>,
    pub(crate) exclude_type: Option<String>,
    pub(crate) include_all: Option<bool>,
    pub(crate) include_all_proxies: Option<bool>,
    pub(crate) include_all_providers: Option<bool>,
    pub(crate) empty_fallback: Option<String>,
    pub(crate) default_selected: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) expected_status: Option<String>,
    pub(crate) hidden: Option<bool>,
    pub(crate) icon: Option<String>,
    pub(crate) disable_udp: Option<bool>,
    pub(crate) tolerance: Option<u16>,
    pub(crate) interval: Option<u64>,
    pub(crate) timeout: Option<u64>,
    pub(crate) lazy: Option<bool>,
    pub(crate) max_failed_times: Option<u64>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawProxyProvider {
    #[serde(rename = "type")]
    pub(crate) kind: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) interval: Option<u64>,
    pub(crate) header: Option<BTreeMap<String, Vec<String>>>,
    pub(crate) size_limit: Option<usize>,
    pub(crate) filter: Option<String>,
    pub(crate) exclude_filter: Option<String>,
    pub(crate) exclude_type: Option<String>,
    pub(crate) payload: Option<Vec<RawProxy>>,
    pub(crate) health_check: Option<RawProviderHealthCheck>,
    #[serde(rename = "override")]
    pub(crate) overrides: Option<RawProxyProviderOverride>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawProviderHealthCheck {
    pub(crate) enable: Option<bool>,
    pub(crate) url: Option<String>,
    pub(crate) interval: Option<u64>,
    pub(crate) timeout: Option<u64>,
    pub(crate) lazy: Option<bool>,
    pub(crate) expected_status: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawProxyProviderOverride {
    pub(crate) additional_prefix: Option<String>,
    pub(crate) additional_suffix: Option<String>,
    pub(crate) proxy_name: Option<Vec<RawProxyNameReplacement>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawProxyNameReplacement {
    pub(crate) pattern: String,
    pub(crate) target: String,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawProxyProviderFile {
    pub(crate) proxies: Option<Vec<RawProxy>>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProviderEtagCache {
    pub(crate) url: String,
    pub(crate) digest: String,
    pub(crate) etag: String,
}
