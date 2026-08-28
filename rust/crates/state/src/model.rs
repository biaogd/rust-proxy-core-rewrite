use std::collections::BTreeMap;

use rewrite_model::{Host, InboundProtocol, Metadata, Network};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataSnapshot {
    pub network: String,
    #[serde(rename = "type")]
    pub inbound_type: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(rename = "sourceGeoIP")]
    pub source_geo_ip: Option<Vec<String>>,
    #[serde(rename = "destinationGeoIP")]
    pub destination_geo_ip: Option<Vec<String>>,
    #[serde(rename = "sourceIPASN")]
    pub source_ipasn: String,
    #[serde(rename = "destinationIPASN")]
    pub destination_ipasn: String,
    pub source_port: String,
    pub destination_port: String,
    #[serde(rename = "inboundIP")]
    pub inbound_ip: String,
    pub inbound_port: String,
    pub inbound_name: String,
    pub inbound_user: String,
    pub rematch_name: String,
    pub host: String,
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
    pub uid: u32,
    pub process: String,
    pub process_path: String,
    pub special_proxy: String,
    pub special_rules: String,
    pub remote_destination: String,
    pub dscp: u8,
    pub sniff_host: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    pub id: String,
    pub metadata: MetadataSnapshot,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub provider_chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub connections: Option<Vec<ConnectionInfo>>,
    pub memory: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSnapshot {
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyDelayHistory {
    pub time: String,
    pub delay: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyUrlHealth {
    pub alive: bool,
    pub history: Vec<ProxyDelayHistory>,
}

#[derive(Clone, Debug)]
pub struct ProxyHealthSnapshot {
    pub alive: bool,
    pub history: Vec<ProxyDelayHistory>,
    pub extra: BTreeMap<String, ProxyUrlHealth>,
}

impl From<&Metadata> for MetadataSnapshot {
    fn from(metadata: &Metadata) -> Self {
        let inbound_type = match metadata.inbound {
            InboundProtocol::Http => "HTTP",
            InboundProtocol::Https => "HTTPS",
            InboundProtocol::Socks4 => "Socks4",
            InboundProtocol::Socks5 => "Socks5",
        };
        let network = match metadata.network {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        };
        let destination_ip = metadata
            .destination_ip
            .map_or_else(String::new, |address| address.to_string());
        let remote_destination = match &metadata.destination.host {
            Host::Ip(address) => format!("{address}:{}", metadata.destination.port),
            Host::Domain(domain) => format!("{domain}:{}", metadata.destination.port),
        };
        Self {
            network: network.to_owned(),
            inbound_type: inbound_type.to_owned(),
            source_ip: metadata
                .source_ip
                .map_or_else(String::new, |address| address.to_string()),
            destination_ip,
            source_geo_ip: None,
            destination_geo_ip: None,
            source_ipasn: String::new(),
            destination_ipasn: String::new(),
            source_port: metadata.source_port.to_string(),
            destination_port: metadata.destination.port.to_string(),
            inbound_ip: "127.0.0.1".to_owned(),
            inbound_port: metadata.inbound_port.to_string(),
            inbound_name: metadata.inbound_name.clone(),
            inbound_user: metadata.inbound_user.clone(),
            rematch_name: metadata.rematch_name.clone(),
            host: metadata.host.clone(),
            dns_mode: "normal".to_owned(),
            uid: 0,
            process: String::new(),
            process_path: String::new(),
            special_proxy: String::new(),
            special_rules: metadata.special_rules.clone(),
            remote_destination,
            dscp: metadata.dscp,
            sniff_host: metadata.sniff_host.clone(),
        }
    }
}
