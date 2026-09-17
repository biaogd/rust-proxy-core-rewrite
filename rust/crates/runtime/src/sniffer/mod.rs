//! TCP sniffer (RUN-04): TLS SNI + HTTP Host peek before rule evaluation.

mod http;
mod prefixed;
mod tls;

use std::time::Duration;

use rewrite_config::{SniffProtocol, SnifferConfig, SnifferProtocolConfig};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Host, Metadata};
use rewrite_state::RuntimeState;
use tokio::io::AsyncReadExt;

use self::http::sniff_http;
use self::prefixed::PrefixedInboundStream;
use self::tls::sniff_tls;

const MAX_SNIFF_BUFFER: usize = 64 * 1024;
const SNIFF_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(super) enum SniffError {
    Need(usize),
    Fatal,
}

/// Optionally peeks TLS/HTTP and may rewrite `metadata` / wrap the stream.
///
/// `preface` bytes already drained by an inbound handshake are treated as the
/// start of the application stream (replayed via [`PrefixedInboundStream`]).
pub(crate) async fn prepare_tcp_stream(
    client: BoxedInboundStream,
    preface: &[u8],
    metadata: &mut Metadata,
    config: &SnifferConfig,
    state: &RuntimeState,
) -> (BoxedInboundStream, bool) {
    if !config.enable {
        return (wrap_preface(client, preface), false);
    }
    if !should_override(metadata, config) {
        return (wrap_preface(client, preface), false);
    }

    let candidates = tcp_candidates(config, metadata.destination.port);
    if candidates.is_empty() {
        return (wrap_preface(client, preface), false);
    }

    match sniff_domain(client, preface, &candidates).await {
        Ok((host, ports_config, stream)) => {
            if !domain_can_replace(&host, config) {
                state.log("debug", format!("[Sniffer] Skip sni[{host}]"));
                return (stream, false);
            }
            let replaced = replace_domain(metadata, &host, ports_config.override_destination);
            state.log(
                "debug",
                format!(
                    "[Sniffer] Sniff TCP success host={host} override={}",
                    ports_config.override_destination
                ),
            );
            (stream, replaced)
        }
        Err(stream) => (stream, false),
    }
}

fn wrap_preface(client: BoxedInboundStream, preface: &[u8]) -> BoxedInboundStream {
    if preface.is_empty() {
        client
    } else {
        Box::new(PrefixedInboundStream::new(client, preface.to_vec()))
    }
}

fn should_override(metadata: &Metadata, config: &SnifferConfig) -> bool {
    if let Some(dst) = metadata.destination_ip
        && config.skip_dst_address.iter().any(|net| net.contains(&dst))
    {
        return false;
    }
    if let Some(src) = metadata.source_ip
        && config.skip_src_address.iter().any(|net| net.contains(&src))
    {
        return false;
    }
    if metadata.host.is_empty() && config.parse_pure_ip {
        return true;
    }
    if metadata.dns_mapping && config.force_dns_mapping {
        return true;
    }
    config
        .force_domain
        .iter()
        .any(|matcher| matcher.matches(&metadata.host))
}

fn domain_can_replace(host: &str, config: &SnifferConfig) -> bool {
    if !is_valid_sniff_host(host) {
        return false;
    }
    !config
        .skip_domain
        .iter()
        .any(|matcher| matcher.matches(host))
}

fn is_valid_sniff_host(host: &str) -> bool {
    if host.is_empty() || host == "." {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && !host.starts_with('.')
        && !host.starts_with('-')
}

fn replace_domain(metadata: &mut Metadata, host: &str, override_dest: bool) -> bool {
    metadata.sniff_host = host.to_owned();
    if override_dest {
        metadata.host = host.to_owned();
        metadata.destination.host = Host::Domain(host.to_owned());
        metadata.destination_ip = None;
        metadata.dns_mapping = false;
        true
    } else {
        false
    }
}

fn tcp_candidates(
    config: &SnifferConfig,
    port: u16,
) -> Vec<(SniffProtocol, SnifferProtocolConfig)> {
    // Go iterates sniffer.List order: TLS, HTTP, QUIC.
    let order = [SniffProtocol::Tls, SniffProtocol::Http];
    let mut out = Vec::new();
    for protocol in order {
        if let Some(entry) = config.protocols.get(&protocol)
            && entry.supports_port(port, protocol)
        {
            out.push((protocol, entry.clone()));
        }
    }
    out
}

async fn sniff_domain(
    mut client: BoxedInboundStream,
    preface: &[u8],
    candidates: &[(SniffProtocol, SnifferProtocolConfig)],
) -> Result<(String, SnifferProtocolConfig, BoxedInboundStream), BoxedInboundStream> {
    let mut buffer = preface.to_vec();
    let mut active: Vec<(SniffProtocol, SnifferProtocolConfig, usize)> = candidates
        .iter()
        .map(|(protocol, config)| (*protocol, config.clone(), 1usize))
        .collect();

    if buffer.is_empty() {
        match read_more(&mut client, &mut buffer, 1, SNIFF_DEADLINE).await {
            Ok(()) => {}
            Err(()) => return Err(wrap_preface(client, &buffer)),
        }
    }

    let deadline = tokio::time::Instant::now() + SNIFF_DEADLINE;
    while !active.is_empty() {
        let want = active.iter().map(|entry| entry.2).min().unwrap_or(1);
        if want > MAX_SNIFF_BUFFER && want > buffer.len() {
            return Err(wrap_preface(client, &buffer));
        }
        if buffer.len() < want {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(wrap_preface(client, &buffer));
            }
            match read_more(&mut client, &mut buffer, want, remaining).await {
                Ok(()) => {}
                Err(()) => return Err(wrap_preface(client, &buffer)),
            }
        }

        let mut next_active = Vec::new();
        for (protocol, config, need) in active {
            if need > buffer.len() {
                next_active.push((protocol, config, need));
                continue;
            }
            match sniff_data(protocol, &buffer) {
                Ok(host) => {
                    if is_valid_sniff_host(&host) {
                        let stream = wrap_preface(client, &buffer);
                        return Ok((host, config, stream));
                    }
                }
                Err(SniffError::Need(next)) if next > buffer.len() => {
                    next_active.push((protocol, config, next));
                }
                Err(_) => {}
            }
        }
        active = next_active;
    }

    Err(wrap_preface(client, &buffer))
}

fn sniff_data(protocol: SniffProtocol, data: &[u8]) -> Result<String, SniffError> {
    match protocol {
        SniffProtocol::Tls => sniff_tls(data),
        SniffProtocol::Http => sniff_http(data),
        SniffProtocol::Quic => Err(SniffError::Fatal),
    }
}

async fn read_more(
    client: &mut BoxedInboundStream,
    buffer: &mut Vec<u8>,
    want: usize,
    timeout: Duration,
) -> Result<(), ()> {
    if buffer.len() >= want {
        return Ok(());
    }
    if want > MAX_SNIFF_BUFFER {
        return Err(());
    }
    let deadline = tokio::time::Instant::now() + timeout;
    while buffer.len() < want {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(());
        }
        let mut chunk = vec![0_u8; (want - buffer.len()).min(16 * 1024)];
        match tokio::time::timeout(remaining, client.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buffer.extend_from_slice(&chunk[..n]),
            _ => return Err(()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rewrite_config::SnifferProtocolConfig;
    use rewrite_model::{Destination, InboundProtocol};
    use std::collections::BTreeMap;

    #[test]
    fn should_override_pure_ip() {
        let metadata = Metadata::new(
            Destination {
                host: Host::Ip(std::net::Ipv4Addr::LOCALHOST.into()),
                port: 443,
            },
            InboundProtocol::Socks5,
        );
        let mut config = SnifferConfig::disabled();
        config.enable = true;
        config.parse_pure_ip = true;
        assert!(should_override(&metadata, &config));
    }

    #[test]
    fn tls_candidate_default_port() {
        let mut protocols = BTreeMap::new();
        protocols.insert(
            SniffProtocol::Tls,
            SnifferProtocolConfig {
                ports: Vec::new(),
                override_destination: true,
            },
        );
        let config = SnifferConfig {
            enable: true,
            protocols,
            ..SnifferConfig::disabled()
        };
        assert_eq!(tcp_candidates(&config, 443).len(), 1);
        assert!(tcp_candidates(&config, 80).is_empty());
    }
}
