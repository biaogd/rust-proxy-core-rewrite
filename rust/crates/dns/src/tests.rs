use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rewrite_config::DnsCacheAlgorithm;

use crate::cache::{Cache, CacheLookup, age_ttls, cache_ttl, positive_ttl};
use crate::enhancer::parse_system_hosts;
use crate::transport::go_style_true;
use crate::wire::{policy_match_rank, query_tailscale, rest_response};
use crate::{DnsError, TailscaleDnsResolver, register_tailscale_dns_resolver};

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
            0, 10, 4, b'm', b'a', b'i', b'l', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't',
            b'e', b's', b't', 0,
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

    let exact = policy_match_rank("exact.example.test", "exact.example.test").expect("exact match");
    let wildcard =
        policy_match_rank("*.example.test", "exact.example.test").expect("wildcard match");
    let suffix = policy_match_rank("+.example.test", "exact.example.test").expect("suffix match");
    assert!(exact > wildcard);
    assert!(wildcard > suffix);
}

#[tokio::test]
async fn proxy_server_resolution_uses_configured_hosts_not_system_dns() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use rewrite_config::Config;

    use crate::resolve_proxy_server_or_system;

    let config = Config::from_yaml(
        r"
mixed-port: 7890
mode: rule
hosts:
  localhost: 127.0.0.2
dns:
  enable: true
  listen: 127.0.0.1:5353
  use-hosts: true
  nameserver:
    - udp://192.0.2.1:53
rules:
  - MATCH,DIRECT
",
    )
    .expect("config");
    let resolved = resolve_proxy_server_or_system(
        &config.hosts,
        config.dns.as_ref(),
        "localhost",
        51820,
        false,
    )
    .await
    .expect("configured hosts");
    let system = tokio::net::lookup_host(("localhost", 51820))
        .await
        .expect("system localhost")
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    assert_eq!(
        resolved,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 51820)
    );
    assert!(
        !system.contains(&resolved.ip()),
        "configured 127.0.0.2 must not be the system localhost answer, got {system:?}"
    );
}

#[tokio::test]
async fn direct_resolution_uses_configured_dns_not_system() {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use hickory_proto::serialize::binary::BinDecodable;
    use rewrite_config::Config;
    use tokio::net::UdpSocket;

    use crate::resolve_direct_or_system;

    let configured = Ipv4Addr::new(192, 0, 2, 10);
    let dns_socket = UdpSocket::bind("127.0.0.1:0").await.expect("dns bind");
    let dns_addr = dns_socket.local_addr().expect("dns addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        loop {
            let Ok((n, from)) = dns_socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let mut response = query;
            response.metadata.message_type = MessageType::Response;
            if let Some(name) = response.queries.first().map(Query::name).cloned() {
                response.add_answer(Record::from_rdata(name, 30, RData::A(A(configured))));
            }
            let Ok(payload) = response.to_vec() else {
                continue;
            };
            let _ = dns_socket.send_to(&payload, from).await;
        }
    });

    let source = format!(
        r"
mixed-port: 7890
mode: rule
dns:
  enable: true
  listen: 127.0.0.1:5353
  ipv6: false
  nameserver:
    - udp://{dns_addr}
rules:
  - MATCH,DIRECT
"
    );
    let config = Config::from_yaml(&source).expect("dns config");
    let host = "wg-health-diff.test";
    let via_config = resolve_direct_or_system(config.dns.as_ref(), host, true, false)
        .await
        .expect("configured DNS");
    assert_eq!(via_config, IpAddr::V4(configured));
    let system = tokio::net::lookup_host((host, 80)).await;
    if let Ok(addresses) = system {
        let ips: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
        assert!(
            !ips.contains(&via_config),
            "system DNS must not return the configured TEST-NET address, got {ips:?}"
        );
    }
}

#[tokio::test]
async fn ipv6_only_selects_aaaa_from_dual_stack_domain() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use rewrite_config::Config;
    use tokio::net::UdpSocket;

    use crate::resolve_direct_or_system;

    let ipv4 = Ipv4Addr::new(192, 0, 2, 10);
    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
    let dns_socket = UdpSocket::bind("127.0.0.1:0").await.expect("dns bind");
    let dns_addr = dns_socket.local_addr().expect("dns addr");
    tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        loop {
            let Ok((n, from)) = dns_socket.recv_from(&mut buf).await else {
                break;
            };
            let Ok(query) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let mut response = query;
            response.metadata.message_type = MessageType::Response;
            let question = response
                .queries
                .first()
                .map(|item| (item.name().clone(), item.query_type()));
            if let Some((name, qtype)) = question {
                let data = match qtype {
                    RecordType::A => Some(RData::A(A(ipv4))),
                    RecordType::AAAA => Some(RData::AAAA(AAAA(ipv6))),
                    _ => None,
                };
                if let Some(data) = data {
                    response.add_answer(Record::from_rdata(name, 30, data));
                }
            }
            if let Ok(payload) = response.to_vec() {
                let _ = dns_socket.send_to(&payload, from).await;
            }
        }
    });

    let source = format!(
        r"
mixed-port: 7890
mode: rule
dns:
  enable: true
  listen: 127.0.0.1:5353
  ipv6: true
  nameserver:
    - udp://{dns_addr}
rules:
  - MATCH,DIRECT
"
    );
    let config = Config::from_yaml(&source).expect("dns config");
    let host = "wg-dualstack.test";
    let ipv6_only = resolve_direct_or_system(config.dns.as_ref(), host, false, true)
        .await
        .expect("IPv6-only from dual-stack name");
    assert_eq!(ipv6_only, IpAddr::V6(ipv6));
    let dual = resolve_direct_or_system(config.dns.as_ref(), host, true, true)
        .await
        .expect("dual-stack prefers IPv4");
    assert_eq!(dual, IpAddr::V4(ipv4));
}
