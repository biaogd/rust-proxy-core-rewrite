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
