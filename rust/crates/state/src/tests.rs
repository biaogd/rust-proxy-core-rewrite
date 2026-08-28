use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::RuntimeState;
use crate::dns_state::{FAKE_IP_MEMORY_CAPACITY, FakeIpPool};

fn mapping_address(index: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        10,
        ((index >> 16) & 0xff) as u8,
        ((index >> 8) & 0xff) as u8,
        (index & 0xff) as u8,
    ))
}

#[test]
fn redir_host_mapping_uses_the_go_size_only_lru_contract() {
    let state = RuntimeState::default();
    let first = mapping_address(1);
    let second = mapping_address(2);
    state.insert_dns_mapping(first, "first.test", 1);
    state.insert_dns_mapping(second, "second.test", 1);
    for index in 3..=4096 {
        state.insert_dns_mapping(mapping_address(index), "filler.test", 1);
    }

    assert_eq!(
        state.lookup_dns_mapping(first).as_deref(),
        Some("first.test")
    );
    state.insert_dns_mapping(mapping_address(4097), "overflow.test", 1);

    assert_eq!(
        state.lookup_dns_mapping(first).as_deref(),
        Some("first.test")
    );
    assert!(state.lookup_dns_mapping(second).is_none());
}

#[test]
fn controller_storage_replaces_and_deletes_exact_bytes() {
    let state = RuntimeState::default();
    assert!(state.storage_get("ui/key").is_none());
    state.storage_set("ui/key", b" {\"enabled\":true} \n".to_vec());
    assert_eq!(
        state.storage_get("ui/key").as_deref(),
        Some(b" {\"enabled\":true} \n".as_slice())
    );
    state.storage_set("ui/key", b"null".to_vec());
    assert_eq!(
        state.storage_get("ui/key").as_deref(),
        Some(b"null".as_slice())
    );
    state.storage_delete("ui/key");
    state.storage_delete("ui/key");
    assert!(state.storage_get("ui/key").is_none());
}

#[test]
fn controller_proxy_selection_and_health_share_runtime_state() {
    let state = RuntimeState::default();
    assert_eq!(state.global_proxy(), "DIRECT");
    let available = vec!["DIRECT".to_owned(), "REJECT".to_owned()];
    assert!(!state.set_global_proxy("missing", &available));
    assert!(state.set_global_proxy("REJECT", &available));
    assert_eq!(state.global_proxy(), "REJECT");
    let expanded = vec![
        "DIRECT".to_owned(),
        "REJECT".to_owned(),
        "configured".to_owned(),
    ];
    state.sync_global_proxy(&expanded);
    assert_eq!(state.global_proxy(), "REJECT");
    state.sync_global_proxy(&["configured".to_owned()]);
    assert_eq!(state.global_proxy(), "configured");

    let initial = state.proxy_health("DIRECT");
    assert!(initial.alive);
    assert!(initial.history.is_empty());
    state.record_proxy_delay("DIRECT", "http://health.test/", 42, true);
    let healthy = state.proxy_health("DIRECT");
    assert!(healthy.alive);
    assert_eq!(healthy.history[0].delay, 42);
    assert!(healthy.extra["http://health.test/"].alive);
    state.record_proxy_delay("DIRECT", "http://health.test/", 0, false);
    let failed = state.proxy_health("DIRECT");
    assert!(!failed.alive);
    assert_eq!(failed.history[1].delay, 0);
    assert_eq!(failed.extra["http://health.test/"].history.len(), 2);
}

#[test]
fn group_dial_failures_trigger_health_checks_at_the_go_boundaries() {
    let state = RuntimeState::default();
    let window = Duration::from_secs(1);
    let take_trigger = || {
        state
            .group_health_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_first()
    };

    state.record_group_dial_failure("fallback", window, 2, false);
    assert_eq!(take_trigger(), None);
    state.record_group_dial_failure("fallback", window, 2, false);
    assert_eq!(take_trigger().as_deref(), Some("fallback"));
    state.finish_group_health_check("fallback");

    state.record_group_dial_failure("fallback", Duration::ZERO, 2, false);
    std::thread::sleep(Duration::from_millis(1));
    state.record_group_dial_failure("fallback", Duration::ZERO, 2, false);
    state.record_group_dial_failure("fallback", window, 2, false);
    assert_eq!(take_trigger(), None);
    state.record_group_dial_failure("fallback", window, 2, false);
    assert_eq!(take_trigger().as_deref(), Some("fallback"));
    state.finish_group_health_check("fallback");

    state.record_group_dial_failure("fallback", window, 99, true);
    assert_eq!(take_trigger().as_deref(), Some("fallback"));
}

#[test]
fn fallback_choice_starts_dynamic_and_can_be_fixed_or_cleared() {
    let state = RuntimeState::default();
    let members = vec!["proxy-a".to_owned(), "DIRECT".to_owned()];
    state.sync_group_choices([("recovery", members.as_slice(), None, true)], false);
    assert_eq!(state.selector_proxy("recovery").as_deref(), Some(""));
    assert!(state.set_selector_proxy("recovery", "DIRECT", &members));
    assert_eq!(state.selector_proxy("recovery").as_deref(), Some("DIRECT"));
    assert!(state.clear_group_choice("recovery", false));
    assert_eq!(state.selector_proxy("recovery").as_deref(), Some(""));
}

#[test]
fn url_test_chooses_fastest_healthy_or_fixed_member() {
    let state = RuntimeState::default();
    let members = vec!["slow".to_owned(), "fast".to_owned()];
    let url = "http://health.test/";
    state.sync_group_choices([("speed", members.as_slice(), None, true)], false);
    state.record_proxy_delay("slow", url, 200, true);
    state.record_proxy_delay("fast", url, 50, true);
    assert_eq!(
        state.url_test_proxy("speed", &members, url, 10).as_deref(),
        Some("fast")
    );
    assert!(state.set_selector_proxy("speed", "slow", &members));
    assert_eq!(
        state.url_test_proxy("speed", &members, url, 10).as_deref(),
        Some("slow")
    );
    state.record_proxy_delay("slow", url, 0, false);
    assert_eq!(
        state.url_test_proxy("speed", &members, url, 10).as_deref(),
        Some("fast")
    );
    assert_eq!(state.selector_proxy("speed").as_deref(), Some(""));
}

#[test]
fn round_robin_skips_unhealthy_members() {
    let state = RuntimeState::default();
    let members = vec!["proxy-a".to_owned(), "proxy-b".to_owned()];
    let url = "http://health.test/";
    assert_eq!(
        state
            .round_robin_proxy("balanced", &members, url)
            .as_deref(),
        Some("proxy-a")
    );
    assert_eq!(
        state
            .round_robin_proxy("balanced", &members, url)
            .as_deref(),
        Some("proxy-b")
    );
    state.record_proxy_delay("proxy-a", url, 0, false);
    assert_eq!(
        state
            .round_robin_proxy("balanced", &members, url)
            .as_deref(),
        Some("proxy-b")
    );
}

#[test]
fn consistent_hashing_is_key_stable_and_skips_unhealthy_members() {
    let state = RuntimeState::default();
    let members = vec!["proxy-a".to_owned(), "proxy-b".to_owned()];
    let url = "http://health.test/";
    let selected = state
        .consistent_hash_proxy(&members, url, "example.test")
        .expect("selected member");
    assert_eq!(
        state.consistent_hash_proxy(&members, url, "example.test"),
        Some(selected.clone())
    );
    state.record_proxy_delay(&selected, url, 0, false);
    assert_ne!(
        state.consistent_hash_proxy(&members, url, "example.test"),
        Some(selected)
    );
}

#[test]
fn sticky_sessions_cache_a_healthy_member_and_replace_a_failed_one() {
    let state = RuntimeState::default();
    let members = vec!["proxy-a".to_owned(), "proxy-b".to_owned()];
    let url = "http://health.test/";
    let selected = state
        .sticky_session_proxy("sticky", &members, url, "source.example.test")
        .expect("selected member");
    assert_eq!(
        state.sticky_session_proxy("sticky", &members, url, "source.example.test"),
        Some(selected.clone())
    );
    state.record_proxy_delay(&selected, url, 0, false);
    let replacement = state
        .sticky_session_proxy("sticky", &members, url, "source.example.test")
        .expect("replacement member");
    assert_ne!(replacement, selected);
    assert_eq!(
        state.sticky_session_proxy("sticky", &members, url, "source.example.test"),
        Some(replacement)
    );
}

#[test]
fn fake_ip_pool_starts_at_four_and_wraps_before_last() {
    let network = "198.19.0.1/29".parse().expect("prefix");
    let mut pool = FakeIpPool::new(network, false);
    assert_eq!(pool.lookup("one.test").to_string(), "198.19.0.4");
    assert_eq!(pool.lookup("two.test").to_string(), "198.19.0.5");
    assert_eq!(pool.lookup("three.test").to_string(), "198.19.0.6");
    assert_eq!(pool.lookup("four.test").to_string(), "198.19.0.4");
    assert!(
        pool.look_back("198.19.0.4".parse().expect("address"))
            .is_some()
    );
    assert!(
        pool.look_back("198.19.0.5".parse().expect("address"))
            .is_some()
    );
}

#[test]
fn fake_ip_pool_is_case_insensitive_and_memory_bounded() {
    let network = "198.19.0.1/16".parse().expect("prefix");
    let mut pool = FakeIpPool::new(network, false);
    let first = pool.lookup("First.Test");
    assert_eq!(pool.lookup("first.test"), first);
    for index in 0..FAKE_IP_MEMORY_CAPACITY {
        pool.lookup(&format!("{index}.test"));
    }
    assert_eq!(pool.host_count(), FAKE_IP_MEMORY_CAPACITY);
    assert!(!pool.contains_host("first.test"));
    assert_ne!(pool.lookup("FIRST.TEST"), first);
}
