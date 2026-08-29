use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use md5::{Digest, Md5};
use prost::Message;

use crate::dns::{
    GeoIpCidrWire, GeoIpListWire, GeoIpWire, GeoSiteDomainTypeWire, GeoSiteDomainWire,
    GeoSiteListWire, GeoSiteWire,
};
use crate::proxy::{expand_proxy_group, proxy_member_types};
use crate::*;

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
    assert_eq!(config.proxies[0].kind, ProxyKind::Rematch);
    assert_eq!(
        config.rematch("SET-NAME").expect("rematch").name,
        "SET-NAME"
    );
}

#[test]
fn parses_phase_six_a_simple_adapters_and_provider_members() {
    let source = format!(
        "{MINIMAL}\nproxies:\n  - {{name: local-direct, type: direct}}\n  - {{name: local-reject, type: reject}}\n  - {{name: local-dns, type: dns}}\nproxy-providers:\n  simple:\n    type: inline\n    payload:\n      - {{name: provider-direct, type: direct}}\nproxy-groups:\n  - {{name: simple-group, type: select, proxies: [local-reject], use: [simple]}}\n"
    );
    let config = Config::from_yaml(&source).expect("Phase 6A simple adapters");
    assert_eq!(
        config
            .proxies
            .iter()
            .map(|proxy| proxy.kind)
            .collect::<Vec<_>>(),
        [ProxyKind::Direct, ProxyKind::Reject, ProxyKind::Dns]
    );
    assert_eq!(config.proxy_providers[0].proxies[0].kind, ProxyKind::Direct);
    assert_eq!(
        config.default_global_proxies(),
        [
            "DIRECT",
            "REJECT",
            "local-direct",
            "local-reject",
            "local-dns",
            "simple-group"
        ]
    );
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
                endpoint: DnsClassicEndpoint::Socket("127.0.0.1:15353".parse().expect("literal"),),
                transport: DnsTransport::Tcp,
                query_options: DnsQueryOptions::default(),
            }],
            main_resolvers: vec![DnsResolverClient::Classic(DnsClassicUpstream {
                endpoint: DnsClassicEndpoint::Socket("127.0.0.1:15353".parse().expect("literal"),),
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
    let source =
        "dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - dhcp://fixture0\n";
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
    let default =
        Config::from_yaml("mixed-port: 7890\nrules: ['MATCH,DIRECT']\n").expect("default profile");
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
                endpoint: DnsClassicEndpoint::Socket("127.0.0.1:25353".parse().expect("literal"),),
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
                endpoint: DnsClassicEndpoint::Socket("127.0.0.1:25353".parse().expect("literal"),),
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
        let source =
            format!("dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - {url}\n");
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
        let source =
            format!("dns:\n  enable: true\n  listen: 127.0.0.1:5353\n  nameserver:\n    - {url}\n");
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
fn builds_the_oracle_default_global_catalog_and_accepts_a_custom_global() {
    let source = format!(
        "{MINIMAL}\nproxies:\n  - {{name: local-http, type: http, server: 127.0.0.1, port: 8080}}\nproxy-groups:\n  - {{name: local-group, type: select, proxies: [DIRECT]}}\n"
    );
    let default_global = Config::from_yaml(&source).expect("default GLOBAL");
    assert!(!default_global.has_custom_global_group());
    assert_eq!(
        default_global.default_global_proxies(),
        ["DIRECT", "REJECT", "local-http", "local-group"]
    );

    let custom = Config::from_yaml(&format!(
        "{MINIMAL}\nproxy-groups:\n  - {{name: GLOBAL, type: select, proxies: [REJECT, DIRECT]}}\n"
    ))
    .expect("custom GLOBAL");
    assert!(custom.has_custom_global_group());
    assert_eq!(custom.proxy_groups[0].proxies, ["REJECT", "DIRECT"]);
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
        cache_modified: None,
        health_check: ProviderHealthConfig {
            enabled: false,
            url: String::new(),
            expected_status: "*".to_owned(),
            interval: 0,
            timeout: 5_000,
            lazy: true,
        },
        transform: ProxyProviderTransform::default(),
        proxies: ["provider-alpha", "provider-beta", "provider-omit"]
            .into_iter()
            .map(|name| ProxyConfig {
                name: name.to_owned(),
                kind: ProxyKind::Http,
                server: "127.0.0.1".to_owned(),
                port: 8080,
                username: None,
                password: None,
                tls: false,
                sni: None,
                skip_cert_verify: false,
                name_cert_verify: None,
                fingerprint: None,
                certificate: None,
                private_key: None,
                udp: false,
                headers: BTreeMap::new(),
                cipher: None,
                plugin: None,
                udp_over_tcp: false,
                obfs: None,
                obfs_param: None,
                protocol: None,
                protocol_param: None,
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
        cache_modified: None,
        health_check: ProviderHealthConfig {
            enabled: false,
            url: String::new(),
            expected_status: "*".to_owned(),
            interval: 0,
            timeout: 5_000,
            lazy: true,
        },
        transform: ProxyProviderTransform::default(),
        proxies: vec![ProxyConfig {
            name: "provider-alpha".to_owned(),
            kind: ProxyKind::Http,
            server: "127.0.0.1".to_owned(),
            port: 8080,
            username: None,
            password: None,
            tls: false,
            sni: None,
            skip_cert_verify: false,
            name_cert_verify: None,
            fingerprint: None,
            certificate: None,
            private_key: None,
            udp: false,
            headers: BTreeMap::new(),
            cipher: None,
            plugin: None,
            udp_over_tcp: false,
            obfs: None,
            obfs_param: None,
            protocol: None,
            protocol_param: None,
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
fn parses_phase6b_http_and_socks5_tls_options() {
    let fingerprint = "11".repeat(32);
    let source = format!(
        "{MINIMAL}\nproxies:\n  - name: secure-http\n    type: http\n    server: proxy.test\n    port: 8443\n    username: user\n    password: pass\n    tls: true\n    sni: front.test\n    skip-cert-verify: true\n    name-cert-verify: verify.test\n    fingerprint: '{fingerprint}'\n    certificate: client.pem\n    private-key: client.key\n    headers:\n      X-Phase: 6b\n"
    );
    let config = Config::from_yaml(&source).expect("HTTP TLS config");
    let proxy = &config.proxies[0];
    assert!(proxy.tls);
    assert_eq!(proxy.sni.as_deref(), Some("front.test"));
    assert!(proxy.skip_cert_verify);
    assert_eq!(proxy.name_cert_verify.as_deref(), Some("verify.test"));
    assert_eq!(proxy.fingerprint.as_deref(), Some(fingerprint.as_str()));
    assert_eq!(proxy.certificate.as_deref(), Some("client.pem"));
    assert_eq!(proxy.private_key.as_deref(), Some("client.key"));
    assert_eq!(proxy.headers["X-Phase"], "6b");

    let home = std::env::temp_dir().join("mihomo-phase6b-proxy-home");
    let resolved = Config::from_yaml_with_provider_directory(&source, &home, false)
        .expect("relative proxy client keypair paths");
    assert_eq!(
        resolved.proxies[0].certificate.as_deref(),
        Some(home.join("client.pem").to_string_lossy().as_ref())
    );
    assert_eq!(
        resolved.proxies[0].private_key.as_deref(),
        Some(home.join("client.key").to_string_lossy().as_ref())
    );

    let socks = source.replace("type: http", "type: socks5");
    assert!(matches!(
        Config::from_yaml(&socks),
        Err(ConfigError::UnsupportedProxy(_))
    ));

    let socks = Config::from_yaml(&format!(
            "{MINIMAL}\nproxies:\n  - name: secure-socks\n    type: socks5\n    server: proxy.test\n    port: 1080\n    tls: true\n    udp: true\n    name-cert-verify: verify.test\n    fingerprint: '{fingerprint}'\n    certificate: client.pem\n    private-key: client.key\n"
        ))
        .expect("SOCKS5 TLS/UDP config");
    assert!(socks.proxies[0].tls);
    assert!(socks.proxies[0].udp);
    assert_eq!(
        socks.proxies[0].name_cert_verify.as_deref(),
        Some("verify.test")
    );

    let invalid_pair = source.replace("    private-key: client.key\n", "");
    assert!(matches!(
        Config::from_yaml(&invalid_pair),
        Err(ConfigError::UnsupportedProxy(_))
    ));
}

#[test]
fn mirrors_http_credential_activation_boundaries() {
    let config = Config::from_yaml(&format!(
            "{MINIMAL}\nproxies:\n  - {{name: noauth, type: http, server: proxy.test, port: 8080}}\n  - {{name: user-only, type: http, server: proxy.test, port: 8080, username: user}}\n  - {{name: password-only, type: http, server: proxy.test, port: 8080, password: ignored}}\n  - {{name: both, type: http, server: proxy.test, port: 8080, username: user, password: pass}}\n"
        ))
        .expect("Go-compatible HTTP credential shapes");
    assert_eq!(config.proxies[0].http_credentials(), None);
    assert_eq!(config.proxies[1].http_credentials(), None);
    assert_eq!(config.proxies[2].http_credentials(), None);
    assert_eq!(config.proxies[3].http_credentials(), Some(("user", "pass")));
}

#[test]
fn mirrors_socks5_credential_activation_boundaries() {
    let config = Config::from_yaml(&format!(
            "{MINIMAL}\nproxies:\n  - {{name: noauth, type: socks5, server: proxy.test, port: 1080}}\n  - {{name: user-only, type: socks5, server: proxy.test, port: 1080, username: user}}\n  - {{name: password-only, type: socks5, server: proxy.test, port: 1080, password: ignored}}\n"
        ))
        .expect("Go-compatible SOCKS5 credential shapes");
    assert_eq!(config.proxies[0].socks5_credentials(), None);
    assert_eq!(config.proxies[1].socks5_credentials(), Some(("user", "")));
    assert_eq!(config.proxies[2].socks5_credentials(), None);
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

#[test]
fn parses_phase5e_service_defaults_and_overrides() {
    let defaults = Config::from_yaml(MINIMAL).expect("service defaults");
    assert_eq!(defaults.ntp.server, "time.apple.com");
    assert_eq!(defaults.ntp.port, 123);
    assert_eq!(defaults.ntp.interval, 30);
    assert!(!defaults.ntp.enable);
    assert!(!defaults.geo_auto_update);
    assert_eq!(defaults.geo_update_interval, 24);
    assert_eq!(defaults.geodata_loader, "memconservative");
    assert_eq!(defaults.geosite_matcher, "succinct");

    let configured = Config::from_yaml(&format!(
            "{MINIMAL}\ngeodata-loader: standard\ngeosite-matcher: mph\ngeo-auto-update: true\ngeo-update-interval: 12\ngeox-url:\n  geoip: http://geo.test/ip\n  mmdb: http://geo.test/mmdb\n  asn: http://geo.test/asn\n  geosite: http://geo.test/site\nntp:\n  enable: true\n  server: ntp.test\n  port: 10123\n  interval: 9\n  dialer-proxy: DIRECT\n  write-to-system: true\n"
        ))
        .expect("configured Phase 5E services");
    assert!(configured.ntp.enable);
    assert_eq!(configured.ntp.server, "ntp.test");
    assert_eq!(configured.ntp.port, 10123);
    assert_eq!(configured.ntp.interval, 9);
    assert_eq!(configured.ntp.dialer_proxy, "DIRECT");
    assert!(configured.ntp.write_to_system);
    assert!(configured.geo_auto_update);
    assert_eq!(configured.geo_update_interval, 12);
    assert_eq!(configured.geodata_loader, "standard");
    assert_eq!(configured.geosite_matcher, "mph");
    assert_eq!(configured.geox_url.geo_ip, "http://geo.test/ip");
    assert_eq!(configured.geox_url.geo_site, "http://geo.test/site");
}

#[test]
fn loads_general_geosite_and_geoip_rules_from_home_geodata() {
    let home =
        std::env::temp_dir().join(format!("mihomo-phase5e-geo-rules-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("geodata home");
    std::fs::write(
        home.join("GeoSite.dat"),
        GeoSiteListWire {
            entries: vec![GeoSiteWire {
                country_code: "PHASE5E".to_owned(),
                domains: vec![GeoSiteDomainWire {
                    kind: GeoSiteDomainTypeWire::Domain as i32,
                    value: "geo.phase5e.test".to_owned(),
                }],
            }],
        }
        .encode_to_vec(),
    )
    .expect("GeoSite fixture");
    std::fs::write(
        home.join("GeoIP.dat"),
        GeoIpListWire {
            entries: vec![GeoIpWire {
                country_code: "LOOPBACK".to_owned(),
                networks: vec![GeoIpCidrWire {
                    address: vec![127, 0, 0, 0],
                    prefix: 8,
                }],
            }],
        }
        .encode_to_vec(),
    )
    .expect("GeoIP fixture");
    let source = MINIMAL.replace(
            "rules:\n  - MATCH,DIRECT",
            "geodata-mode: true\nrules:\n  - GEOSITE,PHASE5E,REJECT\n  - GEOIP,LOOPBACK,DIRECT,no-resolve\n  - MATCH,REJECT",
        );
    let config = Config::from_yaml_with_provider_directory(&source, &home, false)
        .expect("general Geo rules");
    let domain = rewrite_model::Metadata::new(
        rewrite_model::Destination {
            host: rewrite_model::Host::Domain("deep.geo.phase5e.test".to_owned()),
            port: 80,
        },
        rewrite_model::InboundProtocol::Http,
    );
    assert_eq!(config.rules.evaluate(&domain).target, "REJECT");
    let address = rewrite_model::Metadata::new(
        rewrite_model::Destination {
            host: rewrite_model::Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 80,
        },
        rewrite_model::InboundProtocol::Http,
    );
    assert_eq!(config.rules.evaluate(&address).target, "DIRECT");
    std::fs::remove_dir_all(home).expect("remove geodata fixture");
}

#[test]
fn parses_fixed_listener_lan_policy() {
    let source = MINIMAL.replace(
            "mixed-port: 7890",
            "mixed-port: 7890\nallow-lan: true\nbind-address: 0.0.0.0\nskip-auth-prefixes: [127.0.0.0/8]\nlan-allowed-ips: [0.0.0.0/0]\nlan-disallowed-ips: [192.0.2.0/24]",
        );
    let config = Config::from_yaml(&source).expect("LAN policy");
    assert_eq!(
        config.listener_address(7890).expect("listener address"),
        "0.0.0.0:7890".parse().expect("socket address")
    );
    assert!(config.skips_inbound_auth(Ipv4Addr::LOCALHOST.into()));
    assert!(config.permits_inbound(Ipv4Addr::LOCALHOST.into()));
    assert!(!config.permits_inbound("192.0.2.1".parse().expect("denied IP")));

    let invalid = source.replace("127.0.0.0/8", "not-a-prefix");
    assert!(matches!(
        Config::from_yaml(&invalid),
        Err(ConfigError::InvalidInbound(_))
    ));

    let mut patched = config.clone();
    patched.bind_address = "[::1]".to_owned();
    patched
        .update_inbound_prefixes(
            Some(vec!["::1/128".to_owned()]),
            Some(vec!["127.0.0.0/8".to_owned()]),
            Some(Vec::new()),
        )
        .expect("controller prefix update");
    assert_eq!(
        patched.listener_address(7890).expect("IPv6 address"),
        "[::1]:7890".parse().expect("IPv6 socket address")
    );
    assert!(
        patched.permits_inbound(
            "::ffff:127.0.0.1"
                .parse()
                .expect("IPv4-mapped IPv6 address")
        )
    );
}
