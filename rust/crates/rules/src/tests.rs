use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rewrite_model::{Destination, Host, InboundProtocol, Metadata};

use crate::model::{
    Decision, LazyEvaluation, ProviderBehavior, ProviderDefinition, RuleError, RuleSet,
};
use crate::parser::{domain_wildcard_matches, geodata_provider_key};

fn metadata(host: &str, port: u16) -> Metadata {
    Metadata::new(
        Destination {
            host: Host::Domain(host.to_owned()),
            port,
        },
        InboundProtocol::Socks5,
    )
}

#[test]
fn evaluates_phase_two_families() {
    let rules = vec![
        "AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),REJECT".to_owned(),
        "MATCH,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    assert_eq!(
        program.evaluate(&metadata("www.example.com", 443)).target,
        "REJECT"
    );
    assert_eq!(
        program.evaluate(&metadata("www.example.com", 80)).target,
        "DIRECT"
    );
}

#[test]
fn tracks_and_disables_top_level_rules() {
    let rules = vec![
        "DOMAIN-SUFFIX,example.com,DIRECT".to_owned(),
        "MATCH,REJECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let initial = program.snapshots();
    assert_eq!(initial[0].kind, "DomainSuffix");
    assert_eq!(initial[0].payload, "example.com");
    assert_eq!(initial[0].target, "DIRECT");
    assert_eq!(initial[0].hit_at_unix_nanos, 0);

    assert_eq!(
        program.evaluate(&metadata("www.example.com", 443)).target,
        "DIRECT"
    );
    assert_eq!(
        program.evaluate(&metadata("other.test", 443)).target,
        "REJECT"
    );
    let observed = program.snapshots();
    assert_eq!((observed[0].hit_count, observed[0].miss_count), (1, 1));
    assert_eq!((observed[1].hit_count, observed[1].miss_count), (1, 0));
    assert!(observed[0].hit_at_unix_nanos > 0);
    assert!(observed[0].miss_at_unix_nanos > 0);

    program.set_disabled(0, true);
    assert_eq!(
        program.evaluate(&metadata("www.example.com", 443)).target,
        "REJECT"
    );
    let disabled = program.snapshots();
    assert!(disabled[0].disabled);
    assert_eq!((disabled[0].hit_count, disabled[0].miss_count), (1, 1));
    assert_eq!(disabled[1].hit_count, 2);

    program.set_disabled(0, false);
    assert_eq!(
        program.evaluate(&metadata("www.example.com", 443)).target,
        "DIRECT"
    );
    assert_eq!(program.snapshots()[0].hit_count, 2);
}

#[test]
fn matches_case_insensitive_domain_regex_with_advanced_syntax() {
    let rules = vec![
        "DOMAIN-REGEX,^(?=LOCAL)local{1,2}host$,REJECT".to_owned(),
        "MATCH,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let decision = program.evaluate(&metadata("localhost", 80));
    assert_eq!(decision.target, "REJECT");
    assert_eq!(decision.matched_kind.as_deref(), Some("DomainRegex"));
    assert_eq!(
        program.evaluate(&metadata("localghost", 80)).target,
        "DIRECT"
    );
}

#[test]
fn rejects_invalid_domain_regex() {
    let rules = vec!["DOMAIN-REGEX,(,DIRECT".to_owned()];
    assert!(matches!(
        RuleSet::parse(&rules, &BTreeMap::new(), &[]),
        Err(RuleError::InvalidPayload)
    ));
}

#[test]
fn matches_domain_wildcards_with_go_byte_semantics() {
    let rules = vec![
        "DOMAIN-WILDCARD,local?o*,REJECT".to_owned(),
        "MATCH,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let decision = program.evaluate(&metadata("localhost", 80));
    assert_eq!(decision.target, "REJECT");
    assert_eq!(decision.matched_kind.as_deref(), Some("DomainWildcard"));
    assert_eq!(program.evaluate(&metadata("localost", 80)).target, "DIRECT");
    assert!(domain_wildcard_matches("?", "a"));
    assert!(!domain_wildcard_matches("?", "é"));
    assert!(domain_wildcard_matches("**", ""));
}

#[test]
fn matches_destination_ip_suffix_bits() {
    let rules = vec![
        "IP-SUFFIX,0.0.0.5/8,REJECT".to_owned(),
        "MATCH,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let mut input = metadata("suffix.test", 80);
    input.destination_ip = Some("192.0.2.5".parse().expect("IPv4"));
    let decision = program.evaluate(&input);
    assert_eq!(decision.target, "REJECT");
    assert_eq!(decision.matched_kind.as_deref(), Some("IPSuffix"));
    input.destination_ip = Some("192.0.2.6".parse().expect("IPv4"));
    assert_eq!(program.evaluate(&input).target, "DIRECT");
}

#[test]
fn rejects_invalid_ip_suffix_width() {
    let rules = vec!["IP-SUFFIX,127.0.0.1/33,DIRECT".to_owned()];
    assert!(matches!(
        RuleSet::parse(&rules, &BTreeMap::new(), &[]),
        Err(RuleError::InvalidPayload)
    ));
}

#[test]
fn matches_source_ip_suffix_aliases() {
    for rule in [
        "SRC-IP-SUFFIX,0.0.0.1/8,REJECT",
        "IP-SUFFIX,0.0.0.1/8,REJECT,src",
    ] {
        let rules = vec![rule.to_owned(), "MATCH,DIRECT".to_owned()];
        let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
        let mut input = metadata("source.test", 80);
        input.source_ip = Some("127.0.0.1".parse().expect("IPv4"));
        let decision = program.evaluate(&input);
        assert_eq!(decision.target, "REJECT");
        assert_eq!(decision.matched_kind.as_deref(), Some("SrcIPSuffix"));
    }
}

#[test]
fn matches_current_local_inbound_types_and_socks_alias() {
    let rules = vec![
        "IN-TYPE,HTTP/SOCKS4,REJECT".to_owned(),
        "MATCH,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let mut input = metadata("inbound.test", 80);
    input.inbound = InboundProtocol::Http;
    assert_eq!(program.evaluate(&input).target, "REJECT");
    input.inbound = InboundProtocol::Https;
    assert_eq!(program.evaluate(&input).target, "DIRECT");
    input.inbound = InboundProtocol::Socks4;
    assert_eq!(program.evaluate(&input).target, "REJECT");
    input.inbound = InboundProtocol::Socks5;
    assert_eq!(program.evaluate(&input).target, "DIRECT");

    let alias = vec!["IN-TYPE,SOCKS,REJECT".to_owned(), "MATCH,DIRECT".to_owned()];
    let program = RuleSet::parse(&alias, &BTreeMap::new(), &[]).expect("valid rules");
    assert_eq!(program.evaluate(&input).target, "REJECT");
}

#[test]
fn matches_inbound_users_exactly() {
    let rules = vec![
        "IN-USER,alice/socks4,REJECT".to_owned(),
        "MATCH,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let mut input = metadata("user.test", 80);
    input.inbound_user = "alice".to_owned();
    assert_eq!(program.evaluate(&input).target, "REJECT");
    input.inbound_user = "Alice".to_owned();
    assert_eq!(program.evaluate(&input).target, "DIRECT");
}

#[test]
fn matches_inbound_names_exactly() {
    let rules = vec![
        "IN-NAME,DEFAULT-HTTP/DEFAULT-MIXED,REJECT".to_owned(),
        "MATCH,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let mut input = metadata("name.test", 80);
    input.inbound_name = "DEFAULT-MIXED".to_owned();
    assert_eq!(program.evaluate(&input).target, "REJECT");
    input.inbound_name = "default-mixed".to_owned();
    assert_eq!(program.evaluate(&input).target, "DIRECT");
}

#[test]
fn matches_dscp_ranges_and_rejects_values_over_sixty_three() {
    let rules = vec!["DSCP,1/4-2,REJECT".to_owned(), "MATCH,DIRECT".to_owned()];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let mut input = metadata("dscp.test", 80);
    input.dscp = 3;
    assert_eq!(program.evaluate(&input).target, "REJECT");
    input.dscp = 0;
    assert_eq!(program.evaluate(&input).target, "DIRECT");
    let invalid = vec!["DSCP,64,DIRECT".to_owned()];
    assert!(matches!(
        RuleSet::parse(&invalid, &BTreeMap::new(), &[]),
        Err(RuleError::InvalidPayload)
    ));
}

#[test]
fn detects_sub_rule_cycle() {
    let sub_rules = BTreeMap::from([
        ("a".to_owned(), vec!["SUB-RULE,(NETWORK,TCP),b".to_owned()]),
        ("b".to_owned(), vec!["SUB-RULE,(NETWORK,TCP),a".to_owned()]),
    ]);
    assert!(matches!(
        RuleSet::parse(&[], &sub_rules, &[]),
        Err(RuleError::SubRuleCycle(_))
    ));
}

#[test]
fn matches_source_ip_and_port_ranges() {
    let rules = vec![
        "SRC-IP-CIDR,10.0.0.0/8,REJECT".to_owned(),
        "DST-PORT,443/8000-9000,DIRECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    let mut input = metadata("example.com", 8080);
    input.source_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
    assert_eq!(program.evaluate(&input).target, "REJECT");
}

#[test]
fn requests_destination_resolution_only_when_ordered_rule_needs_it() {
    let rules = vec![
        "DOMAIN,domain-first.test,REJECT".to_owned(),
        "IP-CIDR,127.0.0.0/8,DIRECT".to_owned(),
        "MATCH,REJECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    assert!(matches!(
        program.evaluate_lazy(&metadata("domain-first.test", 80)),
        LazyEvaluation::Decision(Decision { target, .. }) if target == "REJECT"
    ));

    let mut input = metadata("needs-ip.test", 80);
    assert_eq!(
        program.evaluate_lazy(&input),
        LazyEvaluation::ResolveDestinationIp
    );
    input.destination_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(matches!(
        program.evaluate_lazy(&input),
        LazyEvaluation::Decision(Decision { target, .. }) if target == "DIRECT"
    ));
}

#[test]
fn no_resolve_ip_rule_falls_through_without_requesting_dns() {
    let rules = vec![
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve".to_owned(),
        "MATCH,REJECT".to_owned(),
    ];
    let program = RuleSet::parse(&rules, &BTreeMap::new(), &[]).expect("valid rules");
    assert!(matches!(
        program.evaluate_lazy(&metadata("no-resolve.test", 80)),
        LazyEvaluation::Decision(Decision { target, .. }) if target == "REJECT"
    ));
}

#[test]
fn matches_validated_geosite_and_geoip_resources() {
    let rules = vec![
        "GEOSITE,TEST,REJECT".to_owned(),
        "GEOIP,LOOPBACK,DIRECT,no-resolve".to_owned(),
        "SRC-GEOIP,CLIENT,REJECT".to_owned(),
        "MATCH,REJECT".to_owned(),
    ];
    let providers = BTreeMap::from([
        (
            geodata_provider_key("GEOSITE", "TEST"),
            ProviderDefinition {
                behavior: ProviderBehavior::Classical,
                payload: vec!["DOMAIN-SUFFIX,geo.test".to_owned()],
            },
        ),
        (
            geodata_provider_key("GEOIP", "LOOPBACK"),
            ProviderDefinition {
                behavior: ProviderBehavior::IpCidr,
                payload: vec!["127.0.0.0/8".to_owned()],
            },
        ),
        (
            geodata_provider_key("SRC-GEOIP", "CLIENT"),
            ProviderDefinition {
                behavior: ProviderBehavior::IpCidr,
                payload: vec!["192.0.2.0/24".to_owned()],
            },
        ),
    ]);
    let program = RuleSet::parse_with_targets_and_providers(
        &rules,
        &BTreeMap::new(),
        &[],
        &BTreeSet::new(),
        &providers,
    )
    .expect("validated geodata resources");

    assert_eq!(
        program.evaluate(&metadata("deep.geo.test", 80)).target,
        "REJECT"
    );
    let mut destination = metadata("127.0.0.1", 80);
    destination.destination_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(program.evaluate(&destination).target, "DIRECT");
    let mut source = metadata("other.test", 80);
    source.source_ip = Some("192.0.2.1".parse().expect("source address"));
    assert_eq!(program.evaluate(&source).target, "REJECT");
    assert_eq!(program.snapshots()[0].kind, "GeoSite");
    assert_eq!(program.snapshots()[1].kind, "GeoIP");
    assert_eq!(program.snapshots()[2].kind, "SrcGeoIP");
}
