use std::net::Ipv6Addr;

use crate::decode::{domain_mrs_to_text, ipcidr_mrs_to_text};
use crate::encode::{domain_to_mrs, ipcidr_to_mrs};
use crate::model::{
    DOMAIN_BEHAVIOR, IPCIDR_BEHAVIOR, IPCIDR_SET_VERSION, MRS_MAGIC, RulesetError, SourceFormat,
};
use crate::source::parse_yaml_rules;

#[test]
fn decodes_ipcidr_ranges_to_minimal_prefixes() {
    let mut plain = Vec::new();
    plain.extend(MRS_MAGIC);
    plain.push(IPCIDR_BEHAVIOR);
    plain.extend(3_i64.to_be_bytes());
    plain.extend(0_i64.to_be_bytes());
    plain.push(IPCIDR_SET_VERSION);
    plain.extend(2_i64.to_be_bytes());
    plain.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 0]);
    plain.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 3]);
    plain.extend(u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)).to_be_bytes());
    plain.extend(u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)).to_be_bytes());
    let encoded = zstd::stream::encode_all(plain.as_slice(), 0).unwrap();
    assert_eq!(
        ipcidr_mrs_to_text(&encoded).unwrap(),
        b"192.0.2.0/30\n2001:db8::/127\n"
    );
}

#[test]
fn encodes_text_and_yaml_as_merged_ipcidr_ranges() {
    for (source, format) in [
        (
            b"# comment\n192.0.2.0/25\n192.0.2.128/25\n2001:db8::/127\n".as_slice(),
            SourceFormat::Text,
        ),
        (
            b"payload:\n  - 192.0.2.0/25\n  - 192.0.2.128/25\n  - 2001:db8::/127\n".as_slice(),
            SourceFormat::Yaml,
        ),
    ] {
        let encoded = ipcidr_to_mrs(source, format).unwrap();
        assert_eq!(
            ipcidr_mrs_to_text(&encoded).unwrap(),
            b"192.0.2.0/24\n2001:db8::/127\n"
        );
        let decoded = zstd::stream::decode_all(encoded.as_slice()).unwrap();
        assert_eq!(&decoded[5..13], 3_i64.to_be_bytes());
    }
}

#[test]
fn yaml_stream_skips_preamble_and_bad_entries() {
    let rules = parse_yaml_rules(
        b"metadata:\n  - ignored\npayload:\n  - exact.example\n  - [broken\n  - later.example\n",
    )
    .unwrap();
    assert_eq!(rules, ["exact.example", "later.example"]);
    assert!(matches!(
        parse_yaml_rules(b"payload: [one.example]"),
        Err(RulesetError::MissingPayload)
    ));
}

#[test]
fn decodes_single_key_domain_set() {
    let mut plain = Vec::new();
    plain.extend(MRS_MAGIC);
    plain.push(DOMAIN_BEHAVIOR);
    plain.extend(1_i64.to_be_bytes());
    plain.extend(0_i64.to_be_bytes());
    plain.push(1);
    plain.extend(1_i64.to_be_bytes());
    plain.extend(2_u64.to_be_bytes());
    plain.extend(1_i64.to_be_bytes());
    plain.extend(6_u64.to_be_bytes());
    plain.extend(1_i64.to_be_bytes());
    plain.push(b'a');
    let encoded = zstd::stream::encode_all(plain.as_slice(), 0).unwrap();
    assert_eq!(domain_mrs_to_text(&encoded).unwrap(), b"a\n");
}

#[test]
fn encodes_domain_wildcards_and_normalizes_case() {
    let encoded = domain_to_mrs(
        b"EXACT.example\n*.wild.example\n+.suffix.example\n",
        SourceFormat::Text,
    )
    .unwrap();
    assert_eq!(
        domain_mrs_to_text(&encoded).unwrap(),
        b"*.wild.example\n+.suffix.example\nexact.example\n"
    );
}
