use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64};

use ipnet::IpNet;
use rewrite_model::Network;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Direct,
    Reject,
    RejectDrop,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RematchSpec {
    pub name: String,
    pub target_rematch_name: Option<String>,
    pub target_sub_rule: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderBehavior {
    Domain,
    IpCidr,
    Classical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDefinition {
    pub behavior: ProviderBehavior,
    pub payload: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub target: String,
    pub matched_kind: Option<String>,
    pub rematch_cycle: bool,
    pub rematch_name: String,
    pub special_rules: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LazyEvaluation {
    Decision(Decision),
    ResolveDestinationIp,
}

impl Decision {
    #[must_use]
    pub fn route(&self) -> Route {
        match self.target.as_str() {
            "DIRECT" | "COMPATIBLE" => Route::Direct,
            "REJECT" => Route::Reject,
            "REJECT-DROP" => Route::RejectDrop,
            _ => Route::Unsupported,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuleSet {
    pub(crate) rules: Vec<Rule>,
    pub(crate) sub_rules: BTreeMap<String, Vec<Rule>>,
    pub(crate) actions: BTreeMap<String, Action>,
    pub(crate) runtime: Vec<Arc<RuleRuntime>>,
}

#[derive(Debug, Default)]
pub(crate) struct RuleRuntime {
    pub(crate) disabled: AtomicBool,
    pub(crate) hit_count: AtomicU64,
    pub(crate) hit_at_unix_nanos: AtomicI64,
    pub(crate) miss_count: AtomicU64,
    pub(crate) miss_at_unix_nanos: AtomicI64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSnapshot {
    pub index: usize,
    pub kind: String,
    pub payload: String,
    pub target: String,
    pub size: i64,
    pub disabled: bool,
    pub hit_count: u64,
    pub hit_at_unix_nanos: i64,
    pub miss_count: u64,
    pub miss_at_unix_nanos: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Select,
    Pass,
    PassRule,
    Rematch(RematchSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Rule {
    pub(crate) matcher: Matcher,
    pub(crate) target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Matcher {
    Match,
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(DomainRegex),
    DomainWildcard(String),
    IpCidr {
        network: IpNet,
        source: bool,
        no_resolve: bool,
    },
    IpSuffix {
        address: std::net::IpAddr,
        bits: u8,
        source: bool,
        no_resolve: bool,
    },
    Port {
        ranges: Vec<PortRange>,
        field: PortField,
    },
    Network(Network),
    InType(Vec<rewrite_model::InboundProtocol>),
    InUser(Vec<String>),
    InName(Vec<String>),
    Dscp(Vec<DscpRange>),
    RematchName(Vec<String>),
    And(Vec<Matcher>),
    Or(Vec<Matcher>),
    Not(Box<Matcher>),
    SubRule {
        condition: Box<Matcher>,
        name: String,
    },
    RuleSet {
        name: String,
        matchers: Vec<Matcher>,
        no_resolve: bool,
    },
    Geo {
        kind: GeoMatcherKind,
        payload: String,
        matchers: Vec<Matcher>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GeoMatcherKind {
    GeoSite,
    GeoIp,
    SrcGeoIp,
}

#[derive(Clone, Debug)]
pub(crate) struct DomainRegex {
    pub(crate) pattern: String,
    pub(crate) expression: fancy_regex::Regex,
}

impl PartialEq for DomainRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for DomainRegex {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortField {
    Source,
    Destination,
    Inbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortRange {
    pub(crate) start: u16,
    pub(crate) end: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DscpRange {
    pub(crate) start: u8,
    pub(crate) end: u8,
}

pub(crate) enum RuleMatchResult {
    Target(String),
    NoMatch,
    ResolveDestinationIp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MatchResult {
    Matched,
    Unmatched,
    ResolveDestinationIp,
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("format invalid")]
    FormatInvalid,
    #[error("unsupported rule type: {0}")]
    Unsupported(String),
    #[error("invalid rule payload")]
    InvalidPayload,
    #[error("proxy [{0}] not found")]
    ProxyNotFound(String),
    #[error("sub-rule [{0}] not found")]
    SubRuleNotFound(String),
    #[error("sub-rule name is empty")]
    EmptySubRuleName,
    #[error("sub-rule error: circular references [{0}]")]
    SubRuleCycle(String),
}
