use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use ipnet::IpNet;
use rewrite_model::{Metadata, Network};
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
            "DIRECT" => Route::Direct,
            "REJECT" => Route::Reject,
            "REJECT-DROP" => Route::RejectDrop,
            _ => Route::Unsupported,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSet {
    rules: Vec<Rule>,
    sub_rules: BTreeMap<String, Vec<Rule>>,
    actions: BTreeMap<String, Action>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    Select,
    Pass,
    PassRule,
    Rematch(RematchSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Rule {
    matcher: Matcher,
    target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Matcher {
    Match,
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(DomainRegex),
    IpCidr {
        network: IpNet,
        source: bool,
        no_resolve: bool,
    },
    Port {
        ranges: Vec<PortRange>,
        field: PortField,
    },
    Network(Network),
    RematchName(Vec<String>),
    And(Vec<Matcher>),
    Or(Vec<Matcher>),
    Not(Box<Matcher>),
    SubRule {
        condition: Box<Matcher>,
        name: String,
    },
}

#[derive(Clone, Debug)]
struct DomainRegex {
    pattern: String,
    expression: fancy_regex::Regex,
}

impl PartialEq for DomainRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for DomainRegex {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortField {
    Source,
    Destination,
    Inbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PortRange {
    start: u16,
    end: u16,
}

enum RuleMatchResult {
    Target(String),
    NoMatch,
    ResolveDestinationIp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatchResult {
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

impl RuleSet {
    /// Parses the Phase 2 pure rule program and validates all references.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError`] for malformed or unsupported rules, invalid pure
    /// payloads, unknown targets and sub-rule cycles.
    pub fn parse(
        lines: &[String],
        raw_sub_rules: &BTreeMap<String, Vec<String>>,
        rematches: &[RematchSpec],
    ) -> Result<Self, RuleError> {
        let mut actions = BTreeMap::from([
            ("DIRECT".to_owned(), Action::Select),
            ("REJECT".to_owned(), Action::Select),
            ("REJECT-DROP".to_owned(), Action::Select),
            ("COMPATIBLE".to_owned(), Action::Select),
            ("PASS".to_owned(), Action::Pass),
            ("PASS-RULE".to_owned(), Action::PassRule),
        ]);
        for rematch in rematches {
            if rematch.target_rematch_name.is_none() && rematch.target_sub_rule.is_none() {
                return Err(RuleError::InvalidPayload);
            }
            actions.insert(rematch.name.clone(), Action::Rematch(rematch.clone()));
        }

        if raw_sub_rules.keys().any(String::is_empty) {
            return Err(RuleError::EmptySubRuleName);
        }
        let sub_rule_names: BTreeSet<_> = raw_sub_rules.keys().cloned().collect();
        let rules = parse_rule_list(lines, &actions, &sub_rule_names)?;
        let mut sub_rules = BTreeMap::new();
        for (name, raw_rules) in raw_sub_rules {
            sub_rules.insert(
                name.clone(),
                parse_rule_list(raw_rules, &actions, &sub_rule_names)?,
            );
        }
        verify_sub_rule_cycles(&sub_rules)?;

        Ok(Self {
            rules,
            sub_rules,
            actions,
        })
    }

    #[must_use]
    pub fn evaluate(&self, metadata: &Metadata) -> Decision {
        match self.evaluate_internal(metadata, false) {
            LazyEvaluation::Decision(decision) => decision,
            LazyEvaluation::ResolveDestinationIp => {
                unreachable!("non-lazy evaluation cannot request resolution")
            }
        }
    }

    #[must_use]
    pub fn evaluate_lazy(&self, metadata: &Metadata) -> LazyEvaluation {
        self.evaluate_internal(metadata, true)
    }

    fn evaluate_internal(&self, metadata: &Metadata, allow_resolution: bool) -> LazyEvaluation {
        let mut metadata = metadata.clone();
        let mut rematch_chain = BTreeSet::new();
        for _ in 0..64 {
            let rules = self
                .sub_rules
                .get(&metadata.special_rules)
                .unwrap_or(&self.rules);
            let mut pending_rematch: Option<(&Rule, &RematchSpec)> = None;

            for rule in rules {
                let target = match rule.match_target(&metadata, self, allow_resolution) {
                    RuleMatchResult::Target(target) => target,
                    RuleMatchResult::NoMatch => continue,
                    RuleMatchResult::ResolveDestinationIp => {
                        return LazyEvaluation::ResolveDestinationIp;
                    }
                };
                let Some(action) = self.actions.get(&target) else {
                    continue;
                };
                match action {
                    Action::Pass => {}
                    Action::Rematch(spec) => {
                        pending_rematch = Some((rule, spec));
                        break;
                    }
                    Action::Select | Action::PassRule => {
                        return LazyEvaluation::Decision(make_decision(
                            target,
                            Some(rule.kind()),
                            false,
                            &metadata,
                        ));
                    }
                }
            }

            let Some((rule, rematch)) = pending_rematch else {
                return LazyEvaluation::Decision(make_decision(
                    "DIRECT".to_owned(),
                    None,
                    false,
                    &metadata,
                ));
            };
            if !rematch_chain.insert(rematch.name.clone()) {
                return LazyEvaluation::Decision(make_decision(
                    rematch.name.clone(),
                    Some(rule.kind()),
                    true,
                    &metadata,
                ));
            }
            if let Some(name) = &rematch.target_rematch_name {
                metadata.rematch_name.clone_from(name);
            }
            if let Some(name) = &rematch.target_sub_rule {
                metadata.special_rules.clone_from(name);
            }
        }
        LazyEvaluation::Decision(make_decision("DIRECT".to_owned(), None, true, &metadata))
    }

    #[must_use]
    pub fn select(&self, metadata: &Metadata) -> Route {
        self.evaluate(metadata).route()
    }

    #[must_use]
    pub fn is_phase_one_direct(&self) -> bool {
        self.sub_rules.is_empty()
            && self
                .actions
                .values()
                .all(|action| !matches!(action, Action::Rematch(_)))
            && matches!(
                self.rules.as_slice(),
                [Rule {
                    matcher: Matcher::Match,
                    target,
                }] if target == "DIRECT"
            )
    }

    #[must_use]
    pub fn is_phase_three_tcp(&self) -> bool {
        self.actions
            .values()
            .all(|action| !matches!(action, Action::Rematch(_)))
            && self.rules.iter().all(Rule::has_phase_three_target)
            && self
                .sub_rules
                .values()
                .flatten()
                .all(Rule::has_phase_three_target)
    }

    fn match_sub_rules(
        &self,
        name: &str,
        metadata: &Metadata,
        allow_resolution: bool,
    ) -> RuleMatchResult {
        let Some(rules) = self.sub_rules.get(name) else {
            return RuleMatchResult::NoMatch;
        };
        for rule in rules {
            let target = match rule.match_target(metadata, self, allow_resolution) {
                RuleMatchResult::Target(target) => target,
                RuleMatchResult::NoMatch => continue,
                RuleMatchResult::ResolveDestinationIp => {
                    return RuleMatchResult::ResolveDestinationIp;
                }
            };
            if target == "PASS-RULE" || matches!(self.actions.get(&target), Some(Action::PassRule))
            {
                continue;
            }
            return RuleMatchResult::Target(target);
        }
        RuleMatchResult::NoMatch
    }
}

impl Rule {
    fn match_target(
        &self,
        metadata: &Metadata,
        program: &RuleSet,
        allow_resolution: bool,
    ) -> RuleMatchResult {
        match &self.matcher {
            Matcher::SubRule { condition, name } => {
                match condition.match_result(metadata, allow_resolution) {
                    MatchResult::Matched => {
                        program.match_sub_rules(name, metadata, allow_resolution)
                    }
                    MatchResult::Unmatched => RuleMatchResult::NoMatch,
                    MatchResult::ResolveDestinationIp => RuleMatchResult::ResolveDestinationIp,
                }
            }
            matcher => match matcher.match_result(metadata, allow_resolution) {
                MatchResult::Matched => RuleMatchResult::Target(self.target.clone()),
                MatchResult::Unmatched => RuleMatchResult::NoMatch,
                MatchResult::ResolveDestinationIp => RuleMatchResult::ResolveDestinationIp,
            },
        }
    }

    fn kind(&self) -> String {
        self.matcher.kind().to_owned()
    }

    fn has_phase_three_target(&self) -> bool {
        matches!(self.matcher, Matcher::SubRule { .. })
            || matches!(
                self.target.as_str(),
                "DIRECT" | "REJECT" | "PASS" | "PASS-RULE"
            )
    }
}

impl Matcher {
    fn match_result(&self, metadata: &Metadata, allow_resolution: bool) -> MatchResult {
        match self {
            Self::Match => MatchResult::Matched,
            Self::Domain(domain) => MatchResult::from_bool(metadata.rule_host() == domain),
            Self::DomainSuffix(suffix) => MatchResult::from_bool(
                metadata.rule_host() == suffix
                    || metadata
                        .rule_host()
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.')),
            ),
            Self::DomainKeyword(keyword) => {
                MatchResult::from_bool(metadata.rule_host().contains(keyword))
            }
            Self::DomainRegex(regex) => MatchResult::from_bool(
                regex
                    .expression
                    .is_match(metadata.rule_host())
                    .unwrap_or(false),
            ),
            Self::IpCidr {
                network,
                source,
                no_resolve,
            } => {
                let address = if *source {
                    metadata.source_ip
                } else {
                    metadata.destination_ip
                };
                match address {
                    Some(address) => MatchResult::from_bool(network.contains(&address)),
                    None if !source && !no_resolve && allow_resolution => {
                        MatchResult::ResolveDestinationIp
                    }
                    None => MatchResult::Unmatched,
                }
            }
            Self::Port { ranges, field } => {
                let port = match field {
                    PortField::Source => metadata.source_port,
                    PortField::Destination => metadata.destination.port,
                    PortField::Inbound => metadata.inbound_port,
                };
                MatchResult::from_bool(
                    ranges
                        .iter()
                        .any(|range| (range.start..=range.end).contains(&port)),
                )
            }
            Self::Network(network) => MatchResult::from_bool(metadata.network == *network),
            Self::RematchName(names) => {
                MatchResult::from_bool(names.contains(&metadata.rematch_name))
            }
            Self::And(matchers) => {
                for matcher in matchers {
                    match matcher.match_result(metadata, allow_resolution) {
                        MatchResult::Matched => {}
                        result => return result,
                    }
                }
                MatchResult::Matched
            }
            Self::Or(matchers) => {
                for matcher in matchers {
                    match matcher.match_result(metadata, allow_resolution) {
                        MatchResult::Unmatched => {}
                        result => return result,
                    }
                }
                MatchResult::Unmatched
            }
            Self::Not(matcher) => match matcher.match_result(metadata, allow_resolution) {
                MatchResult::Matched => MatchResult::Unmatched,
                MatchResult::Unmatched => MatchResult::Matched,
                MatchResult::ResolveDestinationIp => MatchResult::ResolveDestinationIp,
            },
            Self::SubRule { condition, .. } => condition.match_result(metadata, allow_resolution),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Match => "Match",
            Self::Domain(_) => "Domain",
            Self::DomainSuffix(_) => "DomainSuffix",
            Self::DomainKeyword(_) => "DomainKeyword",
            Self::DomainRegex(_) => "DomainRegex",
            Self::IpCidr { source: true, .. } => "SrcIPCIDR",
            Self::IpCidr { source: false, .. } => "IPCIDR",
            Self::Port {
                field: PortField::Source,
                ..
            } => "SrcPort",
            Self::Port {
                field: PortField::Destination,
                ..
            } => "DstPort",
            Self::Port {
                field: PortField::Inbound,
                ..
            } => "InPort",
            Self::Network(_) => "Network",
            Self::RematchName(_) => "RematchName",
            Self::And(_) => "AND",
            Self::Or(_) => "OR",
            Self::Not(_) => "NOT",
            Self::SubRule { .. } => "SubRules",
        }
    }
}

impl MatchResult {
    const fn from_bool(value: bool) -> Self {
        if value {
            Self::Matched
        } else {
            Self::Unmatched
        }
    }
}

fn parse_rule_list(
    lines: &[String],
    actions: &BTreeMap<String, Action>,
    sub_rules: &BTreeSet<String>,
) -> Result<Vec<Rule>, RuleError> {
    lines
        .iter()
        .map(|line| parse_rule(line, actions, sub_rules))
        .collect()
}

fn parse_rule(
    raw: &str,
    actions: &BTreeMap<String, Action>,
    sub_rules: &BTreeSet<String>,
) -> Result<Rule, RuleError> {
    let fields = parse_rule_payload(raw, true);
    if fields.target.is_empty() {
        return Err(RuleError::FormatInvalid);
    }
    if fields.kind == "SUB-RULE" {
        if !sub_rules.contains(&fields.target) {
            return Err(RuleError::SubRuleNotFound(fields.target));
        }
    } else if !actions.contains_key(&fields.target) {
        return Err(RuleError::ProxyNotFound(fields.target));
    }
    let matcher = parse_matcher(&fields.kind, &fields.payload, &fields.params)?;
    let matcher = if fields.kind == "SUB-RULE" {
        Matcher::SubRule {
            condition: Box::new(matcher),
            name: fields.target.clone(),
        }
    } else {
        matcher
    };
    Ok(Rule {
        matcher,
        target: fields.target,
    })
}

struct RuleFields {
    kind: String,
    payload: String,
    target: String,
    params: Vec<String>,
}

fn parse_rule_payload(raw: &str, need_target: bool) -> RuleFields {
    let mut items: Vec<_> = raw.split(',').map(str::trim).collect();
    let kind = items
        .first()
        .map_or(String::new(), |item| item.to_uppercase());
    let mut payload = String::new();
    let mut target = String::new();
    let mut params = Vec::new();
    if items.len() > 1 {
        match kind.as_str() {
            "MATCH" => items[1].clone_into(&mut target),
            "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX" => {
                if need_target {
                    items.pop().unwrap_or_default().clone_into(&mut target);
                }
                payload = items[1..].join(",");
            }
            _ => {
                items[1].clone_into(&mut payload);
                if items.len() > 2 {
                    if need_target {
                        items[2].clone_into(&mut target);
                        params.extend(items[3..].iter().map(|item| (*item).to_owned()));
                    } else {
                        params.extend(items[2..].iter().map(|item| (*item).to_owned()));
                    }
                }
            }
        }
    }
    RuleFields {
        kind,
        payload,
        target,
        params,
    }
}

fn parse_matcher(kind: &str, payload: &str, params: &[String]) -> Result<Matcher, RuleError> {
    match kind {
        "MATCH" => Ok(Matcher::Match),
        "DOMAIN" => require_payload(payload, |value| Matcher::Domain(value.to_lowercase())),
        "DOMAIN-SUFFIX" => {
            require_payload(payload, |value| Matcher::DomainSuffix(value.to_lowercase()))
        }
        "DOMAIN-KEYWORD" => require_payload(payload, |value| {
            Matcher::DomainKeyword(value.to_lowercase())
        }),
        "DOMAIN-REGEX" => parse_domain_regex(payload),
        "IP-CIDR" | "IP-CIDR6" => parse_ip_cidr(
            payload,
            params.iter().any(|param| param == "src"),
            params.iter().any(|param| param == "no-resolve"),
        ),
        "SRC-IP-CIDR" => parse_ip_cidr(payload, true, true),
        "SRC-PORT" => parse_port(payload, PortField::Source),
        "DST-PORT" => parse_port(payload, PortField::Destination),
        "IN-PORT" => parse_port(payload, PortField::Inbound),
        "NETWORK" => match payload.to_uppercase().as_str() {
            "TCP" => Ok(Matcher::Network(Network::Tcp)),
            "UDP" => Ok(Matcher::Network(Network::Udp)),
            _ => Err(RuleError::Unsupported("NETWORK".to_owned())),
        },
        "REMATCH-NAME" => {
            let names: Vec<_> = payload
                .split('/')
                .map(str::trim)
                .map(str::to_owned)
                .collect();
            if names.iter().any(String::is_empty) {
                Err(RuleError::InvalidPayload)
            } else {
                Ok(Matcher::RematchName(names))
            }
        }
        "AND" => Ok(Matcher::And(parse_logic_children(payload)?)),
        "OR" => Ok(Matcher::Or(parse_logic_children(payload)?)),
        "NOT" => {
            let children = parse_logic_children(payload)?;
            let [child] = children.try_into().map_err(|_| RuleError::InvalidPayload)?;
            Ok(Matcher::Not(Box::new(child)))
        }
        "SUB-RULE" => {
            let wrapped = format!("({payload})");
            let children = parse_logic_children(&wrapped)?;
            let [child] = children.try_into().map_err(|_| RuleError::InvalidPayload)?;
            Ok(child)
        }
        "" => Err(RuleError::FormatInvalid),
        other => Err(RuleError::Unsupported(other.to_owned())),
    }
}

fn parse_domain_regex(payload: &str) -> Result<Matcher, RuleError> {
    if payload.is_empty() {
        return Err(RuleError::InvalidPayload);
    }
    let expression = fancy_regex::Regex::new(&format!("(?i:{payload})"))
        .map_err(|_| RuleError::InvalidPayload)?;
    Ok(Matcher::DomainRegex(DomainRegex {
        pattern: payload.to_owned(),
        expression,
    }))
}

fn require_payload(
    payload: &str,
    make: impl FnOnce(&str) -> Matcher,
) -> Result<Matcher, RuleError> {
    if payload.is_empty() {
        Err(RuleError::InvalidPayload)
    } else {
        Ok(make(payload))
    }
}

fn parse_ip_cidr(payload: &str, source: bool, no_resolve: bool) -> Result<Matcher, RuleError> {
    let network = IpNet::from_str(payload).map_err(|_| RuleError::InvalidPayload)?;
    Ok(Matcher::IpCidr {
        network,
        source,
        no_resolve,
    })
}

fn parse_port(payload: &str, field: PortField) -> Result<Matcher, RuleError> {
    let normalized = payload.trim().replace(',', "/");
    if normalized.is_empty() || normalized == "*" {
        return Err(RuleError::InvalidPayload);
    }
    let parts: Vec<_> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() || parts.len() > 28 {
        return Err(RuleError::InvalidPayload);
    }
    let mut ranges = Vec::with_capacity(parts.len());
    for part in parts {
        let bounds: Vec<_> = part.split('-').map(str::trim).collect();
        let (start, end) = match bounds.as_slice() {
            [single] => {
                let value = parse_port_number(single)?;
                (value, value)
            }
            [start, end] => (parse_port_number(start)?, parse_port_number(end)?),
            _ => return Err(RuleError::InvalidPayload),
        };
        ranges.push(PortRange {
            start: start.min(end),
            end: start.max(end),
        });
    }
    Ok(Matcher::Port { ranges, field })
}

#[allow(clippy::cast_possible_truncation)]
fn parse_port_number(value: &str) -> Result<u16, RuleError> {
    let parsed = value
        .trim_matches(['[', ']', ' '])
        .parse::<u64>()
        .map_err(|_| RuleError::InvalidPayload)?;
    // The Go oracle parses into uint64 and then converts to uint16, including
    // wraparound. Preserve that observable compatibility at this boundary.
    Ok(parsed as u16)
}

fn parse_logic_children(payload: &str) -> Result<Vec<Matcher>, RuleError> {
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return Err(RuleError::FormatInvalid);
    }
    let mut stack = Vec::new();
    let mut ranges = Vec::new();
    for (index, character) in payload.char_indices() {
        match character {
            '(' => stack.push(index),
            ')' => {
                let start = stack.pop().ok_or(RuleError::FormatInvalid)?;
                ranges.push((start, index));
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(RuleError::FormatInvalid);
    }
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut immediate: Vec<(usize, usize)> = Vec::new();
    for range in ranges {
        if range == (0, payload.len() - 1) {
            continue;
        }
        if immediate
            .iter()
            .any(|(start, end)| *start < range.0 && *end > range.1)
        {
            continue;
        }
        immediate.push(range);
    }

    immediate
        .into_iter()
        .map(|(start, end)| {
            let child = &payload[(start + 1)..end];
            let fields = parse_rule_payload(child, false);
            if matches!(fields.kind.as_str(), "MATCH" | "SUB-RULE" | "") {
                return Err(RuleError::Unsupported(fields.kind));
            }
            parse_matcher(&fields.kind, &fields.payload, &fields.params)
        })
        .collect()
}

fn verify_sub_rule_cycles(sub_rules: &BTreeMap<String, Vec<Rule>>) -> Result<(), RuleError> {
    for name in sub_rules.keys() {
        visit_sub_rule(name, sub_rules, &mut Vec::new())?;
    }
    Ok(())
}

fn visit_sub_rule(
    name: &str,
    sub_rules: &BTreeMap<String, Vec<Rule>>,
    chain: &mut Vec<String>,
) -> Result<(), RuleError> {
    chain.push(name.to_owned());
    if let Some(rules) = sub_rules.get(name) {
        for rule in rules {
            if let Matcher::SubRule { name: target, .. } = &rule.matcher {
                if let Some(position) = chain.iter().position(|name| name == target) {
                    let mut cycle = chain[position..].to_vec();
                    cycle.push(target.clone());
                    return Err(RuleError::SubRuleCycle(cycle.join("->")));
                }
                visit_sub_rule(target, sub_rules, chain)?;
            }
        }
    }
    chain.pop();
    Ok(())
}

fn make_decision(
    target: String,
    matched_kind: Option<String>,
    rematch_cycle: bool,
    metadata: &Metadata,
) -> Decision {
    Decision {
        target,
        matched_kind,
        rematch_cycle,
        rematch_name: metadata.rematch_name.clone(),
        special_rules: metadata.special_rules.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rewrite_model::{Destination, Host, InboundProtocol};

    use super::*;

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
}
