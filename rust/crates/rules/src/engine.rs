use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use rewrite_model::Metadata;

use crate::model::{
    Action, Decision, LazyEvaluation, MatchResult, Matcher, ProviderDefinition, RematchSpec, Route,
    Rule, RuleError, RuleMatchResult, RuleRuntime, RuleSet, RuleSnapshot,
};
use crate::parser::{make_decision, parse_rule_list, verify_sub_rule_cycles};

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
        Self::parse_with_targets(lines, raw_sub_rules, rematches, &BTreeSet::new())
    }

    /// Parses a rule program with additional configured outbound/group names.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError`] under the same conditions as [`Self::parse`].
    pub fn parse_with_targets(
        lines: &[String],
        raw_sub_rules: &BTreeMap<String, Vec<String>>,
        rematches: &[RematchSpec],
        targets: &BTreeSet<String>,
    ) -> Result<Self, RuleError> {
        Self::parse_with_targets_and_providers(
            lines,
            raw_sub_rules,
            rematches,
            targets,
            &BTreeMap::new(),
        )
    }

    /// Parses a rule program with additional targets and provider payloads.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError`] for malformed rules, targets, provider references
    /// or provider entries.
    pub fn parse_with_targets_and_providers(
        lines: &[String],
        raw_sub_rules: &BTreeMap<String, Vec<String>>,
        rematches: &[RematchSpec],
        targets: &BTreeSet<String>,
        providers: &BTreeMap<String, ProviderDefinition>,
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
        for target in targets {
            actions.insert(target.clone(), Action::Select);
        }

        if raw_sub_rules.keys().any(String::is_empty) {
            return Err(RuleError::EmptySubRuleName);
        }
        let sub_rule_names: BTreeSet<_> = raw_sub_rules.keys().cloned().collect();
        let rules = parse_rule_list(lines, &actions, &sub_rule_names, providers)?;
        let mut sub_rules = BTreeMap::new();
        for (name, raw_rules) in raw_sub_rules {
            sub_rules.insert(
                name.clone(),
                parse_rule_list(raw_rules, &actions, &sub_rule_names, providers)?,
            );
        }
        verify_sub_rule_cycles(&sub_rules)?;

        Ok(Self {
            runtime: (0..rules.len())
                .map(|_| Arc::new(RuleRuntime::default()))
                .collect(),
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

    pub(crate) fn evaluate_internal(
        &self,
        metadata: &Metadata,
        allow_resolution: bool,
    ) -> LazyEvaluation {
        let mut metadata = metadata.clone();
        let mut rematch_chain = BTreeSet::new();
        for _ in 0..64 {
            let top_level = metadata.special_rules.is_empty();
            let rules = self
                .sub_rules
                .get(&metadata.special_rules)
                .unwrap_or(&self.rules);
            let mut pending_rematch: Option<(&Rule, &RematchSpec)> = None;

            for (index, rule) in rules.iter().enumerate() {
                let runtime = top_level.then(|| &self.runtime[index]);
                if runtime.is_some_and(|runtime| runtime.disabled.load(Ordering::Acquire)) {
                    continue;
                }
                let target = match rule.match_target(&metadata, self, allow_resolution) {
                    RuleMatchResult::Target(target) => target,
                    RuleMatchResult::NoMatch => {
                        if let Some(runtime) = runtime {
                            runtime.record_miss();
                        }
                        continue;
                    }
                    RuleMatchResult::ResolveDestinationIp => {
                        return LazyEvaluation::ResolveDestinationIp;
                    }
                };
                if let Some(runtime) = runtime {
                    runtime.record_hit();
                }
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
    pub fn snapshots(&self) -> Vec<RuleSnapshot> {
        self.rules
            .iter()
            .zip(&self.runtime)
            .enumerate()
            .map(|(index, (rule, runtime))| RuleSnapshot {
                index,
                kind: rule.kind(),
                payload: rule.payload(),
                target: rule.target.clone(),
                size: rule.matcher.record_size(),
                disabled: runtime.disabled.load(Ordering::Acquire),
                hit_count: runtime.hit_count.load(Ordering::Relaxed),
                hit_at_unix_nanos: runtime.hit_at_unix_nanos.load(Ordering::Relaxed),
                miss_count: runtime.miss_count.load(Ordering::Relaxed),
                miss_at_unix_nanos: runtime.miss_at_unix_nanos.load(Ordering::Relaxed),
            })
            .collect()
    }

    pub fn set_disabled(&self, index: usize, disabled: bool) {
        if let Some(runtime) = self.runtime.get(index) {
            runtime.disabled.store(disabled, Ordering::Release);
        }
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
        self.is_phase_three_tcp_with_targets(&BTreeSet::new())
    }

    #[must_use]
    pub fn is_phase_three_tcp_with_targets(&self, targets: &BTreeSet<String>) -> bool {
        self.rules
            .iter()
            .all(|rule| rule.has_executable_tcp_target(&self.actions, targets))
            && self
                .sub_rules
                .values()
                .flatten()
                .all(|rule| rule.has_executable_tcp_target(&self.actions, targets))
    }

    pub(crate) fn match_sub_rules(
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
    pub(crate) fn match_target(
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

    pub(crate) fn kind(&self) -> String {
        self.matcher.kind().to_owned()
    }

    pub(crate) fn payload(&self) -> String {
        self.matcher.payload()
    }

    pub(crate) fn has_executable_tcp_target(
        &self,
        actions: &BTreeMap<String, Action>,
        targets: &BTreeSet<String>,
    ) -> bool {
        matches!(self.matcher, Matcher::SubRule { .. })
            || matches!(
                self.target.as_str(),
                "DIRECT" | "COMPATIBLE" | "REJECT" | "REJECT-DROP" | "PASS" | "PASS-RULE"
            )
            || matches!(actions.get(&self.target), Some(Action::Rematch(_)))
            || targets.contains(&self.target)
    }
}

impl RuleRuntime {
    pub(crate) fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        self.hit_at_unix_nanos
            .store(now_unix_nanos(), Ordering::Relaxed);
    }

    pub(crate) fn record_miss(&self) {
        self.miss_count.fetch_add(1, Ordering::Relaxed);
        self.miss_at_unix_nanos
            .store(now_unix_nanos(), Ordering::Relaxed);
    }
}

pub(crate) fn now_unix_nanos() -> i64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    i64::try_from(nanos).unwrap_or(i64::MAX)
}
