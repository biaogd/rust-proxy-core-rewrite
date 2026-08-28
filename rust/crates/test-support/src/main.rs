use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::IpAddr;

use rewrite_config::{ConfigError, ConfigSpec, NormalizedConfig};
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network};
use rewrite_rules::{Decision, RematchSpec, RuleError, RuleSet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Config {
        #[serde(rename = "yaml")]
        source: String,
    },
    Rules {
        #[serde(default)]
        rules: Vec<String>,
        #[serde(default, rename = "sub-rules")]
        sub_rules: BTreeMap<String, Vec<String>>,
        #[serde(default)]
        rematches: Vec<RematchInput>,
        #[serde(default)]
        metadata: Box<MetadataInput>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RematchInput {
    name: String,
    target_rematch_name: Option<String>,
    target_sub_rule: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct MetadataInput {
    network: String,
    host: String,
    sniff_host: String,
    source_ip: String,
    destination_ip: String,
    source_port: u16,
    destination_port: u16,
    inbound_port: u16,
    rematch_name: String,
    special_rules: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Response {
    accepted: bool,
    error_class: Option<&'static str>,
    config: Option<NormalizedConfig>,
    decision: Option<DecisionOutput>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct DecisionOutput {
    target: String,
    matched_kind: Option<String>,
    rematch_cycle: bool,
    final_metadata: FinalMetadata,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct FinalMetadata {
    rematch_name: String,
    special_rules: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let requests: Vec<Request> = serde_json::from_str(&input)?;
    let responses: Vec<_> = requests.into_iter().map(observe).collect();
    serde_json::to_writer(io::stdout().lock(), &responses)?;
    Ok(())
}

fn observe(request: Request) -> Response {
    match request {
        Request::Config { source } => match ConfigSpec::from_yaml(&source) {
            Ok(specification) => Response {
                accepted: true,
                error_class: None,
                config: Some(specification.normalized()),
                decision: None,
            },
            Err(error) => rejected(classify_config_error(&error)),
        },
        Request::Rules {
            rules,
            sub_rules,
            rematches,
            metadata,
        } => observe_rules(&rules, &sub_rules, rematches, *metadata),
    }
}

fn observe_rules(
    rules: &[String],
    sub_rules: &BTreeMap<String, Vec<String>>,
    rematches: Vec<RematchInput>,
    metadata: MetadataInput,
) -> Response {
    let rematches: Vec<_> = rematches
        .into_iter()
        .map(|input| RematchSpec {
            name: input.name,
            target_rematch_name: input.target_rematch_name,
            target_sub_rule: input.target_sub_rule,
        })
        .collect();
    let program = match RuleSet::parse(rules, sub_rules, &rematches) {
        Ok(program) => program,
        Err(error) => return rejected(classify_rule_error(&error)),
    };
    let Ok(metadata) = make_metadata(metadata) else {
        return rejected("invalid-metadata");
    };
    Response {
        accepted: true,
        error_class: None,
        config: None,
        decision: Some(program.evaluate(&metadata).into()),
    }
}

fn make_metadata(input: MetadataInput) -> Result<Metadata, ()> {
    let destination_ip = parse_optional_ip(&input.destination_ip)?;
    let destination_host = if input.host.is_empty() {
        destination_ip.map_or_else(|| Host::Domain(String::new()), Host::Ip)
    } else {
        Host::Domain(input.host.clone())
    };
    let mut metadata = Metadata::new(
        Destination {
            host: destination_host,
            port: input.destination_port,
        },
        InboundProtocol::Socks5,
    );
    metadata.network = match input.network.to_uppercase().as_str() {
        "" | "TCP" => Network::Tcp,
        "UDP" => Network::Udp,
        _ => return Err(()),
    };
    metadata.host = input.host;
    metadata.sniff_host = input.sniff_host;
    metadata.source_ip = parse_optional_ip(&input.source_ip)?;
    metadata.destination_ip = destination_ip;
    metadata.source_port = input.source_port;
    metadata.inbound_port = input.inbound_port;
    metadata.rematch_name = input.rematch_name;
    metadata.special_rules = input.special_rules;
    Ok(metadata)
}

fn parse_optional_ip(value: &str) -> Result<Option<IpAddr>, ()> {
    if value.is_empty() {
        Ok(None)
    } else {
        value.parse().map(Some).map_err(|_| ())
    }
}

impl From<Decision> for DecisionOutput {
    fn from(decision: Decision) -> Self {
        Self {
            target: decision.target,
            matched_kind: decision.matched_kind,
            rematch_cycle: decision.rematch_cycle,
            final_metadata: FinalMetadata {
                rematch_name: decision.rematch_name,
                special_rules: decision.special_rules,
            },
        }
    }
}

fn rejected(error_class: &'static str) -> Response {
    Response {
        accepted: false,
        error_class: Some(error_class),
        config: None,
        decision: None,
    }
}

fn classify_config_error(error: &ConfigError) -> &'static str {
    match error {
        ConfigError::Yaml(_) => "yaml",
        ConfigError::InvalidMode => "invalid-mode",
        ConfigError::InvalidLogLevel => "invalid-log-level",
        ConfigError::Rule(error) => classify_rule_error(error),
        ConfigError::UnsupportedProxy(_) => "unsupported-proxy",
        ConfigError::Io(_)
        | ConfigError::UnsupportedKey(_)
        | ConfigError::InvalidRuntimePort(_)
        | ConfigError::InvalidControllerAddress(_)
        | ConfigError::InvalidConfigPath
        | ConfigError::UnsafeConfigPath { .. }
        | ConfigError::InvalidDns(_)
        | ConfigError::InvalidHosts(_)
        | ConfigError::UnsupportedRuntime(_) => "other",
    }
}

fn classify_rule_error(error: &RuleError) -> &'static str {
    match error {
        RuleError::FormatInvalid => "rule-format",
        RuleError::Unsupported(_) => "unsupported-rule",
        RuleError::InvalidPayload => "invalid-rule-payload",
        RuleError::ProxyNotFound(_) => "proxy-not-found",
        RuleError::SubRuleNotFound(_) => "sub-rule-not-found",
        RuleError::EmptySubRuleName => "sub-rule-name",
        RuleError::SubRuleCycle(_) => "sub-rule-cycle",
    }
}
