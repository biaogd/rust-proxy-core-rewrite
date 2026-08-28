use serde::Deserialize;

use crate::model::{RulesetError, SourceFormat};

#[derive(Debug, Default, Deserialize)]
struct RulePayload {
    #[serde(default)]
    payload: Vec<String>,
    #[serde(default)]
    rules: Vec<String>,
}

pub(crate) fn parse_rules(
    source: &[u8],
    format: SourceFormat,
) -> Result<Vec<String>, RulesetError> {
    match format {
        SourceFormat::Text => Ok(String::from_utf8_lossy(source)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
            .map(ToOwned::to_owned)
            .collect()),
        SourceFormat::Yaml => parse_yaml_rules(source),
    }
}

pub(crate) fn parse_yaml_rules(source: &[u8]) -> Result<Vec<String>, RulesetError> {
    let mut header = Vec::new();
    let mut header_found = false;
    let mut rules = Vec::new();
    for line in source.split_inclusive(|byte| *byte == b'\n') {
        if !line.ends_with(b"\n") && !header_found {
            return Err(RulesetError::MissingPayload);
        }
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() || trimmed.starts_with(b"#") {
            continue;
        }
        if !header_found {
            header.extend(line);
            let header_length = header.len();
            header.extend(b"  - ''");
            let candidate = serde_yaml_ng::from_slice::<RulePayload>(&header);
            header.truncate(header_length);
            if candidate
                .as_ref()
                .is_ok_and(|payload| !payload.rules.is_empty() || !payload.payload.is_empty())
            {
                header_found = true;
            } else {
                header.clear();
            }
            continue;
        }
        let header_length = header.len();
        header.extend(line);
        if let Ok(payload) = serde_yaml_ng::from_slice::<RulePayload>(&header)
            && let Some(rule) = payload.payload.first().or_else(|| payload.rules.first())
            && !rule.is_empty()
        {
            rules.push(rule.clone());
        }
        header.truncate(header_length);
    }
    Ok(rules)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}
