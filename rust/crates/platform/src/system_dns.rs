//! Darwin system DNS ownership via `scutil` (no `SystemConfiguration` FFI).
//!
//! macOS applications resolve through getaddrinfo / the primary network
//! service. Packet hijack of `8.8.8.8:53` on the TUN is not enough: the
//! resolver never sends those packets unless the system DNS servers are
//! pointed at the TUN DNS address (Go: TUN IPv4 next address).
//!
//! Linux 8A hijacks DNS at the packet layer and does not rewrite resolv.conf.
//! Windows DNS ownership is 8C.

use std::net::IpAddr;
#[cfg(target_os = "macos")]
use std::process::Command;

use crate::PlatformError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DarwinDnsConfig {
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub domain_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DarwinDnsSnapshot {
    service_id: String,
    original: Option<DarwinDnsConfig>,
}

/// Applied Darwin DNS rewrite. Restored on [`DnsOwner::restore`] or drop.
#[derive(Debug)]
pub struct DnsOwner {
    snapshot: Option<DarwinDnsSnapshot>,
}

impl DnsOwner {
    #[must_use]
    pub fn noop() -> Self {
        Self { snapshot: None }
    }

    /// Restores the captured primary-service DNS, or no-ops when none was applied.
    ///
    /// # Errors
    ///
    /// Returns scutil restore failures after a Darwin rewrite.
    pub fn restore(&mut self) -> Result<(), PlatformError> {
        let Some(snapshot) = self.snapshot.take() else {
            return Ok(());
        };
        #[cfg(target_os = "macos")]
        {
            restore_darwin_dns(&snapshot)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = snapshot;
            Ok(())
        }
    }
}

impl Drop for DnsOwner {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Linux: no-op. Darwin: rewrite primary service DNS. Windows: fail-closed.
///
/// # Errors
///
/// Returns when scutil cannot snapshot or rewrite the primary service, or when
/// the platform is outside the 8A/8B surface.
pub fn apply_tun_system_dns(dns: IpAddr) -> Result<DnsOwner, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let _ = dns;
        Ok(DnsOwner::noop())
    }
    #[cfg(target_os = "windows")]
    {
        let _ = dns;
        Err(PlatformError::Unsupported(
            "Windows system DNS ownership is Phase 8C, not 8B".into(),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let snapshot = snapshot_darwin_dns()?;
        if let Err(error) = apply_darwin_dns(&snapshot.service_id, dns) {
            let _ = restore_darwin_dns(&snapshot);
            return Err(error);
        }
        Ok(DnsOwner {
            snapshot: Some(snapshot),
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = dns;
        Err(PlatformError::Unsupported(
            "system DNS ownership is Darwin-only in Phase 8B".into(),
        ))
    }
}

#[must_use]
pub fn darwin_dns_key(service_id: &str) -> String {
    format!("State:/Network/Service/{service_id}/DNS")
}

/// Parses `PrimaryService` from `scutil` `show State:/Network/Global/IPv4`.
///
/// # Errors
///
/// Returns when the dictionary has no `PrimaryService` entry.
pub fn parse_scutil_primary_service(show: &str) -> Result<String, PlatformError> {
    for line in show.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("PrimaryService") else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix(':').unwrap_or(rest).trim();
        if !rest.is_empty() {
            return Ok(rest.to_string());
        }
    }
    Err(PlatformError::Dns(
        "scutil State:/Network/Global/IPv4 has no PrimaryService".into(),
    ))
}

/// Parses `ServerAddresses` / `SearchDomains` / `DomainName` from an scutil DNS dictionary.
#[must_use]
pub fn parse_scutil_dns_dictionary(body: &str) -> DarwinDnsConfig {
    let mut config = DarwinDnsConfig::default();
    let mut mode = DictMode::Root;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('}') {
            mode = DictMode::Root;
            continue;
        }
        if let Some(rest) = field_value(trimmed, "ServerAddresses") {
            mode = DictMode::Servers;
            if let Ok(address) = rest.parse::<IpAddr>() {
                config.servers.push(address);
            }
            continue;
        }
        if let Some(rest) = field_value(trimmed, "SearchDomains") {
            mode = DictMode::Search;
            if is_scalar_dict_value(rest) {
                config.search_domains.push(rest.to_owned());
            }
            continue;
        }
        if let Some(rest) = field_value(trimmed, "DomainName") {
            mode = DictMode::Root;
            if is_scalar_dict_value(rest) {
                config.domain_name = Some(rest.to_owned());
            }
            continue;
        }
        match mode {
            DictMode::Servers => {
                if let Some((_, value)) = trimmed.split_once(':')
                    && let Ok(address) = value.trim().parse::<IpAddr>()
                {
                    config.servers.push(address);
                }
            }
            DictMode::Search => {
                if let Some((_, value)) = trimmed.split_once(':') {
                    let value = value.trim();
                    if is_scalar_dict_value(value) {
                        config.search_domains.push(value.to_owned());
                    }
                }
            }
            DictMode::Root => {}
        }
    }
    config
}

#[must_use]
pub fn build_scutil_dns_script(key: &str, config: &DarwinDnsConfig) -> String {
    let mut script = String::from("d.init\n");
    if !config.servers.is_empty() {
        script.push_str("d.add ServerAddresses *");
        for server in &config.servers {
            script.push(' ');
            script.push_str(&server.to_string());
        }
        script.push('\n');
    }
    if !config.search_domains.is_empty() {
        script.push_str("d.add SearchDomains *");
        for domain in &config.search_domains {
            script.push(' ');
            script.push_str(domain);
        }
        script.push('\n');
    }
    if let Some(domain) = &config.domain_name {
        script.push_str("d.add DomainName ");
        script.push_str(domain);
        script.push('\n');
    }
    script.push_str("set ");
    script.push_str(key);
    script.push_str("\nquit\n");
    script
}

#[must_use]
pub fn build_scutil_remove_script(key: &str) -> String {
    format!("remove {key}\nquit\n")
}

#[derive(Clone, Copy)]
enum DictMode {
    Root,
    Servers,
    Search,
}

fn field_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(name)?.trim_start();
    let rest = rest.strip_prefix(':')?.trim();
    Some(rest)
}

fn is_scalar_dict_value(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('<')
}

#[cfg(target_os = "macos")]
fn is_scutil_no_such_key(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("no such key") || lower.contains("is not defined")
}

#[cfg(target_os = "macos")]
fn is_missing_dns_key(error: &PlatformError) -> bool {
    match error {
        PlatformError::Dns(message) | PlatformError::Command(message) => {
            let lower = message.to_ascii_lowercase();
            lower.contains("no such key") || lower.contains("is not defined")
        }
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn looks_like_permission(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("permission")
        || lower.contains("operation not permitted")
        || lower.contains("not privileged")
        || lower.contains("must be root")
}

#[cfg(target_os = "macos")]
fn snapshot_darwin_dns() -> Result<DarwinDnsSnapshot, PlatformError> {
    let global = scutil_show("State:/Network/Global/IPv4")?;
    let service_id = parse_scutil_primary_service(&global)?;
    let key = darwin_dns_key(&service_id);
    let original = match scutil_show(&key) {
        Ok(body) if !body.trim().is_empty() && !is_scutil_no_such_key(&body) => {
            Some(parse_scutil_dns_dictionary(&body))
        }
        Ok(_) => None,
        Err(error) if is_missing_dns_key(&error) => None,
        Err(error) => return Err(error),
    };
    Ok(DarwinDnsSnapshot {
        service_id,
        original,
    })
}

#[cfg(target_os = "macos")]
fn apply_darwin_dns(service_id: &str, dns: IpAddr) -> Result<(), PlatformError> {
    let key = darwin_dns_key(service_id);
    let script = build_scutil_dns_script(
        &key,
        &DarwinDnsConfig {
            servers: vec![dns],
            search_domains: Vec::new(),
            domain_name: None,
        },
    );
    scutil_script(&script).map_err(|error| {
        if looks_like_permission(&error.to_string()) {
            PlatformError::Dns(format!(
                "scutil DNS rewrite for {key} requires root; refusing to skip: {error}"
            ))
        } else {
            error
        }
    })
}

#[cfg(target_os = "macos")]
fn restore_darwin_dns(snapshot: &DarwinDnsSnapshot) -> Result<(), PlatformError> {
    let key = darwin_dns_key(&snapshot.service_id);
    let script = match &snapshot.original {
        Some(original) => build_scutil_dns_script(&key, original),
        None => build_scutil_remove_script(&key),
    };
    match scutil_script(&script) {
        Ok(()) => Ok(()),
        Err(error) if is_missing_dns_key(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn scutil_show(key: &str) -> Result<String, PlatformError> {
    let stdout = scutil_run(&format!("show {key}\nquit\n"))?;
    Ok(stdout)
}

#[cfg(target_os = "macos")]
fn scutil_script(script: &str) -> Result<(), PlatformError> {
    let _ = scutil_run(script)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn scutil_run(script: &str) -> Result<String, PlatformError> {
    use std::io::Write;

    let mut child = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| PlatformError::Dns(format!("failed to spawn scutil: {error}")))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| PlatformError::Dns("scutil stdin was not piped".to_owned()))?;
        stdin.write_all(script.as_bytes()).map_err(|error| {
            PlatformError::Dns(format!("failed to write scutil script: {error}"))
        })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| PlatformError::Dns(format!("scutil failed to wait: {error}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(PlatformError::Dns(format!(
            "scutil failed ({}): {stderr}{stdout}",
            output.status
        )));
    }
    if is_scutil_no_such_key(&stdout) || is_scutil_no_such_key(&stderr) {
        return Err(PlatformError::Dns(format!(
            "scutil no such key: {stderr}{stdout}"
        )));
    }
    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_primary_service() {
        let show = r"
<dictionary> {
  PrimaryService : 4B4B4B4B-4B4B-4B4B-4B4B-4B4B4B4B4B4B
  PrimaryInterface : en0
  Router : 192.168.1.1
}
";
        assert_eq!(
            parse_scutil_primary_service(show).unwrap(),
            "4B4B4B4B-4B4B-4B4B-4B4B-4B4B4B4B4B4B"
        );
    }

    #[test]
    fn parse_dns_dictionary_servers_and_search() {
        let show = r"
<dictionary> {
  ServerAddresses : <array> {
    0 : 192.168.1.1
    1 : 8.8.8.8
  }
  SearchDomains : <array> {
    0 : lan
  }
  DomainName : home.arpa
}
";
        let parsed = parse_scutil_dns_dictionary(show);
        assert_eq!(
            parsed.servers,
            vec![
                "192.168.1.1".parse::<IpAddr>().expect("dns"),
                "8.8.8.8".parse::<IpAddr>().expect("dns"),
            ]
        );
        assert_eq!(parsed.search_domains, vec!["lan".to_owned()]);
        assert_eq!(parsed.domain_name.as_deref(), Some("home.arpa"));
    }

    #[test]
    fn scutil_set_script_rewrites_servers_only() {
        let key = darwin_dns_key("ABCD");
        let script = build_scutil_dns_script(
            &key,
            &DarwinDnsConfig {
                servers: vec!["198.18.0.2".parse::<IpAddr>().expect("tun dns")],
                search_domains: Vec::new(),
                domain_name: None,
            },
        );
        assert!(script.contains("d.init"));
        assert!(script.contains("d.add ServerAddresses * 198.18.0.2"));
        assert!(script.contains("set State:/Network/Service/ABCD/DNS"));
        assert!(script.contains("quit"));
        assert!(!script.contains("SearchDomains"));
    }

    #[test]
    fn scutil_remove_script_targets_service_key() {
        let script = build_scutil_remove_script(&darwin_dns_key("ABCD"));
        assert_eq!(script, "remove State:/Network/Service/ABCD/DNS\nquit\n");
    }
}
