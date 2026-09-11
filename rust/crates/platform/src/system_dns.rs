//! Darwin system DNS ownership via `scutil` (no `SystemConfiguration` FFI)
//! and Windows TUN-adapter DNS via `netsh` (no IP Helper FFI).
//!
//! macOS applications resolve through getaddrinfo / the primary network
//! service. Packet hijack of `8.8.8.8:53` on the TUN is not enough: the
//! resolver never sends those packets unless the system DNS servers are
//! pointed at the TUN DNS address (Go: TUN IPv4 next address).
//!
//! Linux 8A hijacks DNS at the packet layer and does not rewrite resolv.conf.
//! Windows 8C sets DNS on the Wintun adapter only and never rewrites other
//! NICs, so other VPNs keep their own DNS.

use std::net::IpAddr;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

use crate::PlatformError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DarwinDnsValue {
    Scalar(String),
    Array(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DarwinDnsConfig {
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub domain_name: Option<String>,
    /// Keys outside `ServerAddresses` / `SearchDomains` / `DomainName`, such as
    /// `SupplementalMatchDomains`. Nested dictionaries are skipped because
    /// `scutil` cannot round-trip them with `d.add`.
    pub extra: Vec<(String, DarwinDnsValue)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DarwinDnsSnapshot {
    service_id: String,
    original: Option<DarwinDnsConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsDnsSnapshot {
    interface: String,
    original: WindowsDnsOrigin,
}

/// How DNS was configured on a Windows adapter before TUN ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsDnsOrigin {
    Dhcp,
    Static(Vec<IpAddr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Darwin/Windows variants are constructed only on that OS.
enum DnsSnapshot {
    Darwin(DarwinDnsSnapshot),
    Windows(WindowsDnsSnapshot),
}

/// Applied Darwin/Windows DNS rewrite. Restored on [`DnsOwner::restore`] or drop.
#[derive(Debug)]
pub struct DnsOwner {
    snapshot: Option<DnsSnapshot>,
}

impl DnsOwner {
    #[must_use]
    pub fn noop() -> Self {
        Self { snapshot: None }
    }

    /// Restores captured DNS, or no-ops when none was applied.
    ///
    /// # Errors
    ///
    /// Returns scutil or netsh restore failures.
    pub fn restore(&mut self) -> Result<(), PlatformError> {
        let Some(snapshot) = self.snapshot.take() else {
            return Ok(());
        };
        match snapshot {
            DnsSnapshot::Darwin(snapshot) => {
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
            DnsSnapshot::Windows(snapshot) => {
                #[cfg(target_os = "windows")]
                {
                    restore_windows_dns(&snapshot)
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = snapshot;
                    Ok(())
                }
            }
        }
    }
}

impl Drop for DnsOwner {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Linux: no-op. Darwin: rewrite primary service DNS. Windows: fail-closed
/// unless [`apply_windows_tun_interface_dns`] is used.
///
/// # Errors
///
/// Returns when scutil cannot snapshot or rewrite the primary service, or when
/// the platform is outside the 8A/8B/8C surface.
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
            "Windows TUN DNS must target the Wintun adapter via apply_windows_tun_interface_dns; refusing to rewrite other NICs".into(),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let snapshot = snapshot_darwin_dns()?;
        if let Err(error) = apply_darwin_dns(&snapshot.service_id, dns, snapshot.original.is_some())
        {
            let _ = restore_darwin_dns(&snapshot);
            return Err(error);
        }
        Ok(DnsOwner {
            snapshot: Some(DnsSnapshot::Darwin(snapshot)),
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = dns;
        Err(PlatformError::Unsupported(
            "system DNS ownership is Darwin/Windows-only in Phase 8B/8C".into(),
        ))
    }
}

/// Sets DNS on the named Windows TUN adapter only (never the physical NIC).
///
/// # Errors
///
/// Returns when `netsh` cannot snapshot or rewrite the adapter, or when the
/// platform is not Windows.
pub fn apply_windows_tun_interface_dns(
    interface: &str,
    dns: IpAddr,
) -> Result<DnsOwner, PlatformError> {
    if interface.is_empty() {
        return Err(PlatformError::Dns(
            "Windows TUN DNS requires the Wintun adapter name".into(),
        ));
    }
    #[cfg(target_os = "windows")]
    {
        let original = snapshot_windows_dns(interface)?;
        let snapshot = WindowsDnsSnapshot {
            interface: interface.to_owned(),
            original,
        };
        if let Err(error) = apply_windows_dns(interface, dns) {
            let _ = restore_windows_dns(&snapshot);
            return Err(error);
        }
        Ok(DnsOwner {
            snapshot: Some(DnsSnapshot::Windows(snapshot)),
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = dns;
        Err(PlatformError::Unsupported(
            "Windows TUN adapter DNS is Phase 8C".into(),
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

/// Parses an scutil DNS dictionary, including extra keys such as
/// `SupplementalMatchDomains`. Nested dictionaries are skipped.
#[must_use]
pub fn parse_scutil_dns_dictionary(body: &str) -> DarwinDnsConfig {
    let mut entries = Vec::new();
    let mut mode = DictMode::Root;
    let mut array_key = String::new();
    let mut array_values = Vec::new();
    let mut skip_depth = 0_u32;
    for line in body.lines() {
        let trimmed = line.trim();
        if skip_depth > 0 {
            if trimmed.contains("<dictionary>") {
                skip_depth += 1;
            }
            if trimmed.starts_with('}') {
                skip_depth -= 1;
            }
            continue;
        }
        if trimmed.starts_with('}') {
            if matches!(mode, DictMode::Array) {
                entries.push((
                    std::mem::take(&mut array_key),
                    DarwinDnsValue::Array(std::mem::take(&mut array_values)),
                ));
                mode = DictMode::Root;
            }
            continue;
        }
        match mode {
            DictMode::Root => {
                let Some((name, rest)) = split_field(trimmed) else {
                    continue;
                };
                if rest.starts_with("<array>") {
                    mode = DictMode::Array;
                    name.clone_into(&mut array_key);
                    array_values.clear();
                } else if rest.starts_with("<dictionary>") {
                    skip_depth = 1;
                } else if is_scalar_dict_value(rest) {
                    entries.push((name.to_owned(), DarwinDnsValue::Scalar(rest.to_owned())));
                }
            }
            DictMode::Array => {
                if let Some((_, value)) = trimmed.split_once(':') {
                    let value = value.trim();
                    if is_scalar_dict_value(value) {
                        array_values.push(value.to_owned());
                    }
                }
            }
        }
    }
    if matches!(mode, DictMode::Array) {
        entries.push((array_key, DarwinDnsValue::Array(array_values)));
    }
    fold_dns_entries(entries)
}

fn fold_dns_entries(entries: Vec<(String, DarwinDnsValue)>) -> DarwinDnsConfig {
    let mut config = DarwinDnsConfig::default();
    for (key, value) in entries {
        match key.as_str() {
            "ServerAddresses" => {
                config.servers = ip_values(&value);
            }
            "SearchDomains" => {
                config.search_domains = string_values(&value);
            }
            "DomainName" => {
                if let DarwinDnsValue::Scalar(domain) = value
                    && is_scalar_dict_value(&domain)
                {
                    config.domain_name = Some(domain);
                }
            }
            _ => config.extra.push((key, value)),
        }
    }
    config
}

fn ip_values(value: &DarwinDnsValue) -> Vec<IpAddr> {
    string_values(value)
        .into_iter()
        .filter_map(|item| item.parse().ok())
        .collect()
}

fn string_values(value: &DarwinDnsValue) -> Vec<String> {
    match value {
        DarwinDnsValue::Scalar(item) => vec![item.clone()],
        DarwinDnsValue::Array(items) => items.clone(),
    }
}

/// Rebuilds a DNS dictionary from scratch (`d.init`). Used when the key is
/// missing and must be created, or when restore has to recreate a wiped key.
#[must_use]
pub fn build_scutil_dns_script(key: &str, config: &DarwinDnsConfig) -> String {
    let mut script = String::from("d.init\n");
    append_dns_fields(&mut script, config, true);
    finish_scutil_set_script(&mut script, key);
    script
}

/// Loads the existing DNS dictionary and overwrites `ServerAddresses` only.
#[must_use]
pub fn build_scutil_merge_servers_script(key: &str, servers: &[IpAddr]) -> String {
    let mut script = format!("get {key}\n");
    append_server_addresses(&mut script, servers);
    finish_scutil_set_script(&mut script, key);
    script
}

/// Restores owned DNS fields without `d.init`, so extra keys and concurrent
/// updates to those extras survive. Missing extras from the snapshot are
/// filled back in; extras already present are left untouched.
#[must_use]
pub fn build_scutil_restore_dns_script(
    key: &str,
    original: &DarwinDnsConfig,
    current: Option<&DarwinDnsConfig>,
) -> String {
    let Some(current) = current else {
        return build_scutil_dns_script(key, original);
    };
    let mut script = format!("get {key}\n");
    if original.servers.is_empty() {
        script.push_str("d.remove ServerAddresses\n");
    } else {
        append_server_addresses(&mut script, &original.servers);
    }
    if current.search_domains.is_empty() && !original.search_domains.is_empty() {
        append_array_field(&mut script, "SearchDomains", &original.search_domains);
    }
    if current.domain_name.is_none()
        && let Some(domain) = &original.domain_name
    {
        append_scalar_field(&mut script, "DomainName", domain);
    }
    for (name, value) in &original.extra {
        if current
            .extra
            .iter()
            .any(|(current_name, _)| current_name == name)
        {
            continue;
        }
        append_extra_field(&mut script, name, value);
    }
    finish_scutil_set_script(&mut script, key);
    script
}

fn append_dns_fields(script: &mut String, config: &DarwinDnsConfig, include_extras: bool) {
    append_server_addresses(script, &config.servers);
    if !config.search_domains.is_empty() {
        append_array_field(script, "SearchDomains", &config.search_domains);
    }
    if let Some(domain) = &config.domain_name {
        append_scalar_field(script, "DomainName", domain);
    }
    if include_extras {
        for (name, value) in &config.extra {
            append_extra_field(script, name, value);
        }
    }
}

fn append_server_addresses(script: &mut String, servers: &[IpAddr]) {
    if servers.is_empty() {
        return;
    }
    let values: Vec<String> = servers.iter().map(ToString::to_string).collect();
    append_array_field(script, "ServerAddresses", &values);
}

fn append_array_field(script: &mut String, key: &str, values: &[String]) {
    script.push_str("d.add ");
    script.push_str(key);
    script.push_str(" *");
    for value in values {
        script.push(' ');
        script.push_str(value);
    }
    script.push('\n');
}

fn append_scalar_field(script: &mut String, key: &str, value: &str) {
    script.push_str("d.add ");
    script.push_str(key);
    script.push(' ');
    script.push_str(value);
    script.push('\n');
}

fn append_extra_field(script: &mut String, key: &str, value: &DarwinDnsValue) {
    match value {
        DarwinDnsValue::Array(values) => append_array_field(script, key, values),
        DarwinDnsValue::Scalar(value) => append_scalar_field(script, key, value),
    }
}

fn finish_scutil_set_script(script: &mut String, key: &str) {
    script.push_str("set ");
    script.push_str(key);
    script.push_str("\nquit\n");
}

#[must_use]
pub fn build_scutil_remove_script(key: &str) -> String {
    format!("remove {key}\nquit\n")
}

/// Builds `netsh interface ipv4 set dnsservers` arguments for the TUN adapter.
#[must_use]
pub fn windows_set_tun_dns_args(interface: &str, dns: IpAddr) -> Vec<String> {
    vec![
        "interface".to_owned(),
        "ipv4".to_owned(),
        "set".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface}"),
        "static".to_owned(),
        dns.to_string(),
        "primary".to_owned(),
        "validate=no".to_owned(),
    ]
}

/// Builds `netsh` arguments that restore DHCP DNS on the TUN adapter.
#[must_use]
pub fn windows_restore_dhcp_dns_args(interface: &str) -> Vec<String> {
    vec![
        "interface".to_owned(),
        "ipv4".to_owned(),
        "set".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface}"),
        "source=dhcp".to_owned(),
        "validate=no".to_owned(),
    ]
}

/// Parses one adapter block from `netsh interface ipv4 show dnsservers`.
#[must_use]
pub fn parse_netsh_dnsservers(stdout: &str, interface: &str) -> WindowsDnsOrigin {
    let needle = format!("Configuration for interface \"{interface}\"");
    let rest = stdout
        .split(&needle)
        .nth(1)
        .or_else(|| {
            stdout
                .split(&format!("Configuration for interface '{interface}'"))
                .nth(1)
        })
        .unwrap_or("");
    let block = rest
        .split("Configuration for interface")
        .next()
        .unwrap_or(rest);
    let mut servers = Vec::new();
    let mut dhcp = false;
    for line in block.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("configured through dhcp") {
            dhcp = true;
        }
        for token in trimmed.split_whitespace() {
            if let Ok(address) = token.trim_end_matches(',').parse::<IpAddr>() {
                servers.push(address);
            }
        }
    }
    if dhcp || servers.is_empty() {
        WindowsDnsOrigin::Dhcp
    } else {
        WindowsDnsOrigin::Static(servers)
    }
}

#[cfg(target_os = "windows")]
fn snapshot_windows_dns(interface: &str) -> Result<WindowsDnsOrigin, PlatformError> {
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "show", "dnsservers"])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(PlatformError::Dns(format!(
            "netsh show dnsservers failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(parse_netsh_dnsservers(
        &String::from_utf8_lossy(&output.stdout),
        interface,
    ))
}

#[cfg(target_os = "windows")]
fn apply_windows_dns(interface: &str, dns: IpAddr) -> Result<(), PlatformError> {
    let args = windows_set_tun_dns_args(interface, dns);
    let output = Command::new("netsh")
        .args(&args)
        .output()
        .map_err(PlatformError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}{stdout}");
    if looks_like_permission(&combined) {
        return Err(PlatformError::Dns(format!(
            "netsh DNS rewrite for `{interface}` requires Administrator; refusing to skip: {combined}"
        )));
    }
    Err(PlatformError::Dns(format!(
        "netsh DNS rewrite for `{interface}` failed: {combined}"
    )))
}

#[cfg(target_os = "windows")]
fn restore_windows_dns(snapshot: &WindowsDnsSnapshot) -> Result<(), PlatformError> {
    match &snapshot.original {
        WindowsDnsOrigin::Dhcp => {
            let args = windows_restore_dhcp_dns_args(&snapshot.interface);
            let output = Command::new("netsh")
                .args(&args)
                .output()
                .map_err(PlatformError::Io)?;
            if output.status.success() {
                Ok(())
            } else {
                Err(PlatformError::Dns(format!(
                    "netsh DNS restore for `{}` failed: {}{}",
                    snapshot.interface,
                    String::from_utf8_lossy(&output.stderr),
                    String::from_utf8_lossy(&output.stdout)
                )))
            }
        }
        WindowsDnsOrigin::Static(servers) => {
            let Some(first) = servers.first() else {
                return restore_windows_dns(&WindowsDnsSnapshot {
                    interface: snapshot.interface.clone(),
                    original: WindowsDnsOrigin::Dhcp,
                });
            };
            apply_windows_dns(&snapshot.interface, *first)
        }
    }
}

#[derive(Clone, Copy)]
enum DictMode {
    Root,
    Array,
}

fn split_field(line: &str) -> Option<(&str, &str)> {
    let (name, rest) = line.split_once(':')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name, rest.trim()))
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn looks_like_permission(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("permission")
        || lower.contains("operation not permitted")
        || lower.contains("not privileged")
        || lower.contains("must be root")
        || lower.contains("access is denied")
        || lower.contains("requires elevation")
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
fn apply_darwin_dns(
    service_id: &str,
    dns: IpAddr,
    had_original: bool,
) -> Result<(), PlatformError> {
    let key = darwin_dns_key(service_id);
    let script = if had_original {
        build_scutil_merge_servers_script(&key, &[dns])
    } else {
        build_scutil_dns_script(
            &key,
            &DarwinDnsConfig {
                servers: vec![dns],
                ..Default::default()
            },
        )
    };
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
        Some(original) => {
            let current = match scutil_show(&key) {
                Ok(body) if !body.trim().is_empty() && !is_scutil_no_such_key(&body) => {
                    Some(parse_scutil_dns_dictionary(&body))
                }
                Ok(_) => None,
                Err(error) if is_missing_dns_key(&error) => None,
                Err(_) => None,
            };
            build_scutil_restore_dns_script(&key, original, current.as_ref())
        }
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
        assert!(parsed.extra.is_empty());
    }

    #[test]
    fn parse_dns_dictionary_keeps_extra_fields() {
        let show = r"
<dictionary> {
  ServerAddresses : <array> {
    0 : 192.168.1.1
  }
  SearchDomains : <array> {
    0 : lan
  }
  DomainName : home.arpa
  SupplementalMatchDomains : <array> {
    0 : corp.example.com
    1 : vpn.example.com
  }
  SupplementalMatchDomainsNoSearch : 1
}
";
        let parsed = parse_scutil_dns_dictionary(show);
        assert_eq!(
            parsed.servers,
            vec!["192.168.1.1".parse::<IpAddr>().expect("dns")]
        );
        assert_eq!(
            parsed.extra,
            vec![
                (
                    "SupplementalMatchDomains".to_owned(),
                    DarwinDnsValue::Array(vec![
                        "corp.example.com".to_owned(),
                        "vpn.example.com".to_owned(),
                    ]),
                ),
                (
                    "SupplementalMatchDomainsNoSearch".to_owned(),
                    DarwinDnsValue::Scalar("1".to_owned()),
                ),
            ]
        );
    }

    #[test]
    fn scutil_set_script_rewrites_servers_only() {
        let key = darwin_dns_key("ABCD");
        let script = build_scutil_merge_servers_script(
            &key,
            &["198.18.0.2".parse::<IpAddr>().expect("tun dns")],
        );
        assert!(!script.contains("d.init"));
        assert!(script.contains("get State:/Network/Service/ABCD/DNS"));
        assert!(script.contains("d.add ServerAddresses * 198.18.0.2"));
        assert!(script.contains("set State:/Network/Service/ABCD/DNS"));
        assert!(script.contains("quit"));
        assert!(!script.contains("SearchDomains"));
        assert!(!script.contains("SupplementalMatchDomains"));
    }

    #[test]
    fn scutil_restore_script_fills_missing_extras_without_overwriting() {
        let key = darwin_dns_key("ABCD");
        let original = DarwinDnsConfig {
            servers: vec!["192.168.1.1".parse::<IpAddr>().expect("dns")],
            search_domains: vec!["lan".to_owned()],
            domain_name: Some("home.arpa".to_owned()),
            extra: vec![
                (
                    "SupplementalMatchDomains".to_owned(),
                    DarwinDnsValue::Array(vec!["corp.example.com".to_owned()]),
                ),
                (
                    "SupplementalMatchDomainsNoSearch".to_owned(),
                    DarwinDnsValue::Scalar("1".to_owned()),
                ),
            ],
        };
        let current = DarwinDnsConfig {
            servers: vec!["198.18.0.2".parse::<IpAddr>().expect("tun dns")],
            search_domains: vec!["other".to_owned()],
            domain_name: Some("other.arpa".to_owned()),
            extra: vec![(
                "SupplementalMatchDomainsNoSearch".to_owned(),
                DarwinDnsValue::Scalar("0".to_owned()),
            )],
        };
        let script = build_scutil_restore_dns_script(&key, &original, Some(&current));
        assert!(!script.contains("d.init"));
        assert!(script.contains("get State:/Network/Service/ABCD/DNS"));
        assert!(script.contains("d.add ServerAddresses * 192.168.1.1"));
        assert!(script.contains("d.add SupplementalMatchDomains * corp.example.com"));
        assert!(!script.contains("SearchDomains"));
        assert!(!script.contains("DomainName"));
        assert!(!script.contains("SupplementalMatchDomainsNoSearch"));
        let recreated = build_scutil_restore_dns_script(&key, &original, None);
        assert!(recreated.contains("d.init"));
        assert!(recreated.contains("d.add SupplementalMatchDomains * corp.example.com"));
        assert!(recreated.contains("d.add SupplementalMatchDomainsNoSearch 1"));
    }

    #[test]
    fn scutil_remove_script_targets_service_key() {
        let script = build_scutil_remove_script(&darwin_dns_key("ABCD"));
        assert_eq!(script, "remove State:/Network/Service/ABCD/DNS\nquit\n");
    }

    #[test]
    fn windows_dns_args_target_named_adapter_only() {
        assert_eq!(
            windows_set_tun_dns_args("mihomo", "198.18.0.2".parse().expect("dns")),
            vec![
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                "name=mihomo",
                "static",
                "198.18.0.2",
                "primary",
                "validate=no"
            ]
        );
        assert_eq!(windows_restore_dhcp_dns_args("mihomo")[4], "name=mihomo");
    }

    #[test]
    fn parses_netsh_dnsservers_dhcp_and_static() {
        let stdout = r#"
Configuration for interface "Ethernet"
    DNS servers configured through DHCP:  192.168.1.1
    Register with which suffix:           Primary only

Configuration for interface "mihomo"
    Statically Configured DNS Servers:    198.18.0.2
    Register with which suffix:           None
"#;
        assert_eq!(
            parse_netsh_dnsservers(stdout, "Ethernet"),
            WindowsDnsOrigin::Dhcp
        );
        assert_eq!(
            parse_netsh_dnsservers(stdout, "mihomo"),
            WindowsDnsOrigin::Static(vec!["198.18.0.2".parse().expect("dns")])
        );
    }
}
