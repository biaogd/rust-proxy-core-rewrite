//! Shared long-lived services and transactional updater boundaries.

use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

use flate2::read::GzDecoder;
use futures_util::StreamExt;
use prost::Message;
use rewrite_config::{Config, NtpConfig};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::UnixTime;
use tokio_rustls::rustls::time_provider::TimeProvider;

const DOWNLOAD_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct AdjustedClock {
    offset_micros: AtomicI64,
}

impl fmt::Debug for AdjustedClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdjustedClock")
            .field("offset_micros", &self.offset_micros())
            .finish()
    }
}

impl AdjustedClock {
    pub fn set_offset_micros(&self, offset: i64) {
        self.offset_micros.store(offset, Ordering::Release);
    }

    #[must_use]
    pub fn offset_micros(&self) -> i64 {
        self.offset_micros.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn now(&self) -> SystemTime {
        let offset = self.offset_micros();
        if offset >= 0 {
            SystemTime::now() + Duration::from_micros(offset.unsigned_abs())
        } else {
            SystemTime::now() - Duration::from_micros(offset.unsigned_abs())
        }
    }
}

impl TimeProvider for AdjustedClock {
    fn current_time(&self) -> Option<UnixTime> {
        self.now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(UnixTime::since_unix_epoch)
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("NTP endpoint is invalid")]
    InvalidNtpEndpoint,
    #[error("NTP dialer proxy awaits a UDP-capable outbound: {0}")]
    UnsupportedNtpProxy(String),
    #[error("NTP exchange failed")]
    NtpExchange,
    #[error("NTP exchange timed out")]
    NtpTimeout,
    #[error("download failed: {0}")]
    Download(String),
    #[error("download exceeds {DOWNLOAD_LIMIT} bytes")]
    DownloadTooLarge,
    #[error("unknown or unsupported file type")]
    UnsupportedArchive,
    #[error("archive path is unsafe: {0}")]
    UnsafeArchivePath(String),
    #[error("archive or filesystem operation failed: {0}")]
    Archive(#[from] std::io::Error),
    #[error("invalid geodata: {0}")]
    InvalidGeodata(String),
    #[error("configuration has no home directory")]
    MissingHome,
}

/// Performs one bounded SNTP exchange and publishes the resulting offset.
///
/// # Errors
///
/// Returns an endpoint, proxy, timeout or UDP exchange error.
pub async fn update_ntp(config: &NtpConfig, clock: &AdjustedClock) -> Result<i64, ServiceError> {
    if !config.dialer_proxy.is_empty() {
        return Err(ServiceError::UnsupportedNtpProxy(
            config.dialer_proxy.clone(),
        ));
    }
    let port = u16::try_from(config.port).map_err(|_| ServiceError::InvalidNtpEndpoint)?;
    let mut addresses = tokio::net::lookup_host((config.server.as_str(), port))
        .await
        .map_err(|_| ServiceError::InvalidNtpEndpoint)?;
    let address = addresses.next().ok_or(ServiceError::InvalidNtpEndpoint)?;
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| ServiceError::NtpExchange)?;
    let socket = sntpc_net_tokio::UdpSocketWrapper::new(socket);
    let context = sntpc::NtpContext::new(sntpc::StdTimestampGen::default());
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        sntpc::get_time(address, &socket, context),
    )
    .await
    .map_err(|_| ServiceError::NtpTimeout)?
    .map_err(|_| ServiceError::NtpExchange)?;
    clock.set_offset_micros(result.offset());
    Ok(result.offset())
}

fn updater_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Selects the normal Ring provider when Rustls is built with both Ring and
/// AWS-LC (the latter is used only by per-connection ECH configs).
pub fn install_default_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

fn updater_client() -> Result<reqwest::Client, ServiceError> {
    install_default_crypto_provider();
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|error| ServiceError::Download(error.to_string()))
}

async fn download(url: &str) -> Result<Vec<u8>, ServiceError> {
    let response = updater_client()?
        .get(url)
        .send()
        .await
        .map_err(|error| ServiceError::Download(error.to_string()))?;
    if !response.status().is_success() {
        return Err(ServiceError::Download(format!(
            "HTTP status {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > DOWNLOAD_LIMIT as u64)
    {
        return Err(ServiceError::DownloadTooLarge);
    }
    let mut body = response.bytes_stream();
    let mut result = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| ServiceError::Download(error.to_string()))?;
        if result.len().saturating_add(chunk.len()) > DOWNLOAD_LIMIT {
            return Err(ServiceError::DownloadTooLarge);
        }
        result.extend_from_slice(&chunk);
    }
    Ok(result)
}

/// Downloads and replaces the configured external UI with safe library-owned
/// ZIP or tar+gzip extraction.
///
/// # Errors
///
/// Returns a download, archive validation or filesystem transaction error.
pub async fn update_ui(config: &Config) -> Result<(), ServiceError> {
    let _guard = updater_lock().lock().await;
    let target = ui_target(config)?;
    let payload = download(&config.external_ui_url).await?;
    let home = config.home_directory().ok_or(ServiceError::MissingHome)?;
    let temporary = home.join("downloadUI.tmp");
    tokio::task::spawn_blocking(move || replace_ui(&payload, &temporary, &target))
        .await
        .map_err(|error| ServiceError::Archive(std::io::Error::other(error)))??;
    Ok(())
}

/// Downloads an explicitly configured UI only when its target directory is
/// absent or empty. Returns whether a download was performed.
///
/// # Errors
///
/// Returns the same bounded download and extraction errors as [`update_ui`].
pub async fn auto_update_ui(config: &Config) -> Result<bool, ServiceError> {
    if config.external_ui.is_empty() && config.external_ui_name.is_empty() {
        return Ok(false);
    }
    let target = ui_target(config)?;
    if std::fs::read_dir(&target).is_ok_and(|mut entries| entries.next().is_some()) {
        return Ok(false);
    }
    update_ui(config).await?;
    Ok(true)
}

fn ui_target(config: &Config) -> Result<PathBuf, ServiceError> {
    let home = config.home_directory().ok_or(ServiceError::MissingHome)?;
    Ok(config.external_ui_path().unwrap_or_else(|| home.join("ui")))
}

fn replace_ui(payload: &[u8], temporary: &Path, target: &Path) -> Result<(), ServiceError> {
    if temporary.exists() {
        std::fs::remove_dir_all(temporary)?;
    }
    std::fs::create_dir_all(temporary)?;
    let extracted = if payload.starts_with(b"PK\x03\x04") {
        extract_zip(payload, temporary)
    } else if payload.starts_with(&[0x1f, 0x8b]) {
        extract_targz(payload, temporary)
    } else {
        Err(ServiceError::UnsupportedArchive)
    };
    if let Err(error) = extracted {
        let _ = std::fs::remove_dir_all(temporary);
        return Err(error);
    }
    if target.exists() {
        for entry in std::fs::read_dir(target)? {
            remove_any(&entry?.path())?;
        }
    } else {
        std::fs::create_dir_all(target)?;
    }
    let source = single_root(temporary)?;
    for entry in std::fs::read_dir(&source)? {
        let entry = entry?;
        move_or_copy(&entry.path(), &target.join(entry.file_name()))?;
    }
    std::fs::remove_dir_all(temporary)?;
    Ok(())
}

fn extract_zip(payload: &[u8], destination: &Path) -> Result<(), ServiceError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(payload))
        .map_err(|error| ServiceError::Archive(std::io::Error::other(error)))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| ServiceError::Archive(std::io::Error::other(error)))?;
        let Some(relative) = entry.enclosed_name() else {
            return Err(ServiceError::UnsafeArchivePath(entry.name().to_owned()));
        };
        let path = destination.join(relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&path)?;
        } else if !entry.is_symlink() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut output = std::fs::File::create(path)?;
            std::io::copy(&mut entry, &mut output)?;
        }
    }
    Ok(())
}

fn extract_targz(payload: &[u8], destination: &Path) -> Result<(), ServiceError> {
    let decoder = GzDecoder::new(Cursor::new(payload));
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            continue;
        }
        let raw = entry.path()?.into_owned();
        if !entry.unpack_in(destination)? {
            return Err(ServiceError::UnsafeArchivePath(
                raw.to_string_lossy().into_owned(),
            ));
        }
    }
    Ok(())
}

fn single_root(path: &Path) -> Result<PathBuf, ServiceError> {
    let entries = std::fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() == 1 && entries[0].file_type()?.is_dir() {
        Ok(entries[0].path())
    } else {
        Ok(path.to_path_buf())
    }
}

fn move_or_copy(source: &Path, destination: &Path) -> Result<(), ServiceError> {
    match std::fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(18) => {
            copy_tree(source, destination)?;
            remove_any(source)
        }
        Err(error) => Err(error.into()),
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), ServiceError> {
    let metadata = std::fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        std::fs::create_dir_all(destination)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else if metadata.file_type().is_file() {
        std::fs::copy(source, destination)?;
    }
    Ok(())
}

fn remove_any(path: &Path) -> Result<(), ServiceError> {
    if std::fs::symlink_metadata(path)?.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteListWire {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<GeoSiteWire>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteWire {
    #[prost(string, tag = "1")]
    country_code: String,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpListWire {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<GeoIpWire>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpWire {
    #[prost(string, tag = "1")]
    country_code: String,
}

/// Downloads and validates geodata consumed by the current Rust DNS config,
/// then atomically replaces only changed files.
///
/// # Errors
///
/// Returns a download, data validation or atomic filesystem update error.
pub async fn update_geodata(config: &Config) -> Result<(), ServiceError> {
    let _guard = updater_lock().lock().await;
    let home = config.home_directory().ok_or(ServiceError::MissingHome)?;
    let mut updates = Vec::new();
    if config_uses_geoip(config) {
        if config.geodata_mode {
            updates.push((
                config.geox_url.geo_ip.as_str(),
                home.join("GeoIP.dat"),
                GeoKind::GeoIp,
            ));
        } else {
            updates.push((
                config.geox_url.mmdb.as_str(),
                home.join("geoip.metadb"),
                GeoKind::Mmdb,
            ));
        }
    }
    if config_uses_geosite(config) {
        updates.push((
            config.geox_url.geo_site.as_str(),
            home.join("GeoSite.dat"),
            GeoKind::GeoSite,
        ));
    }
    for (url, path, kind) in updates {
        let payload = download(url).await?;
        validate_geo(kind, &payload)?;
        if std::fs::read(&path).is_ok_and(|current| current == payload) {
            continue;
        }
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, payload)?;
        std::fs::rename(temporary, path)?;
    }
    Ok(())
}

/// Reports whether the oldest currently consumed geodata file has exceeded
/// the configured refresh interval. Missing files are immediately due.
///
/// # Errors
///
/// Returns [`ServiceError::MissingHome`] when no resource directory is known.
pub fn geodata_update_due(config: &Config) -> Result<bool, ServiceError> {
    let home = config.home_directory().ok_or(ServiceError::MissingHome)?;
    let mut paths = Vec::new();
    if config_uses_geoip(config) {
        paths.push(if config.geodata_mode {
            home.join("GeoIP.dat")
        } else {
            home.join("geoip.metadb")
        });
    }
    if config_uses_geosite(config) {
        paths.push(home.join("GeoSite.dat"));
    }
    if paths.is_empty() {
        return Ok(false);
    }
    let interval = Duration::from_secs(
        u64::try_from(config.geo_update_interval.max(1))
            .unwrap_or(1)
            .saturating_mul(60 * 60),
    );
    let now = SystemTime::now();
    for path in paths {
        let Ok(modified) = std::fs::metadata(path).and_then(|metadata| metadata.modified()) else {
            return Ok(true);
        };
        if now.duration_since(modified).unwrap_or_default() >= interval {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy)]
enum GeoKind {
    GeoIp,
    GeoSite,
    Mmdb,
}

fn validate_geo(kind: GeoKind, payload: &[u8]) -> Result<(), ServiceError> {
    match kind {
        GeoKind::GeoIp => GeoIpListWire::decode(payload)
            .map_err(|error| ServiceError::InvalidGeodata(error.to_string()))
            .and_then(|list| {
                list.entries
                    .iter()
                    .any(|entry| entry.country_code.eq_ignore_ascii_case("cn"))
                    .then_some(())
                    .ok_or_else(|| ServiceError::InvalidGeodata("GeoIP list has no CN".to_owned()))
            }),
        GeoKind::GeoSite => GeoSiteListWire::decode(payload)
            .map_err(|error| ServiceError::InvalidGeodata(error.to_string()))
            .and_then(|list| {
                list.entries
                    .iter()
                    .any(|entry| entry.country_code.eq_ignore_ascii_case("cn"))
                    .then_some(())
                    .ok_or_else(|| {
                        ServiceError::InvalidGeodata("GeoSite list has no CN".to_owned())
                    })
            }),
        GeoKind::Mmdb => maxminddb::Reader::from_source(payload)
            .map(|_| ())
            .map_err(|error| ServiceError::InvalidGeodata(error.to_string())),
    }
}

fn config_uses_geoip(config: &Config) -> bool {
    config
        .dns
        .as_ref()
        .and_then(|dns| dns.fallback.as_ref())
        .is_some_and(|fallback| fallback.geoip.is_some())
        || config.uses_rule_kind("GEOIP")
        || config.uses_rule_kind("SRC-GEOIP")
}

fn config_uses_geosite(config: &Config) -> bool {
    use rewrite_config::{DnsPolicyMatcher, FakeIpRuleMatcher};
    let policy_has_geo = config.dns.as_ref().is_some_and(|dns| {
        dns.policies
            .iter()
            .chain(&dns.proxy_policies)
            .any(|policy| matches!(policy.matcher, DnsPolicyMatcher::Geosite { .. }))
    });
    let fallback_has_geo = config.dns.as_ref().is_some_and(|dns| {
        dns.fallback
            .as_ref()
            .is_some_and(|fallback| !fallback.geosites.is_empty())
    });
    let fake_has_geo = config.dns.as_ref().is_some_and(|dns| {
        dns.fake_ip.as_ref().is_some_and(|fake| {
            fake.filter
                .iter()
                .any(|matcher| matches!(matcher, DnsPolicyMatcher::Geosite { .. }))
                || fake
                    .rules
                    .iter()
                    .any(|rule| matches!(rule.matcher, FakeIpRuleMatcher::Geosite { .. }))
        })
    });
    policy_has_geo || fallback_has_geo || fake_has_geo || config.uses_rule_kind("GEOSITE")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ntp_timestamp(time: SystemTime) -> [u8; 8] {
        const NTP_UNIX_DELTA: u64 = 2_208_988_800;
        let elapsed = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time after Unix epoch");
        let seconds = elapsed.as_secs().saturating_add(NTP_UNIX_DELTA);
        let fraction = ((u64::from(elapsed.subsec_nanos())) << 32) / 1_000_000_000;
        ((seconds << 32) | fraction).to_be_bytes()
    }

    #[test]
    fn adjusted_clock_applies_and_resets_offset() {
        let clock = AdjustedClock::default();
        clock.set_offset_micros(2_000_000);
        let shifted = clock.now();
        assert!(shifted > SystemTime::now() + Duration::from_secs(1));
        clock.set_offset_micros(0);
        assert_eq!(clock.offset_micros(), 0);
    }

    #[tokio::test]
    async fn local_ntp_exchange_updates_adjusted_clock() {
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind NTP fixture");
        let port = server.local_addr().expect("fixture address").port();
        let authority = tokio::spawn(async move {
            let mut request = [0_u8; 48];
            let (length, peer) = server.recv_from(&mut request).await.expect("NTP request");
            assert_eq!(length, 48);
            let shifted = SystemTime::now() + Duration::from_secs(2);
            let timestamp = ntp_timestamp(shifted);
            let mut response = [0_u8; 48];
            response[0] = 0x24;
            response[1] = 1;
            response[2] = request[2];
            response[3] = 0xec;
            response[12..16].copy_from_slice(b"LOCL");
            response[16..24].copy_from_slice(&timestamp);
            response[24..32].copy_from_slice(&request[40..48]);
            response[32..40].copy_from_slice(&timestamp);
            response[40..48].copy_from_slice(&timestamp);
            server.send_to(&response, peer).await.expect("NTP response");
        });
        let clock = AdjustedClock::default();
        let offset = update_ntp(
            &NtpConfig {
                enable: true,
                server: "127.0.0.1".to_owned(),
                port: i64::from(port),
                interval: 30,
                dialer_proxy: String::new(),
                write_to_system: false,
            },
            &clock,
        )
        .await
        .expect("local NTP exchange");
        authority.await.expect("fixture task");
        assert!((1_000_000..=3_000_000).contains(&offset));
        assert_eq!(clock.offset_micros(), offset);
    }
}
