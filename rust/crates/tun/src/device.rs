use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use rewrite_config::TunConfig;
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::TunError;

/// Environment variable that points at `wintun.dll` or the directory that holds it.
pub const WINTUN_ENV: &str = "MIHOMO_WINTUN";

/// Windows interface metric applied only to this Wintun adapter (lower wins).
pub const WINDOWS_TUN_METRIC: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunDeviceConfig {
    pub name: Option<String>,
    pub mtu: u16,
    pub inet4: Vec<IpNet>,
    pub inet6: Vec<IpNet>,
}

impl TunDeviceConfig {
    #[must_use]
    pub fn from_tun_config(config: &TunConfig) -> Self {
        let mtu = if config.mtu == 0 {
            9000
        } else {
            u16::try_from(config.mtu).unwrap_or(u16::MAX)
        };
        Self {
            name: (!config.device.is_empty()).then(|| config.device.clone()),
            mtu,
            inet4: config.inet4_address.clone(),
            inet6: config.inet6_address.clone(),
        }
    }
}

pub struct TunDevice {
    device: AsyncDevice,
    name: String,
}

impl TunDevice {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn device(&self) -> &AsyncDevice {
        &self.device
    }

    #[must_use]
    pub fn into_device(self) -> AsyncDevice {
        self.device
    }
}

/// Darwin utun IPv4 destination / DNS address: the next address in the prefix
/// (Go `Inet4Address[0].Addr().Next()`).
///
/// # Errors
///
/// Returns when the prefix is not IPv4.
pub fn ipv4_point_to_point_destination(prefix: &IpNet) -> Result<Ipv4Addr, TunError> {
    match prefix.addr() {
        std::net::IpAddr::V4(address) => Ok(Ipv4Addr::from(u32::from(address).wrapping_add(1))),
        std::net::IpAddr::V6(_) => Err(TunError::Stack(
            "inet4-address entry must be IPv4".to_owned(),
        )),
    }
}

/// Ordered Wintun search paths: env, executable directory, then `wintun.dll`.
#[must_use]
pub fn wintun_candidates(env: Option<&Path>, exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(value) = env {
        if value.is_dir() {
            out.push(value.join("wintun.dll"));
        } else {
            out.push(value.to_path_buf());
        }
    }
    if let Some(dir) = exe_dir {
        out.push(dir.join("wintun.dll"));
    }
    out.push(PathBuf::from("wintun.dll"));
    out
}

#[cfg(target_os = "windows")]
fn resolve_wintun_dll() -> Result<PathBuf, TunError> {
    let env = std::env::var_os(WINTUN_ENV).map(PathBuf::from);
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    for candidate in wintun_candidates(env.as_deref(), exe_dir.as_deref()) {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(TunError::Unsupported(
        "wintun.dll not found; Phase 8C requires Wintun next to the binary or MIHOMO_WINTUN; refusing to skip"
            .to_owned(),
    ))
}

#[cfg(target_os = "windows")]
fn map_windows_device_error(error: std::io::Error) -> TunError {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found")
        || lower.contains("cannot find")
        || lower.contains("the specified module could not be found")
        || lower.contains("error 126")
    {
        return TunError::Unsupported(format!(
            "wintun.dll not found; Phase 8C requires Wintun: {message}"
        ));
    }
    if lower.contains("access is denied")
        || lower.contains("privileg")
        || lower.contains("elevation")
        || lower.contains("error 5")
    {
        return TunError::Unsupported(format!(
            "Wintun requires Administrator; refusing to skip: {message}"
        ));
    }
    TunError::Device(error)
}

/// Opens a TUN device with the Phase 8 address/MTU settings.
///
/// Darwin: `packet_information(false)` so netstack sees raw IP, and
/// `associate_route(false)` so [`rewrite_platform::RouteOwner`] owns routes.
/// Point-to-point destination is the next IPv4 address (TUN DNS).
///
/// Windows: load Wintun from `MIHOMO_WINTUN` or beside the executable, never
/// delete the driver (other VPNs share it), and set this adapter's metric only.
///
/// # Errors
///
/// Returns device creation failures from `tun-rs`, or a missing/unprivileged
/// Wintun error on Windows.
pub fn open_tun_device(config: &TunDeviceConfig) -> Result<TunDevice, TunError> {
    let mut builder = DeviceBuilder::new().mtu(config.mtu);
    if let Some(name) = &config.name {
        builder = builder.name(name.clone());
    }
    #[cfg(target_os = "macos")]
    {
        builder = builder.packet_information(false).associate_route(false);
    }
    #[cfg(target_os = "windows")]
    {
        let wintun = resolve_wintun_dll()?;
        builder = builder
            .delete_driver(false)
            .metric(WINDOWS_TUN_METRIC)
            .description("mihomo")
            .wintun_file(wintun.to_string_lossy().into_owned());
    }
    if let Some(first) = config.inet4.first() {
        let std::net::IpAddr::V4(address) = first.addr() else {
            return Err(TunError::Stack(
                "inet4-address entry must be IPv4".to_owned(),
            ));
        };
        let destination = if cfg!(target_os = "macos") {
            Some(ipv4_point_to_point_destination(first)?)
        } else {
            None
        };
        builder = builder.ipv4(address, first.prefix_len(), destination);
    }
    if let Some(first) = config.inet6.first() {
        let std::net::IpAddr::V6(address) = first.addr() else {
            return Err(TunError::Stack(
                "inet6-address entry must be IPv6".to_owned(),
            ));
        };
        builder = builder.ipv6(address, first.prefix_len());
    }
    let device = {
        #[cfg(target_os = "windows")]
        {
            builder.build_async().map_err(map_windows_device_error)?
        }
        #[cfg(not(target_os = "windows"))]
        {
            builder.build_async()?
        }
    };
    let name = device
        .name()
        .unwrap_or_else(|_| config.name.clone().unwrap_or_else(|| "tun".to_owned()));
    Ok(TunDevice { device, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn darwin_p2p_destination_is_next_address() {
        let prefix = "198.18.0.1/30".parse::<IpNet>().expect("prefix");
        assert_eq!(
            ipv4_point_to_point_destination(&prefix).expect("v4"),
            "198.18.0.2".parse::<Ipv4Addr>().expect("dest")
        );
    }

    #[test]
    fn wintun_candidates_prefer_env_then_exe_dir() {
        let env = Path::new(r"C:\vpn\wintun.dll");
        let exe = Path::new(r"C:\app");
        let candidates = wintun_candidates(Some(env), Some(exe));
        assert_eq!(candidates[0], env);
        assert_eq!(candidates[1], exe.join("wintun.dll"));
        assert_eq!(
            candidates.last().map(PathBuf::as_path),
            Some(Path::new("wintun.dll"))
        );
        let dir = std::env::temp_dir();
        let dir_env = wintun_candidates(Some(&dir), None);
        assert_eq!(dir_env[0], dir.join("wintun.dll"));
    }

    #[test]
    fn windows_metric_is_this_adapter_only() {
        assert_eq!(WINDOWS_TUN_METRIC, 1);
        assert_eq!(WINTUN_ENV, "MIHOMO_WINTUN");
    }
}
