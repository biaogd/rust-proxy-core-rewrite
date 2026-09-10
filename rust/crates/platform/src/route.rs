//! Owned route bookkeeping for TUN auto-route.

use std::net::IpAddr;
use std::process::Command;

use ipnet::IpNet;

use crate::PlatformError;

/// A route installed by this process that must be removed on stop/failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedRoute {
    pub destination: IpNet,
    pub device: String,
    pub gateway: Option<IpAddr>,
    pub table: Option<u32>,
}

#[derive(Default)]
pub struct RouteOwner {
    routes: Vec<OwnedRoute>,
}

impl RouteOwner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn routes(&self) -> &[OwnedRoute] {
        &self.routes
    }

    /// Records a route as owned after a successful install.
    pub fn record(&mut self, route: OwnedRoute) {
        self.routes.push(route);
    }

    /// Removes every owned route. Continues after individual failures.
    ///
    /// # Errors
    ///
    /// Returns the first failure after attempting all removals.
    pub fn revert_all(&mut self) -> Result<(), PlatformError> {
        let mut first_error = None;
        while let Some(route) = self.routes.pop() {
            if let Err(error) = remove_owned_route(&route) {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for RouteOwner {
    fn drop(&mut self) {
        let _ = self.revert_all();
    }
}

/// Installs a destination route via the given device. Only Linux is implemented
/// for Phase 8A; other platforms return a clear unsupported error.
///
/// # Errors
///
/// Returns command failures or unsupported-platform errors.
pub fn install_device_route(route: &OwnedRoute) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("ip");
        command.arg("route").arg("replace");
        command.arg(route.destination.to_string());
        if let Some(gateway) = route.gateway {
            command.arg("via").arg(gateway.to_string());
        }
        command.arg("dev").arg(&route.device);
        if let Some(table) = route.table {
            command.arg("table").arg(table.to_string());
        }
        let output = command.output().map_err(PlatformError::Io)?;
        if output.status.success() {
            return Ok(());
        }
        Err(PlatformError::Command(format!(
            "ip route replace failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = route;
        Err(PlatformError::Unsupported(
            "TUN auto-route install is only implemented for Linux in Phase 8A".to_owned(),
        ))
    }
}

fn remove_owned_route(route: &OwnedRoute) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("ip");
        command.arg("route").arg("del");
        command.arg(route.destination.to_string());
        if let Some(gateway) = route.gateway {
            command.arg("via").arg(gateway.to_string());
        }
        command.arg("dev").arg(&route.device);
        if let Some(table) = route.table {
            command.arg("table").arg(table.to_string());
        }
        let output = command.output().map_err(PlatformError::Io)?;
        if output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("No such process")
            || String::from_utf8_lossy(&output.stderr).contains("Cannot find device")
            || String::from_utf8_lossy(&output.stderr).contains("No such file")
        {
            return Ok(());
        }
        Err(PlatformError::Command(format!(
            "ip route del failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = route;
        Ok(())
    }
}

/// Installs a host route via the current default gateway so TUN auto-route
/// cannot capture DIRECT, DNS upstream, or proxy-server packets.
///
/// # Errors
///
/// Returns command failures, missing default-route, or unsupported-platform errors.
pub fn protect_host_route(host: IpAddr, owner: &mut RouteOwner) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let (gateway, device) = linux_default_route(host)?;
        let destination = match host {
            IpAddr::V4(_) => IpNet::new(host, 32),
            IpAddr::V6(_) => IpNet::new(host, 128),
        }
        .map_err(|error| PlatformError::Command(format!("host route prefix: {error}")))?;
        let route = OwnedRoute {
            destination,
            device,
            gateway,
            table: None,
        };
        install_device_route(&route)?;
        owner.record(route);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = host;
        let _ = owner;
        Err(PlatformError::Unsupported(
            "TUN loop-avoidance host routes are only implemented for Linux in Phase 8A".to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_default_route(host: IpAddr) -> Result<(Option<IpAddr>, String), PlatformError> {
    let family = if host.is_ipv4() { "-4" } else { "-6" };
    let output = Command::new("ip")
        .args([family, "route", "show", "default"])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(PlatformError::Command(format!(
            "ip route show default failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut via = None;
    let mut device = None;
    let mut words = stdout.split_whitespace();
    while let Some(word) = words.next() {
        match word {
            "via" => via = words.next(),
            "dev" => device = words.next(),
            _ => {}
        }
    }
    let device = device.ok_or_else(|| {
        PlatformError::Command("default route has no device; refusing TUN auto-route".to_owned())
    })?;
    let gateway = via
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|error| PlatformError::Command(format!("default gateway: {error}")))
        })
        .transpose()?;
    Ok((gateway, device.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_records_and_clears_without_routes() {
        let mut owner = RouteOwner::new();
        assert!(owner.routes().is_empty());
        owner.revert_all().expect("empty revert");
    }
}
