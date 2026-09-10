use std::net::Ipv4Addr;

use ipnet::IpNet;
use rewrite_config::TunConfig;
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::TunError;

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

/// Opens a TUN device with the Phase 8A address/MTU settings.
///
/// # Errors
///
/// Returns device creation failures from `tun-rs`.
pub fn open_tun_device(config: &TunDeviceConfig) -> Result<TunDevice, TunError> {
    let mut builder = DeviceBuilder::new().mtu(config.mtu);
    if let Some(name) = &config.name {
        builder = builder.name(name.clone());
    }
    if let Some(first) = config.inet4.first() {
        let std::net::IpAddr::V4(address) = first.addr() else {
            return Err(TunError::Stack(
                "inet4-address entry must be IPv4".to_owned(),
            ));
        };
        builder = builder.ipv4(address, first.prefix_len(), None::<Ipv4Addr>);
    }
    if let Some(first) = config.inet6.first() {
        let std::net::IpAddr::V6(address) = first.addr() else {
            return Err(TunError::Stack(
                "inet6-address entry must be IPv6".to_owned(),
            ));
        };
        builder = builder.ipv6(address, first.prefix_len());
    }
    let device = builder.build_async()?;
    let name = device
        .name()
        .unwrap_or_else(|_| config.name.clone().unwrap_or_else(|| "tun".to_owned()));
    Ok(TunDevice { device, name })
}
