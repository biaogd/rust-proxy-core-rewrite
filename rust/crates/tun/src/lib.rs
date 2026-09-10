//! TUN device and userspace stack adaptation for Phase 8.
//!
//! Packet I/O uses `tun-rs`. TCP/UDP session extraction uses
//! `netstack-smoltcp`. Platform route/device ownership lives in
//! `rewrite-platform`; this crate does not install routes itself.

mod device;
mod error;
mod session;
mod stack;

pub use device::{TunDevice, TunDeviceConfig, open_tun_device};
pub use error::TunError;
pub use session::{
    InboundTcpSession, InboundUdpDatagram, TunInboundStream, TunSessionHub, TunUdpReplyTx,
    spawn_session_hub,
};
pub use stack::{StackHandles, build_smoltcp_stack};
