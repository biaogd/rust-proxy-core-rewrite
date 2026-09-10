use netstack_smoltcp::{Stack, StackBuilder, TcpListener, UdpSocket};

use crate::TunError;

pub struct StackHandles {
    pub stack: Stack,
    pub runner: Option<netstack_smoltcp::Runner>,
    pub udp: UdpSocket,
    pub tcp: TcpListener,
}

/// Builds the pinned `netstack-smoltcp` stack used by Phase 8A.
///
/// # Errors
///
/// Returns stack construction failures.
pub fn build_smoltcp_stack(mtu: usize) -> Result<StackHandles, TunError> {
    let (stack, runner, udp, tcp) = StackBuilder::default()
        .stack_buffer_size(1024)
        .tcp_buffer_size(1024)
        .udp_buffer_size(1024)
        .enable_udp(true)
        .enable_tcp(true)
        .enable_icmp(true)
        .mtu(mtu)
        .build()
        .map_err(|error| TunError::Stack(error.to_string()))?;
    let udp = udp.ok_or_else(|| TunError::Stack("UDP disabled unexpectedly".to_owned()))?;
    let tcp = tcp.ok_or_else(|| TunError::Stack("TCP disabled unexpectedly".to_owned()))?;
    Ok(StackHandles {
        stack,
        runner,
        udp,
        tcp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_smoltcp_stack_without_a_device() {
        let handles = build_smoltcp_stack(1500).expect("stack");
        drop(handles);
    }
}
