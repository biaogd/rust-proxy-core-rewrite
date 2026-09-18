//! Linux `TProxy` TCP listener binding (`IP_TRANSPARENT`).

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{LocalTcpOptions, configure_tcp_keepalive};

/// Binds a TCP listener with Linux `TProxy` socket options.
///
/// Matches Go `listener/tproxy`: `SO_REUSEADDR`, `IP_TRANSPARENT` /
/// `IPV6_TRANSPARENT`, and original-destination recv opts. MPTCP is forced
/// off (Go disables it for tproxy). Requires `CAP_NET_ADMIN` on Linux.
///
/// # Errors
///
/// Returns bind/listen errors, or unsupported on non-Linux.
pub fn bind_tproxy_tcp_listener(
    address: SocketAddr,
    options: LocalTcpOptions,
) -> io::Result<std::net::TcpListener> {
    #[cfg(target_os = "linux")]
    {
        linux_bind_tproxy(address, options)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (address, options);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tproxy TCP listener is only implemented on Linux (W1.2)",
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_bind_tproxy(
    address: SocketAddr,
    options: LocalTcpOptions,
) -> io::Result<std::net::TcpListener> {
    use std::os::fd::AsRawFd;

    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    // Go forces MPTCP off for tproxy — do not honor inbound-mptcp here.
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(!options.dual_stack)?;
    }
    configure_tcp_keepalive(&socket, options)?;
    // Transparent opts before bind/listen (also valid after listen; before is safer).
    rewrite_sys::set_ip_transparent(socket.as_raw_fd(), address.is_ipv6())?;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}
