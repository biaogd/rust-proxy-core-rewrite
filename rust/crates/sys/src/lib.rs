//! Isolated FFI helpers. Keep this crate tiny — prefer safe wrappers in
//! `rewrite-platform` that call into these functions.

use std::io;
use std::net::SocketAddr;

/// Linux `getsockopt(SO_ORIGINAL_DST)` / `IP6T_SO_ORIGINAL_DST`.
///
/// # Errors
///
/// Returns the OS error from `getsockopt`, or unsupported on non-Linux.
#[cfg(unix)]
pub fn tcp_original_destination(
    fd: std::os::fd::RawFd,
    local: SocketAddr,
) -> io::Result<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        linux_original_destination(fd, local)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, local);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP original destination is only implemented on Linux (W1.1 redir)",
        ))
    }
}

#[cfg(not(unix))]
pub fn tcp_original_destination(_fd: (), local: SocketAddr) -> io::Result<SocketAddr> {
    let _ = local;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP original destination is only implemented on Linux (W1.1 redir)",
    ))
}

#[cfg(target_os = "linux")]
fn linux_original_destination(
    fd: std::os::fd::RawFd,
    local: SocketAddr,
) -> io::Result<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    // SAFETY: `fd` is a live TCP socket; `addr` is a stack buffer sized via
    // `len` that getsockopt will not overrun.
    if local.is_ipv4() {
        let mut addr = libc::sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                SO_ORIGINAL_DST,
                std::ptr::addr_of_mut!(addr).cast(),
                &mut len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let port = u16::from_be(addr.sin_port);
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    } else {
        let mut addr = libc::sockaddr_in6 {
            sin6_family: 0,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
            sin6_scope_id: 0,
        };
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IP6T_SO_ORIGINAL_DST,
                std::ptr::addr_of_mut!(addr).cast(),
                &mut len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let port = u16::from_be(addr.sin6_port);
        let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
        Ok(SocketAddr::new(IpAddr::V6(ip), port))
    }
}

/// Enables Linux `IP_TRANSPARENT` / `IPV6_TRANSPARENT` on a socket (TProxy).
///
/// # Errors
///
/// Returns the OS error from `setsockopt`, or unsupported on non-Linux.
#[cfg(unix)]
pub fn set_ip_transparent(fd: std::os::fd::RawFd, ipv6: bool) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_set_ip_transparent(fd, ipv6)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, ipv6);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IP_TRANSPARENT is only implemented on Linux (W1.2 tproxy)",
        ))
    }
}

#[cfg(not(unix))]
pub fn set_ip_transparent(_fd: (), _ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IP_TRANSPARENT is only implemented on Linux (W1.2 tproxy)",
    ))
}

#[cfg(target_os = "linux")]
fn linux_set_ip_transparent(fd: std::os::fd::RawFd, ipv6: bool) -> io::Result<()> {
    // linux/include/uapi/linux/in.h / in6.h — IPV6_TRANSPARENT = 75 (0x4b)
    const IPV6_TRANSPARENT: libc::c_int = 0x4b;
    const IP_RECVORIGDSTADDR: libc::c_int = 20;
    const IPV6_RECVORIGDSTADDR: libc::c_int = 74;

    // SAFETY: `fd` is a live socket; setsockopt writes a single int option.
    let enable: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            std::ptr::addr_of!(enable).cast(),
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if ipv6 {
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_TRANSPARENT,
                std::ptr::addr_of!(enable).cast(),
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            std::ptr::addr_of!(enable).cast(),
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if ipv6 {
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_RECVORIGDSTADDR,
                std::ptr::addr_of!(enable).cast(),
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
