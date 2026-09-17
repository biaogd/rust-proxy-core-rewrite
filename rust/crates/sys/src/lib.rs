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

/// Linux `NETLINK_INET_DIAG` socket lookup: returns `(uid, inode)` for a local
/// source address/port, matching Go `resolveSocketByNetlink`.
///
/// # Errors
///
/// Returns OS errors from netlink dial/execute, or not-found when no socket matches.
#[cfg(target_os = "linux")]
pub fn inet_diag_uid_inode(
    tcp: bool,
    src: std::net::IpAddr,
    src_port: u16,
) -> io::Result<(u32, u32)> {
    linux_inet_diag_uid_inode(tcp, src, src_port)
}

#[cfg(not(target_os = "linux"))]
pub fn inet_diag_uid_inode(
    _tcp: bool,
    _src: std::net::IpAddr,
    _src_port: u16,
) -> io::Result<(u32, u32)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "inet_diag process lookup is only implemented on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn linux_inet_diag_uid_inode(
    tcp: bool,
    src: std::net::IpAddr,
    src_port: u16,
) -> io::Result<(u32, u32)> {
    use std::mem;
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::ptr;

    const NETLINK_INET_DIAG: libc::c_int = 4;
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_DUMP: u16 = 0x100;
    const NLMSG_ERROR: u16 = 0x2;
    const NLMSG_DONE: u16 = 0x3;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NlMsgHdr {
        len: u32,
        type_: u16,
        flags: u16,
        seq: u32,
        pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InetDiagReq {
        family: u8,
        protocol: u8,
        ext: u8,
        pad: u8,
        states: u32,
        src_port: [u8; 2],
        dst_port: [u8; 2],
        src: [u8; 16],
        dst: [u8; 16],
        ifi: u32,
        cookie: [u32; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InetDiagMsg {
        family: u8,
        state: u8,
        timer: u8,
        retrans: u8,
        src_port: [u8; 2],
        dst_port: [u8; 2],
        src: [u8; 16],
        dst: [u8; 16],
        ifi: u32,
        cookie: [u32; 2],
        expires: u32,
        rqueue: u32,
        wqueue: u32,
        uid: u32,
        inode: u32,
    }

    let mut request = InetDiagReq {
        family: 0,
        protocol: if tcp {
            libc::IPPROTO_TCP as u8
        } else {
            libc::IPPROTO_UDP as u8
        },
        ext: 0,
        pad: 0,
        states: 0xffff_ffff,
        src_port: src_port.to_be_bytes(),
        dst_port: [0; 2],
        src: [0; 16],
        dst: [0; 16],
        ifi: 0,
        cookie: [0xffff_ffff, 0xffff_ffff],
    };
    match src {
        IpAddr::V4(v4) => {
            request.family = libc::AF_INET as u8;
            request.src[..4].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            request.family = libc::AF_INET6 as u8;
            request.src.copy_from_slice(&v6.octets());
        }
    }

    // SAFETY: AF_NETLINK SOCK_RAW socket for INET_DIAG.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_INET_DIAG) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let hdr_len = mem::size_of::<NlMsgHdr>();
    let req_len = mem::size_of::<InetDiagReq>();
    let total = hdr_len + req_len;
    let mut message = vec![0_u8; total];
    let hdr = NlMsgHdr {
        len: total as u32,
        type_: SOCK_DIAG_BY_FAMILY,
        flags: NLM_F_REQUEST | NLM_F_DUMP,
        seq: 1,
        pid: 0,
    };
    // SAFETY: `message` is large enough for the header.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::addr_of!(hdr).cast::<u8>(),
            message.as_mut_ptr(),
            hdr_len,
        );
        ptr::copy_nonoverlapping(
            ptr::addr_of!(request).cast::<u8>(),
            message.as_mut_ptr().add(hdr_len),
            req_len,
        );
    }

    let mut sockaddr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    sockaddr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: sendto to kernel netlink.
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
            ptr::addr_of!(sockaddr).cast(),
            mem::size_of_val(&sockaddr) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = vec![0_u8; 8192];
    let src_unmapped = match src {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    };

    loop {
        // SAFETY: recvfrom into owned buffer.
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        let mut offset = 0;
        while offset + hdr_len <= n {
            // SAFETY: buffer contains aligned nlmsghdr from kernel.
            let hdr = unsafe { ptr::read_unaligned(buf.as_ptr().add(offset).cast::<NlMsgHdr>()) };
            if hdr.len as usize > n - offset || hdr.len as usize > buf.len() {
                break;
            }
            if hdr.type_ == NLMSG_DONE {
                return Err(io::Error::new(io::ErrorKind::NotFound, "socket not found"));
            }
            if hdr.type_ == NLMSG_ERROR {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "inet_diag netlink error",
                ));
            }
            let payload_off = offset + hdr_len;
            let payload_len = hdr.len as usize - hdr_len;
            if payload_len >= mem::size_of::<InetDiagMsg>() {
                let msg = unsafe {
                    ptr::read_unaligned(buf.as_ptr().add(payload_off).cast::<InetDiagMsg>())
                };
                let port = u16::from_be_bytes(msg.src_port);
                if port == src_port {
                    let msg_src = match msg.family as i32 {
                        libc::AF_INET => {
                            let mut octets = [0_u8; 4];
                            octets.copy_from_slice(&msg.src[..4]);
                            IpAddr::V4(std::net::Ipv4Addr::from(octets))
                        }
                        libc::AF_INET6 => {
                            let addr = std::net::Ipv6Addr::from(msg.src);
                            addr.to_ipv4_mapped()
                                .map(IpAddr::V4)
                                .unwrap_or(IpAddr::V6(addr))
                        }
                        _ => {
                            offset += align_nlmsg(hdr.len as usize);
                            continue;
                        }
                    };
                    if msg_src == src_unmapped {
                        return Ok((msg.uid, msg.inode));
                    }
                }
            }
            offset += align_nlmsg(hdr.len as usize);
        }
    }
}

#[cfg(target_os = "linux")]
fn align_nlmsg(len: usize) -> usize {
    (len + 3) & !3
}
