//! TCP original-destination helpers for transparent redirect listeners.

use std::io;
use std::net::SocketAddr;

/// Reads the pre-redirect destination from a redirected TCP socket.
///
/// On Linux this uses `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` (Go
/// `listener/redir`). Other platforms return [`io::ErrorKind::Unsupported`].
///
/// # Errors
///
/// Returns an I/O error when the option is unavailable or the platform does
/// not implement transparent redirect recovery.
#[cfg(unix)]
pub fn tcp_original_destination(
    fd: std::os::fd::RawFd,
    local: SocketAddr,
) -> io::Result<SocketAddr> {
    rewrite_sys::tcp_original_destination(fd, local)
}

/// Windows / non-Unix stub: transparent redir original-destination is unsupported.
#[cfg(not(unix))]
pub fn tcp_original_destination(_fd: (), local: SocketAddr) -> io::Result<SocketAddr> {
    rewrite_sys::tcp_original_destination((), local)
}
