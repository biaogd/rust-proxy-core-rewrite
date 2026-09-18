//! Process name/path/UID lookup for rule metadata (RULE-07 / RUN-05).

use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rewrite_model::Network;

/// Resolved process identity for a local socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInfo {
    pub uid: u32,
    pub path: PathBuf,
}

/// Looks up the process owning `(network, src_ip, src_port)`.
///
/// Linux uses `NETLINK_INET_DIAG` then `/proc/<pid>/fd` → `exe`. Other
/// platforms return [`io::ErrorKind::Unsupported`].
///
/// # Errors
///
/// Returns not-found when the socket or process cannot be resolved, or
/// unsupported off Linux.
pub fn find_process_name(
    network: Network,
    src_ip: IpAddr,
    src_port: u16,
) -> io::Result<ProcessInfo> {
    #[cfg(target_os = "linux")]
    {
        linux_find_process(network, src_ip, src_port)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (network, src_ip, src_port);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process lookup is only implemented on Linux (W2.1)",
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_find_process(network: Network, src_ip: IpAddr, src_port: u16) -> io::Result<ProcessInfo> {
    let tcp = matches!(network, Network::Tcp);
    let (uid, inode) = rewrite_sys::inet_diag_uid_inode(tcp, src_ip, src_port)?;
    let path = resolve_process_path_by_proc(inode, uid)?;
    Ok(ProcessInfo { uid, path })
}

#[cfg(target_os = "linux")]
fn resolve_process_path_by_proc(inode: u32, uid: u32) -> io::Result<PathBuf> {
    let socket = format!("socket:[{inode}]");
    let entries = fs::read_dir("/proc")?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != uid {
                continue;
            }
        }
        let process_path = entry.path();
        let fd_path = process_path.join("fd");
        let Ok(fds) = fs::read_dir(&fd_path) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            if link.to_string_lossy() == socket {
                return fs::read_link(process_path.join("exe"));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("process of uid({uid}),inode({inode}) not found"),
    ))
}

/// Basename of a process path, matching Go `filepath.Base`.
#[must_use]
pub fn process_basename(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}
