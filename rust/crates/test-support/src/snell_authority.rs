//! Snell TCP/UDP relay authority for 7E-A/B/C/D Go/Rust differentials.
//!
//! This is not a Clash inbound. It decrypts versions 1–3, optionally wraps
//! simple-obfs HTTP/TLS, writes `CommandTunnel`, splices Connect to TCP or
//! `CommandUDP` to a per-packet UDP echo path, and keeps `ConnectV2` sessions
//! open after a zero-chunk half-close.

use std::error::Error;
use std::io::{self, Write};
use std::net::SocketAddr;

use rewrite_protocol_snell::{AuthorityOptions, spawn_authority};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let listen = arguments
        .next()
        .ok_or("missing listen address")?
        .parse::<SocketAddr>()?;
    let psk = arguments.next().ok_or("missing psk")?;
    let version = match arguments.next() {
        Some(text) => text.parse::<u8>().map_err(|_| "invalid version")?,
        None => 1,
    };
    let obfs = match arguments.next().as_deref() {
        None | Some("" | "none") => None,
        Some("http") => Some(rewrite_protocol_snell::AuthorityObfs::Http),
        Some("tls") => Some(rewrite_protocol_snell::AuthorityObfs::Tls),
        Some(other) => return Err(format!("unsupported obfs mode {other}").into()),
    };
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let authority = spawn_authority(AuthorityOptions {
        listen,
        psk: psk.into_bytes(),
        version,
        obfs,
    })
    .await?;
    println!("READY {}", authority.local_addr);
    io::stdout().flush()?;
    std::future::pending::<()>().await;
    Ok(())
}
