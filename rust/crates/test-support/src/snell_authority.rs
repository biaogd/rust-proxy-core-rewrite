//! Snell TCP/UDP relay authority for 7E-A/B Go/Rust differentials.
//!
//! This is not a Clash inbound. It decrypts versions 1–3, writes `CommandTunnel`,
//! and splices Connect to TCP or `CommandUDP` to a per-packet UDP echo path.

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
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let authority = spawn_authority(AuthorityOptions {
        listen,
        psk: psk.into_bytes(),
        version,
    })
    .await?;
    println!("READY {}", authority.local_addr);
    io::stdout().flush()?;
    std::future::pending::<()>().await;
    Ok(())
}
