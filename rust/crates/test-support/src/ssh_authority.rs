//! SSH `direct-tcpip` authority for 6J-A Go/Rust differentials.
//!
//! This is not a Clash inbound. It accepts password and optional public-key
//! authentication, then splices opened channels to the requested TCP dest.

use std::error::Error;
use std::io::{self, Write};
use std::net::SocketAddr;

use rewrite_protocol_ssh::{AuthorityOptions, spawn_authority};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let listen = arguments
        .next()
        .ok_or("missing listen address")?
        .parse::<SocketAddr>()?;
    let username = arguments.next().ok_or("missing username")?;
    let password = arguments.next().ok_or("missing password")?;
    let authorized_key = arguments.next();
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }

    let (bound, host_key) = spawn_authority(
        listen,
        AuthorityOptions {
            username,
            password: Some(password),
            authorized_keys: authorized_key.into_iter().collect(),
        },
    )
    .await?;
    println!("READY {bound}");
    println!("HOST_KEY {host_key}");
    io::stdout().flush()?;
    std::future::pending::<()>().await;
    Ok(())
}
