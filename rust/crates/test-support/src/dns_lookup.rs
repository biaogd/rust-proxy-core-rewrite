use std::env;
use std::fmt::Write as _;
use std::path::Path;

use rewrite_config::Config;
use rewrite_dns::{lookup_domain, lookup_domain_primary_ipv4, resolve_ech};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let config_path = arguments.next().ok_or("missing config path")?;
    let operation = arguments.next().ok_or("missing operation")?;
    let host = arguments.next().ok_or("missing host")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let config = Config::from_path(Path::new(&config_path))?;
    let dns = config.dns.as_ref().ok_or("DNS is disabled")?;
    match operation.as_str() {
        "lookup" => {
            let addresses = lookup_domain(dns, &host, dns.ipv6).await?;
            println!(
                "{}",
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        "primary" => {
            let addresses = lookup_domain_primary_ipv4(dns, &host).await?;
            println!(
                "{}",
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        "ech" => {
            let ech = resolve_ech(dns, &host).await?;
            let mut encoded = String::with_capacity(ech.len() * 2);
            for byte in ech {
                write!(&mut encoded, "{byte:02x}")?;
            }
            println!("{encoded}");
        }
        _ => return Err(format!("unknown operation: {operation}").into()),
    }
    Ok(())
}
