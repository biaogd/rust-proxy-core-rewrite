use std::env;
use std::fs;

use rewrite_config::Config;
use rewrite_dns::{
    resolve_default_domain, resolve_direct_domain, resolve_domain, resolve_proxy_domain,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let config_path = arguments.next().ok_or("missing config path")?;
    let resolver_set = arguments.next().ok_or("missing resolver set")?;
    let host = arguments.next().ok_or("missing host")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let source = fs::read_to_string(config_path)?;
    let config = Config::from_yaml(&source)?;
    let dns = config.dns.as_ref().ok_or("DNS is disabled")?;
    let address = match resolver_set.as_str() {
        "main" => resolve_domain(dns, &host, false).await?,
        "default" => resolve_default_domain(dns, &host, false).await?,
        "direct" => resolve_direct_domain(dns, &host, false).await?,
        "proxy" => resolve_proxy_domain(dns, &host, false).await?,
        _ => return Err(format!("unknown resolver set: {resolver_set}").into()),
    };
    println!("{address}");
    Ok(())
}
