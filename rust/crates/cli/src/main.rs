use std::path::PathBuf;

use clap::Parser;
use rewrite_config::{Config, ConfigSpec};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "rewrite-core", about = "Mihomo Rust compatibility candidate")]
struct Arguments {
    /// Specify configuration file
    #[arg(short = 'f', long = "config")]
    config: PathBuf,

    /// Test configuration and exit
    #[arg(short = 't')]
    test: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute(Arguments::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn execute(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let specification = ConfigSpec::from_path(&arguments.config)?;
    if arguments.test {
        specification.validate_declared_surface()?;
        println!(
            "configuration file {} test is successful",
            arguments.config.display()
        );
        return Ok(());
    }

    let config = Config::try_from(specification)?;
    let shutdown = CancellationToken::new();
    let (reload_sender, reload_receiver) = mpsc::channel(4);
    install_signals(shutdown.clone(), arguments.config.clone(), reload_sender);
    rewrite_runtime::run_with_reload(config, reload_receiver, shutdown).await?;
    Ok(())
}

fn install_signals(
    shutdown: CancellationToken,
    config_path: PathBuf,
    reload_sender: mpsc::Sender<Config>,
) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut terminate =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(signal) => signal,
                    Err(error) => {
                        eprintln!("cannot install SIGTERM handler: {error}");
                        shutdown.cancel();
                        return;
                    }
                };
            let mut hangup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(signal) => signal,
                    Err(error) => {
                        eprintln!("cannot install SIGHUP handler: {error}");
                        shutdown.cancel();
                        return;
                    }
                };
            let ctrl_c = tokio::signal::ctrl_c();
            tokio::pin!(ctrl_c);
            loop {
                tokio::select! {
                    result = &mut ctrl_c => {
                        if let Err(error) = result {
                            eprintln!("Ctrl-C handler failed: {error}");
                        }
                        break;
                    }
                    _ = terminate.recv() => break,
                    received = hangup.recv() => {
                        if received.is_none() {
                            break;
                        }
                        match Config::from_path(&config_path) {
                            Ok(config) => {
                                if reload_sender.send(config).await.is_err() {
                                    break;
                                }
                            }
                            Err(error) => eprintln!("configuration reload failed: {error}"),
                        }
                    }
                }
            }
        }
        #[cfg(not(unix))]
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("Ctrl-C handler failed: {error}");
        }
        shutdown.cancel();
    });
}
