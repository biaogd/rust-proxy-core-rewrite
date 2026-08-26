use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use rewrite_config::{Config, ConfigError, ConfigSpec};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "rewrite-core", about = "Mihomo Rust compatibility candidate")]
struct Arguments {
    /// Show version and build information
    #[arg(short = 'v')]
    version: bool,

    /// Set configuration directory
    #[arg(short = 'd', value_name = "DIRECTORY")]
    home: Option<PathBuf>,

    /// Specify configuration file, or '-' for standard input
    #[arg(short = 'f', value_name = "FILE")]
    config_file: Option<String>,

    /// Specify base64-encoded configuration string
    #[arg(long = "config", value_name = "BASE64")]
    config_string: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't')]
    test: bool,
}

#[derive(Clone, Debug)]
enum ConfigInput {
    File(PathBuf),
    FrozenYaml(String),
}

impl ConfigInput {
    fn specification(&self) -> Result<ConfigSpec, ConfigError> {
        match self {
            Self::File(path) => ConfigSpec::from_path(path),
            Self::FrozenYaml(source) => ConfigSpec::from_yaml(source),
        }
    }

    fn runtime_config(&self) -> Result<Config, ConfigError> {
        match self {
            Self::File(path) => Config::from_path(path),
            Self::FrozenYaml(source) => Config::from_yaml(source),
        }
    }

    fn display_path(&self) -> &Path {
        match self {
            Self::File(path) => path,
            Self::FrozenYaml(_) => Path::new("config.yaml"),
        }
    }
}

#[tokio::main]
async fn main() {
    let arguments = Arguments::parse_from(normalized_arguments(std::env::args_os()));
    if let Err(error) = execute(arguments).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn execute(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.version {
        print_version();
        return Ok(());
    }
    let input = resolve_config_input(&arguments)?;
    if arguments.test {
        input.specification()?.validate_declared_surface()?;
        println!(
            "configuration file {} test is successful",
            input.display_path().display()
        );
        return Ok(());
    }

    let config = input.runtime_config()?;
    let shutdown = CancellationToken::new();
    let (reload_sender, reload_receiver) = mpsc::channel(4);
    install_signals(shutdown.clone(), input, reload_sender);
    rewrite_runtime::run_with_reload(config, reload_receiver, shutdown).await?;
    Ok(())
}

fn print_version() {
    let version = option_env!("MIHOMO_VERSION").unwrap_or("1.10.0");
    let build_time = option_env!("MIHOMO_BUILD_TIME").unwrap_or("unknown time");
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        "x86" => "386",
        other => other,
    };
    println!(
        "Mihomo Meta {version} {os} {architecture} with rustc{} {build_time}",
        env!("MIHOMO_RUSTC_VERSION")
    );
}

fn normalized_arguments(arguments: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut normalized = Vec::new();
    let mut value_follows = false;
    let mut options = true;
    for argument in arguments {
        if value_follows || !options {
            value_follows = false;
            normalized.push(argument);
            continue;
        }
        if argument == "--" {
            options = false;
            normalized.push(argument);
        } else if argument == "-config" {
            normalized.push(OsString::from("--config"));
            value_follows = true;
        } else if let Some(value) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("-config="))
        {
            normalized.push(OsString::from(format!("--config={value}")));
        } else {
            value_follows = matches!(argument.to_str(), Some("-d" | "-f" | "--config"));
            normalized.push(argument);
        }
    }
    normalized
}

fn resolve_config_input(arguments: &Arguments) -> Result<ConfigInput, Box<dyn std::error::Error>> {
    let current_directory = std::env::current_dir()?;
    let home_value = arguments
        .home
        .as_ref()
        .map(|path| path.as_os_str().to_owned())
        .or_else(|| std::env::var_os("CLASH_HOME_DIR"));
    let home_directory = if home_value.as_ref().is_some_and(|value| !value.is_empty()) {
        absolute_from(
            &current_directory,
            PathBuf::from(home_value.expect("checked above")),
        )?
    } else {
        default_home_directory(&current_directory)
    };

    let config_string = arguments
        .config_string
        .clone()
        .or_else(|| std::env::var("CLASH_CONFIG_STRING").ok())
        .unwrap_or_default();
    if !config_string.is_empty() {
        let encoded = config_string
            .bytes()
            .filter(|byte| !matches!(byte, b'\r' | b'\n'))
            .collect::<Vec<_>>();
        let decoded = STANDARD.decode(encoded)?;
        if decoded.is_empty() {
            return Ok(ConfigInput::File(PathBuf::from("config.yaml")));
        }
        return Ok(ConfigInput::FrozenYaml(String::from_utf8(decoded)?));
    }

    let config_file = arguments
        .config_file
        .clone()
        .or_else(|| std::env::var("CLASH_CONFIG_FILE").ok())
        .unwrap_or_default();
    if config_file == "-" {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes)?;
        if bytes.is_empty() {
            return Ok(ConfigInput::File(PathBuf::from("config.yaml")));
        }
        return Ok(ConfigInput::FrozenYaml(String::from_utf8(bytes)?));
    }

    let path = if config_file.is_empty() {
        home_directory.join("config.yaml")
    } else {
        absolute_from(&current_directory, PathBuf::from(config_file))?
    };
    initialize_config_file(&home_directory, &path)?;
    Ok(ConfigInput::File(path))
}

fn initialize_config_file(home_directory: &Path, config_path: &Path) -> std::io::Result<()> {
    if std::fs::metadata(home_directory)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        std::fs::create_dir_all(home_directory)?;
    }
    if std::fs::metadata(config_path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(config_path)?
            .write_all(b"mixed-port: 7890")?;
    }
    Ok(())
}

fn default_home_directory(current_directory: &Path) -> PathBuf {
    let user_home = home::home_dir().unwrap_or_else(|| current_directory.to_path_buf());
    let legacy = user_home.join(".config").join("mihomo");
    if std::fs::metadata(&legacy).is_err()
        && let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME")
    {
        return PathBuf::from(config_home).join("mihomo");
    }
    legacy
}

fn absolute_from(current_directory: &Path, path: PathBuf) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        std::path::absolute(path)
    } else {
        std::path::absolute(current_directory.join(path))
    }
}

fn install_signals(
    shutdown: CancellationToken,
    input: ConfigInput,
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
                        match input.runtime_config() {
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

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::normalized_arguments;

    #[test]
    fn normalizes_go_single_dash_config_forms_only() {
        let arguments = normalized_arguments([
            OsString::from("rewrite-core"),
            OsString::from("-config"),
            OsString::from("one"),
            OsString::from("-config=two"),
            OsString::from("-f"),
            OsString::from("config.yaml"),
        ]);
        assert_eq!(
            arguments,
            [
                "rewrite-core",
                "--config",
                "one",
                "--config=two",
                "-f",
                "config.yaml",
            ]
        );
    }

    #[test]
    fn preserves_option_like_values_and_arguments_after_terminator() {
        let arguments = normalized_arguments([
            OsString::from("rewrite-core"),
            OsString::from("-f"),
            OsString::from("-config"),
            OsString::from("--"),
            OsString::from("-config=literal"),
        ]);
        assert_eq!(
            arguments,
            ["rewrite-core", "-f", "-config", "--", "-config=literal",]
        );
    }
}
