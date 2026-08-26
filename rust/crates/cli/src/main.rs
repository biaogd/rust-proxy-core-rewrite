use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use rewrite_config::{Config, ConfigSpec};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "rewrite-core", about = "Mihomo Rust compatibility candidate")]
struct Arguments {
    /// Show version and build information
    #[arg(short = 'v')]
    version: bool,

    /// Use geodata mode as the configuration default
    #[arg(short = 'm')]
    geodata_mode: bool,

    /// Override external controller address
    #[arg(long = "ext-ctl", value_name = "ADDRESS")]
    external_controller: Option<String>,

    /// Override external controller secret
    #[arg(long = "secret", value_name = "SECRET")]
    secret: Option<String>,

    /// Use one X25519 age identity to decrypt configuration
    #[arg(long = "age-secret-key", value_name = "IDENTITY")]
    age_secret_key: Option<String>,

    /// Run a shell command after startup
    #[arg(long = "post-up", value_name = "COMMAND")]
    post_up: Option<String>,

    /// Run a shell command after shutdown
    #[arg(long = "post-down", value_name = "COMMAND")]
    post_down: Option<String>,

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

#[derive(Clone, Debug, Default)]
struct RuntimeOverrides {
    external_controller: String,
    secret: String,
}

impl RuntimeOverrides {
    fn from_arguments(arguments: &Arguments) -> Self {
        Self {
            external_controller: arguments
                .external_controller
                .clone()
                .or_else(|| std::env::var("CLASH_OVERRIDE_EXTERNAL_CONTROLLER").ok())
                .unwrap_or_default(),
            secret: arguments
                .secret
                .clone()
                .or_else(|| std::env::var("CLASH_OVERRIDE_SECRET").ok())
                .unwrap_or_default(),
        }
    }

    fn apply(&self, mut config: Config) -> Config {
        if !self.external_controller.is_empty() {
            config
                .external_controller
                .clone_from(&self.external_controller);
        }
        if !self.secret.is_empty() {
            config.secret.clone_from(&self.secret);
        }
        config
    }
}

impl ConfigInput {
    fn specification(
        &self,
        geodata_mode: bool,
        age_secret_key: &str,
    ) -> Result<ConfigSpec, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::File(path) => Ok(ConfigSpec::from_yaml_at_path_with_geodata_mode(
                &decrypt_yaml(std::fs::read(path)?.as_slice(), age_secret_key)?,
                path,
                geodata_mode,
            )?),
            Self::FrozenYaml(source) => Ok(ConfigSpec::from_yaml_with_geodata_mode(
                &decrypt_yaml(source.as_bytes(), age_secret_key)?,
                geodata_mode,
            )?),
        }
    }

    fn runtime_config(
        &self,
        geodata_mode: bool,
        age_secret_key: &str,
    ) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::File(path) => Ok(Config::from_yaml_at_path_with_geodata_mode(
                &decrypt_yaml(std::fs::read(path)?.as_slice(), age_secret_key)?,
                path,
                geodata_mode,
            )?),
            Self::FrozenYaml(source) => Ok(Config::from_yaml_with_geodata_mode(
                &decrypt_yaml(source.as_bytes(), age_secret_key)?,
                geodata_mode,
            )?),
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
    let raw_arguments: Vec<_> = std::env::args_os().collect();
    if raw_arguments.get(1).and_then(|value| value.to_str()) == Some("generate") {
        if let Err(error) = run_generate_subcommand(&raw_arguments[2..]) {
            eprintln!("{error}");
            std::process::exit(2);
        }
        return;
    }
    if raw_arguments.get(1).and_then(|value| value.to_str()) == Some("convert-ruleset") {
        if let Err(error) = run_convert_ruleset_subcommand(&raw_arguments[2..]) {
            eprintln!("{error}");
            std::process::exit(2);
        }
        return;
    }
    if raw_arguments.get(1).and_then(|value| value.to_str()) == Some("age") {
        if let Err(error) = run_age_subcommand(&raw_arguments[2..]) {
            eprintln!("{error}");
            std::process::exit(2);
        }
        return;
    }
    let arguments = Arguments::parse_from(normalized_arguments(raw_arguments));
    if let Err(error) = execute(arguments).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_generate_subcommand(
    arguments: &[OsString],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(command) = arguments.first() else {
        return Err(std::io::Error::other(
            "Using: generate uuid/reality-keypair/wg-keypair/ech-keypair/vless-mlkem768/vless-x25519/sudoku-keypair",
        )
        .into());
    };
    match command.to_str() {
        Some("uuid") => println!("{}", uuid::Uuid::new_v4()),
        Some("reality-keypair") => {
            let pair = rewrite_generator::x25519_keypair();
            let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            println!("PrivateKey: {}", encoding.encode(pair.private));
            println!("PublicKey: {}", encoding.encode(pair.public));
        }
        Some("wg-keypair") => {
            let pair = rewrite_generator::x25519_keypair();
            println!("PrivateKey: {}", STANDARD.encode(pair.private));
            println!("PublicKey: {}", STANDARD.encode(pair.public));
        }
        Some("vless-x25519") => {
            let private = arguments.get(1).map(decode_vless_private).transpose()?;
            let material = rewrite_generator::vless_x25519(private);
            let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let private = encoding.encode(material.pair.private);
            let password = encoding.encode(material.pair.public);
            println!("PrivateKey: {private}");
            println!("Password: {password}");
            println!("Hash32: {}", encoding.encode(material.hash32));
            println!("-----------------------");
            println!("      Lazy-Config      ");
            println!("-----------------------");
            println!("[Server] decryption: \"mlkem768x25519plus.native.600s.{private}\"");
            println!("[Client] encryption: \"mlkem768x25519plus.native.0rtt.{password}\"");
        }
        Some("ech-keypair") => {
            let public_name = arguments
                .get(1)
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    std::io::Error::other("Using: generate ech-keypair <plain_server_name>")
                })?;
            let pair = rewrite_generator::ech_keypair(public_name)?;
            println!("Config: {}", STANDARD.encode(pair.config_list));
            println!("Key: {}", pair.key_pem);
        }
        Some("vless-mlkem768") => {
            let seed = arguments.get(1).map(decode_mlkem_seed).transpose()?;
            let material = rewrite_generator::vless_mlkem768(seed);
            let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let seed = encoding.encode(material.seed);
            let client = encoding.encode(material.client);
            println!("Seed: {seed}");
            println!("Client: {client}");
            println!("Hash32: {}", encoding.encode(material.hash32));
            println!("-----------------------");
            println!("      Lazy-Config      ");
            println!("-----------------------");
            println!("[Server] decryption: \"mlkem768x25519plus.native.600s.{seed}\"");
            println!("[Client] encryption: \"mlkem768x25519plus.native.0rtt.{client}\"");
        }
        _ => {}
    }
    Ok(())
}

fn decode_vless_private(
    value: &OsString,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let value = value
        .to_str()
        .ok_or_else(|| std::io::Error::other("invalid X25519 private key"))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .unwrap_or_default();
    decoded.try_into().map_err(|_| {
        std::io::Error::other(format!("invalid length of X25519 private key: {value}")).into()
    })
}

fn decode_mlkem_seed(
    value: &OsString,
) -> Result<[u8; 64], Box<dyn std::error::Error + Send + Sync>> {
    let value = value
        .to_str()
        .ok_or_else(|| std::io::Error::other("invalid ML-KEM-768 seed"))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .unwrap_or_default();
    decoded.try_into().map_err(|_| {
        std::io::Error::other(format!("invalid length of ML-KEM-768 seed: {value}")).into()
    })
}

fn run_convert_ruleset_subcommand(
    arguments: &[OsString],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let usage = "Usage: convert-ruleset <behavior> <format> <source file> <target file>";
    let behavior = arguments
        .first()
        .and_then(|value| value.to_str())
        .ok_or_else(|| std::io::Error::other(usage))?;
    if !matches!(behavior, "ipcidr" | "domain") {
        return Err(std::io::Error::other(format!("unsupported behavior type: {behavior}")).into());
    }
    let format = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(|| std::io::Error::other(usage))?;
    if !matches!(format, "mrs" | "text" | "yaml") {
        return Err(
            std::io::Error::other(format!("unsupported conversion format: {format}")).into(),
        );
    }
    let source = arguments
        .get(2)
        .ok_or_else(|| std::io::Error::other(usage))?;
    let target = arguments
        .get(3)
        .ok_or_else(|| std::io::Error::other(usage))?;
    let source = std::fs::read(source)?;
    let mut target = std::fs::File::create(target)?;
    let output = match (behavior, format) {
        ("ipcidr", "mrs") => rewrite_ruleset::ipcidr_mrs_to_text(&source)?,
        ("ipcidr", "text") => {
            rewrite_ruleset::ipcidr_to_mrs(&source, rewrite_ruleset::SourceFormat::Text)?
        }
        ("ipcidr", "yaml") => {
            rewrite_ruleset::ipcidr_to_mrs(&source, rewrite_ruleset::SourceFormat::Yaml)?
        }
        ("domain", "mrs") => rewrite_ruleset::domain_mrs_to_text(&source)?,
        ("domain", "text") => {
            rewrite_ruleset::domain_to_mrs(&source, rewrite_ruleset::SourceFormat::Text)?
        }
        ("domain", "yaml") => {
            rewrite_ruleset::domain_to_mrs(&source, rewrite_ruleset::SourceFormat::Yaml)?
        }
        _ => unreachable!("format was validated"),
    };
    target.write_all(&output)?;
    Ok(())
}

async fn execute(arguments: Arguments) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if arguments.version {
        print_version();
        return Ok(());
    }
    let age_secret_key = arguments
        .age_secret_key
        .clone()
        .or_else(|| std::env::var("CLASH_AGE_SECRET_KEY").ok())
        .unwrap_or_default();
    if !age_secret_key.is_empty()
        && let Err(error) = rewrite_age::validate_x25519_identity(&age_secret_key)
    {
        eprintln!("Parse age-secret-key error: {error}");
    }
    let input = resolve_config_input(&arguments)?;
    if arguments.test {
        input
            .specification(arguments.geodata_mode, &age_secret_key)?
            .validate_declared_surface()?;
        println!(
            "configuration file {} test is successful",
            input.display_path().display()
        );
        return Ok(());
    }

    let overrides = RuntimeOverrides::from_arguments(&arguments);
    let config = overrides.apply(input.runtime_config(arguments.geodata_mode, &age_secret_key)?);
    let post_up = arguments
        .post_up
        .as_deref()
        .map(str::to_owned)
        .or_else(|| std::env::var("CLASH_POST_UP").ok())
        .unwrap_or_default();
    let post_down = arguments
        .post_down
        .as_deref()
        .map(str::to_owned)
        .or_else(|| std::env::var("CLASH_POST_DOWN").ok())
        .unwrap_or_default();
    let shutdown = CancellationToken::new();
    let (reload_sender, reload_receiver) = mpsc::channel(4);
    let (ready_sender, ready_receiver) = oneshot::channel();
    let (shutdown_hook_ready_sender, shutdown_hook_ready_receiver) = oneshot::channel();
    let (continue_shutdown_sender, continue_shutdown_receiver) = oneshot::channel();
    let runtime_shutdown = shutdown.clone();
    let runtime = tokio::spawn(rewrite_runtime::run_with_reload_lifecycle(
        config,
        reload_receiver,
        runtime_shutdown,
        rewrite_runtime::LifecycleSignals::new(
            ready_sender,
            shutdown_hook_ready_sender,
            continue_shutdown_receiver,
        ),
    ));
    if ready_receiver.await.is_err() {
        return match runtime.await? {
            Ok(()) => Err(std::io::Error::other("runtime stopped before readiness").into()),
            Err(error) => Err(error.into()),
        };
    }
    if !post_up.is_empty()
        && let Err(error) = execute_shell(&post_up).await
    {
        shutdown.cancel();
        let _ = continue_shutdown_sender.send(());
        runtime.await??;
        return Err(std::io::Error::other(format!("post-up script error: {error}")).into());
    }
    install_signals(
        shutdown.clone(),
        input,
        arguments.geodata_mode,
        age_secret_key,
        overrides,
        reload_sender,
    );
    if shutdown_hook_ready_receiver.await.is_err() {
        return match runtime.await? {
            Ok(()) => Err(std::io::Error::other(
                "runtime stopped before the shutdown hook barrier",
            )
            .into()),
            Err(error) => Err(error.into()),
        };
    }
    if !post_down.is_empty()
        && let Err(error) = execute_shell(&post_down).await
    {
        eprintln!("post-down script error: {error}");
    }
    let _ = continue_shutdown_sender.send(());
    runtime.await??;
    Ok(())
}

async fn execute_shell(command: &str) -> std::io::Result<()> {
    #[cfg(windows)]
    let output = Command::new("cmd.exe")
        .arg("/C")
        .arg(command)
        .output()
        .await?;
    #[cfg(not(windows))]
    let output = Command::new("sh").arg("-c").arg(command).output().await?;
    if output.status.success() {
        return Ok(());
    }
    let mut details = output.stdout;
    details.extend(output.stderr);
    Err(std::io::Error::other(format!(
        "{}, {}",
        output.status,
        String::from_utf8_lossy(&details)
    )))
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

fn decrypt_yaml(
    data: &[u8],
    age_secret_key: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let decrypted = rewrite_age::decrypt_config(data, age_secret_key)
        .map_err(|error| std::io::Error::other(format!("decrypt config error: {error}")))?;
    Ok(String::from_utf8(decrypted)?)
}

fn run_age_subcommand(
    arguments: &[OsString],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match arguments.first().and_then(|value| value.to_str()) {
        Some("keygen") => {
            let (secret_key, public_key) = rewrite_age::generate_x25519_key_pair();
            let created = time::OffsetDateTime::now_utc()
                .replace_nanosecond(0)?
                .format(&time::format_description::well_known::Rfc3339)?;
            println!("# created: {created}");
            println!("# public key: {public_key}");
            println!("{secret_key}");
            Ok(())
        }
        Some("convert") => {
            let secret_key = arguments
                .get(1)
                .and_then(|value| value.to_str())
                .ok_or_else(|| std::io::Error::other("Using: age convert <secret_key>"))?;
            println!(
                "{}",
                rewrite_age::recipient_for_x25519_identity(secret_key)?
            );
            Ok(())
        }
        Some("encrypt") => {
            let public_key = age_argument(
                arguments,
                1,
                "age encrypt <public_key> <source_file> <target_file>",
            )?;
            let source = arguments.get(2).ok_or_else(|| {
                std::io::Error::other("Using: age encrypt <public_key> <source_file> <target_file>")
            })?;
            let target = arguments.get(3).ok_or_else(|| {
                std::io::Error::other("Using: age encrypt <public_key> <source_file> <target_file>")
            })?;
            let data = read_age_input(source)?;
            let encrypted = rewrite_age::encrypt_x25519_armor(&data, public_key)?;
            write_age_output(target, encrypted.as_bytes())?;
            Ok(())
        }
        Some("decrypt") => {
            let secret_key = age_argument(
                arguments,
                1,
                "age decrypt <secret_key> <source_file> <target_file>",
            )?;
            let source = arguments.get(2).ok_or_else(|| {
                std::io::Error::other("Using: age decrypt <secret_key> <source_file> <target_file>")
            })?;
            let target = arguments.get(3).ok_or_else(|| {
                std::io::Error::other("Using: age decrypt <secret_key> <source_file> <target_file>")
            })?;
            let data = read_age_input(source)?;
            let decrypted = rewrite_age::decrypt_config(&data, secret_key)?;
            write_age_output(target, &decrypted)?;
            Ok(())
        }
        Some(command) => Err(std::io::Error::other(format!(
            "age subcommand is not implemented: {command}"
        ))
        .into()),
        None => {
            Err(std::io::Error::other("Using: age keygen/keygen-pq/convert/decrypt/encrypt").into())
        }
    }
}

fn age_argument<'a>(
    arguments: &'a [OsString],
    index: usize,
    usage: &'static str,
) -> Result<&'a str, std::io::Error> {
    arguments
        .get(index)
        .and_then(|value| value.to_str())
        .ok_or_else(|| std::io::Error::other(format!("Using: {usage}")))
}

fn read_age_input(source: &std::ffi::OsStr) -> std::io::Result<Vec<u8>> {
    if source == "-" {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        Ok(data)
    } else {
        std::fs::read(source)
    }
}

fn write_age_output(target: &std::ffi::OsStr, data: &[u8]) -> std::io::Result<()> {
    if target == "-" {
        std::io::stdout().write_all(data)
    } else {
        std::fs::write(target, data)
    }
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
        } else if matches!(
            argument.to_str(),
            Some(
                "-config" | "-ext-ctl" | "-secret" | "-age-secret-key" | "-post-up" | "-post-down"
            )
        ) {
            normalized.push(OsString::from(format!("-{}", argument.to_string_lossy())));
            value_follows = true;
        } else if let Some((name, value)) = argument.to_str().and_then(|value| {
            [
                "config",
                "ext-ctl",
                "secret",
                "age-secret-key",
                "post-up",
                "post-down",
            ]
            .into_iter()
            .find_map(|name| {
                value
                    .strip_prefix(&format!("-{name}="))
                    .map(|value| (name, value))
            })
        }) {
            normalized.push(OsString::from(format!("--{name}={value}")));
        } else {
            value_follows = matches!(
                argument.to_str(),
                Some(
                    "-d" | "-f"
                        | "--config"
                        | "--ext-ctl"
                        | "--secret"
                        | "--age-secret-key"
                        | "--post-up"
                        | "--post-down"
                )
            );
            normalized.push(argument);
        }
    }
    normalized
}

fn resolve_config_input(
    arguments: &Arguments,
) -> Result<ConfigInput, Box<dyn std::error::Error + Send + Sync>> {
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
    geodata_mode: bool,
    age_secret_key: String,
    overrides: RuntimeOverrides,
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
                        match input
                            .runtime_config(geodata_mode, &age_secret_key)
                            .map(|config| overrides.apply(config))
                        {
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
            OsString::from("-ext-ctl"),
            OsString::from("127.0.0.1:9090"),
            OsString::from("-secret=token"),
            OsString::from("-age-secret-key=AGE-SECRET-KEY-1EXAMPLE"),
            OsString::from("-post-up"),
            OsString::from("echo up"),
            OsString::from("-post-down=echo down"),
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
                "--ext-ctl",
                "127.0.0.1:9090",
                "--secret=token",
                "--age-secret-key=AGE-SECRET-KEY-1EXAMPLE",
                "--post-up",
                "echo up",
                "--post-down=echo down",
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
