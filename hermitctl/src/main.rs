use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hermitshell_common::HermitConfig;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

const DEFAULT_CONFIG: &str = "/etc/hermitshell/hermitshell.toml";
const DEFAULT_SECRETS: &str = "/etc/hermitshell/hermitshell.secrets.toml";
const DEFAULT_SOCKET: &str = "/run/hermitshell/agent.sock";

#[derive(Parser)]
#[command(name = "hermitctl", about = "HermitShell declarative configuration tool")]
struct Cli {
    /// Path to agent socket
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply configuration from TOML file
    Apply {
        /// Path to config file
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Path to secrets file
        #[arg(long, default_value = DEFAULT_SECRETS)]
        secrets: Option<PathBuf>,
    },
    /// Show what would change without applying
    Diff {
        /// Path to config file
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Export current config as TOML
    Export {
        /// Include secrets in output
        #[arg(long)]
        secrets: bool,
    },
    /// Validate config file without applying
    Validate {
        /// Path to config file
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Show runtime status
    Status,
}

fn socket_rpc(socket_path: &std::path::Path, request: &serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect to agent socket at {}", socket_path.display()))?;
    let req_bytes = serde_json::to_vec(request)?;
    stream.write_all(&req_bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    serde_json::from_str(&response).context("failed to parse agent response")
}

fn load_config(path: &std::path::Path) -> Result<HermitConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    HermitConfig::from_toml(&content)
        .with_context(|| format!("failed to parse TOML config: {}", path.display()))
}

fn cmd_apply(cli: &Cli, config_path: &std::path::Path, secrets_path: Option<&std::path::Path>) -> Result<()> {
    let config = load_config(config_path)?;

    // Validate
    let errors = config.validate();
    if !errors.is_empty() {
        eprintln!("Config validation errors:");
        for e in &errors {
            eprintln!("  {}", e);
        }
        std::process::exit(1);
    }

    // Load secrets if the file exists
    let secrets = if let Some(sp) = secrets_path {
        if sp.exists() {
            let content = std::fs::read_to_string(sp)
                .with_context(|| format!("failed to read secrets file: {}", sp.display()))?;
            let s = hermitshell_common::HermitSecrets::from_toml(&content)
                .with_context(|| format!("failed to parse secrets TOML: {}", sp.display()))?;
            Some(s)
        } else {
            None
        }
    } else {
        None
    };

    // Build the request with optional secrets
    let config_json = config.to_json()?;
    let mut req = serde_json::json!({
        "method": "apply_config",
        "value": config_json,
    });
    if let Some(ref s) = secrets {
        let secrets_json = serde_json::to_string(s).context("failed to serialize secrets")?;
        req["secrets"] = serde_json::Value::String(secrets_json);
    }

    let resp = socket_rpc(&cli.socket, &req)?;
    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        if secrets.is_some() {
            println!("Config and secrets applied successfully.");
        } else {
            println!("Config applied successfully.");
        }
    } else {
        let err = resp.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
        eprintln!("Apply failed: {}", err);
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_diff(cli: &Cli, config_path: &std::path::Path) -> Result<()> {
    let desired = load_config(config_path)?;

    let req = serde_json::json!({ "method": "get_full_config" });
    let resp = socket_rpc(&cli.socket, &req)?;
    let current_json = resp.get("config_value").and_then(|v| v.as_str()).unwrap_or("{}");
    let current: HermitConfig = serde_json::from_str(current_json)
        .context("failed to parse current config from agent")?;

    // Simple diff: compare serialized TOML
    let desired_toml = desired.to_toml().unwrap_or_default();
    let current_toml = current.to_toml().unwrap_or_default();

    if desired_toml == current_toml {
        println!("No changes.");
    } else {
        // Line-by-line diff
        let desired_lines: Vec<&str> = desired_toml.lines().collect();
        let current_lines: Vec<&str> = current_toml.lines().collect();
        for line in &current_lines {
            if !desired_lines.contains(line) {
                println!("- {}", line);
            }
        }
        for line in &desired_lines {
            if !current_lines.contains(line) {
                println!("+ {}", line);
            }
        }
    }
    Ok(())
}

fn cmd_export(cli: &Cli, _include_secrets: bool) -> Result<()> {
    let req = serde_json::json!({ "method": "get_full_config" });
    let resp = socket_rpc(&cli.socket, &req)?;
    let config_json = resp.get("config_value").and_then(|v| v.as_str()).unwrap_or("{}");
    let config: HermitConfig = serde_json::from_str(config_json)
        .context("failed to parse config from agent")?;
    let toml = config.to_toml().context("failed to serialize config as TOML")?;
    print!("{}", toml);
    Ok(())
}

fn cmd_validate(config_path: &std::path::Path) -> Result<()> {
    let config = load_config(config_path)?;
    let errors = config.validate();
    if errors.is_empty() {
        println!("Config is valid.");
    } else {
        eprintln!("Validation errors:");
        for e in &errors {
            eprintln!("  {}", e);
        }
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_status(cli: &Cli) -> Result<()> {
    let req = serde_json::json!({ "method": "get_status" });
    let resp = socket_rpc(&cli.socket, &req)?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Apply { config, secrets } => cmd_apply(&cli, config, secrets.as_deref()),
        Commands::Diff { config } => cmd_diff(&cli, config),
        Commands::Export { secrets } => cmd_export(&cli, *secrets),
        Commands::Validate { config } => cmd_validate(config),
        Commands::Status => cmd_status(&cli),
    }
}
