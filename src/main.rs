mod auth;
mod config;
mod error;
mod ntlm;
mod proxy;
mod server;
mod service;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

use crate::config::Config;

const LONG_ABOUT: &str = "\
A thin HTTP Basic/Digest-to-NTLM bridge.

Runs as a foreground process or a Windows service. Incoming requests authenticate
with Basic or configured Digest credentials. The bridge then performs an NTLMv2
handshake against the configured upstream and returns the upstream response.

Quick start with defaults (proxies to http://localhost:8080, listens on 127.0.0.1:3002):
    ntlm-bridge

Override individual settings on the command line:
    ntlm-bridge --bind 0.0.0.0:3002 --upstream-url http://intranet.local --domain EXAMPLE

Load a config.toml and still override specific fields:
    ntlm-bridge --config ./config.toml --bind 0.0.0.0:8080

Generate a starter config.toml:
    ntlm-bridge print-config --output config.toml
";

#[derive(Parser, Debug)]
#[command(
    name = "ntlm-bridge",
    version = env!("NTLM_BRIDGE_VERSION"),
    about = "HTTP Basic/Digest-to-NTLM bridge",
    long_about = LONG_ABOUT,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    #[command(flatten)]
    overrides: Overrides,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the server in the foreground (default when no subcommand given).
    Run,

    /// Run as a Windows service (invoked by the Service Control Manager).
    #[command(hide = true)]
    ServiceRun,

    /// Install as a Windows service set to auto-start.
    #[cfg(windows)]
    Install {
        /// Path to the config.toml the installed service should load.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },

    /// Uninstall the Windows service.
    #[cfg(windows)]
    Uninstall,

    /// Print a default config.toml. Writes to stdout unless --output is given.
    PrintConfig {
        /// Write the config directly to this path, using UTF-8 (no BOM).
        /// Bypasses PowerShell redirect encoding issues.
        #[arg(long, short, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

#[derive(Args, Debug, Clone, Default)]
struct Overrides {
    /// Path to config.toml. Overrides still apply on top of it.
    #[arg(
        long,
        short,
        value_name = "PATH",
        env = "NTLM_BRIDGE_CONFIG",
        global = true
    )]
    config: Option<PathBuf>,

    /// HTTP listen address. Default: 127.0.0.1:3002
    #[arg(long, value_name = "HOST:PORT", help_heading = "Server", global = true)]
    bind: Option<SocketAddr>,

    /// Overall HTTP request timeout in seconds.
    #[arg(long, value_name = "SECS", help_heading = "Server", global = true)]
    request_timeout: Option<u64>,

    /// Max incoming request body size in bytes.
    #[arg(long, value_name = "BYTES", help_heading = "Server", global = true)]
    max_body_bytes: Option<usize>,

    /// Base URL for the NTLM-protected upstream.
    #[arg(long, value_name = "URL", help_heading = "Upstream", global = true)]
    upstream_url: Option<String>,

    /// Default NTLM domain for Basic users that do not include DOMAIN\user.
    #[arg(long, value_name = "DOMAIN", help_heading = "Upstream", global = true)]
    domain: Option<String>,

    /// Workstation name sent in NTLM authenticate messages.
    #[arg(long, value_name = "NAME", help_heading = "Upstream", global = true)]
    workstation: Option<String>,

    /// Upstream connect timeout in seconds.
    #[arg(long, value_name = "SECS", help_heading = "Upstream", global = true)]
    connect_timeout: Option<u64>,

    /// Accept invalid upstream TLS certificates.
    #[arg(long, action = ArgAction::SetTrue, help_heading = "Upstream", global = true)]
    accept_invalid_certs: bool,

    /// Basic/Digest realm advertised by the bridge.
    #[arg(long, value_name = "REALM", help_heading = "Auth", global = true)]
    auth_realm: Option<String>,

    /// Log level: trace | debug | info | warn | error
    #[arg(long, value_name = "LEVEL", help_heading = "Logging", global = true)]
    log_level: Option<String>,

    /// Log method, target URL, and status.
    #[arg(long, action = ArgAction::SetTrue, help_heading = "Logging", global = true)]
    log_requests: bool,
}

fn build_config(overrides: &Overrides) -> anyhow::Result<Config> {
    let mut cfg = match &overrides.config {
        Some(p) => Config::load(p)?,
        None => Config::load_default_locations()?,
    };

    if let Some(v) = overrides.bind {
        cfg.server.bind = v;
    }
    if let Some(v) = overrides.request_timeout {
        cfg.server.request_timeout_secs = v;
    }
    if let Some(v) = overrides.max_body_bytes {
        cfg.server.max_body_bytes = v;
    }

    if let Some(v) = &overrides.upstream_url {
        cfg.upstream.base_url = v.clone();
    }
    if let Some(v) = &overrides.domain {
        cfg.upstream.domain = v.clone();
    }
    if let Some(v) = &overrides.workstation {
        cfg.upstream.workstation = v.clone();
    }
    if let Some(v) = overrides.connect_timeout {
        cfg.upstream.connect_timeout_secs = v;
    }
    if overrides.accept_invalid_certs {
        cfg.upstream.accept_invalid_certs = true;
    }

    if let Some(v) = &overrides.auth_realm {
        cfg.auth.realm = v.clone();
    }

    if let Some(v) = &overrides.log_level {
        cfg.log.level = v.clone();
    }
    if overrides.log_requests {
        cfg.log.log_requests = true;
    }

    cfg.validate()?;
    Ok(cfg)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cmd = cli.cmd.unwrap_or(Cmd::Run);

    match cmd {
        Cmd::Run => {
            let cfg = build_config(&cli.overrides)?;
            run_foreground(cfg)
        }

        Cmd::ServiceRun => {
            if let Some(path) = &cli.overrides.config {
                std::env::set_var("NTLM_BRIDGE_CONFIG", path);
            }
            #[cfg(windows)]
            {
                service::windows::dispatch()
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!("service-run is only available on Windows")
            }
        }

        #[cfg(windows)]
        Cmd::Install { config } => {
            let exe = std::env::current_exe()?;
            service::windows::install(exe, config)?;
            println!("Installed Windows service 'ntlm-bridge'.");
            println!("Start with: sc.exe start ntlm-bridge");
            Ok(())
        }

        #[cfg(windows)]
        Cmd::Uninstall => {
            service::windows::uninstall()?;
            println!("Uninstalled Windows service 'ntlm-bridge'.");
            Ok(())
        }

        Cmd::PrintConfig { output } => {
            let c = Config::default();
            let s = toml::to_string_pretty(&c)?;
            match output {
                Some(path) => {
                    std::fs::write(&path, s.as_bytes())?;
                    println!("wrote {}", path.display());
                }
                None => print!("{s}"),
            }
            Ok(())
        }
    }
}

fn run_foreground(cfg: Config) -> anyhow::Result<()> {
    server::init_logging(&cfg.log.level)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let state = server::AppState::from_config(cfg)?;
        server::serve(state, server::ctrl_c_shutdown()).await
    })
}
