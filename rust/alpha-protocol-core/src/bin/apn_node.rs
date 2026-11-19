//! APN Node - Alpha Protocol Network node
//!
//! Usage:
//!   apn_node [run] [OPTIONS]        Run the node (default)
//!   apn_node identity show-phrase   Show the recovery phrase
//!   apn_node identity import        Replace the identity (phrase read from stdin)
//!
//! The recovery phrase is shown once, when the identity is created, and only
//! on an interactive terminal. It is never printed on a normal start.

use std::{
    env,
    io::{BufRead, IsTerminal, Write},
    time::Duration,
};

use alpha_protocol_core::{
    identity::NodeIdentity,
    identity_storage,
    heartbeat::{Capabilities, Hardware, Heartbeat, HEARTBEAT_INTERVAL_SECS},
    relay::{subjects, NatsRelay, RelayConfig, RelayEvent},
};
use tokio::sync::mpsc;

/// Options for `apn_node run`.
struct RunOptions {
    /// `--relay`; overrides `APN_RELAY_URL`
    relay_url: Option<String>,
    heartbeat_interval: u64,
    enable_heartbeat: bool,
    device_name: Option<String>,
    /// `--share-hardware` / `APN_SHARE_HARDWARE=1`: also send hostname and
    /// hardware details. Off by default.
    share_hardware: bool,
    capabilities: Capabilities,
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = env::args().collect();

    // Subcommands that only read or change local files: quiet logging, no network.
    match args.get(1).map(String::as_str) {
        Some("identity") => {
            init_logging("warn");
            return identity_command(&args[2..]);
        }
        Some("run") => {
            args.remove(1);
        }
        _ => {}
    }

    let mut opts = RunOptions {
        relay_url: None,
        heartbeat_interval: HEARTBEAT_INTERVAL_SECS,
        enable_heartbeat: true,
        device_name: env::var("APN_NODE_NAME").ok().filter(|s| !s.trim().is_empty()),
        share_hardware: env_flag("APN_SHARE_HARDWARE"),
        capabilities: Capabilities::ALL,
    };

    let value = |args: &[String], i: usize| -> anyhow::Result<String> {
        args.get(i + 1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{} requires a value", args[i]))
    };

    let mut ignored_p2p_flag = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" => {
                opts.relay_url = Some(value(&args, i)?);
                i += 2;
            }
            "--heartbeat-interval" => {
                opts.heartbeat_interval = value(&args, i)?.parse()?;
                anyhow::ensure!(
                    opts.heartbeat_interval >= 1,
                    "--heartbeat-interval must be at least 1"
                );
                i += 2;
            }
            "--no-heartbeat" => {
                opts.enable_heartbeat = false;
                i += 1;
            }
            "--name" => {
                opts.device_name = Some(value(&args, i)?);
                i += 2;
            }
            "--share-hardware" => {
                opts.share_hardware = true;
                i += 1;
            }
            "--capabilities" => {
                opts.capabilities =
                    Capabilities::parse_list(&value(&args, i)?).map_err(anyhow::Error::msg)?;
                i += 2;
            }
            // Peer-to-peer transport is not part of this build. Accept the old
            // flags so existing scripts keep working, and say so.
            "--port" | "--bootstrap" => {
                value(&args, i)?;
                ignored_p2p_flag = true;
                i += 2;
            }
            "--import" => {
                // A phrase on the command line ends up in shell history and in
                // the process list. Refuse it.
                anyhow::bail!(
                    "--import is no longer accepted. Run `apn_node identity import` and enter the phrase when asked."
                );
            }
            "--new" => {
                // Kept for old scripts: a new identity is only ever created
                // when none exists.
                i += 1;
            }
            "--version" | "-V" => {
                println!("apn_node {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                eprintln!("Unknown option: {}\n", other);
                print_help();
                std::process::exit(2);
            }
        }
    }

    init_logging("info,async_nats=warn");
    if ignored_p2p_flag {
        tracing::warn!(
            "--port/--bootstrap are ignored: this build has no peer-to-peer transport, \
             it talks to the relay only"
        );
    }

    run(opts).await
}

async fn run(opts: RunOptions) -> anyhow::Result<()> {
    // Load or create identity (with persistence)
    let (identity, identity_created) = identity_storage::load_or_create()?;
    if identity_created {
        announce_new_identity(&identity)?;
    }
    let node_id = identity.short_id();

    let mut relay_config = RelayConfig::from_env(&node_id)?;
    if let Some(url) = &opts.relay_url {
        relay_config.url = url.clone();
    }

    tracing::info!(
        "APN node {} v{} starting",
        node_id,
        env!("CARGO_PKG_VERSION")
    );

    let (relay_tx, mut relay_rx) = mpsc::unbounded_channel::<RelayEvent>();
    let mut relay = NatsRelay::new(relay_config, relay_tx);
    // Returns immediately; the connection comes up (and comes back) in the
    // background. A relay that is down does not stop the node from starting.
    relay.connect().await?;

    let mut ticker = tokio::time::interval(Duration::from_secs(opts.heartbeat_interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // the first tick fires at once; the connect event sends the first message

    let mut announced = false;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            Some(event) = relay_rx.recv() => {
                match event {
                    RelayEvent::Connected => {
                        // First connection: announce on apn.discovery.
                        // Later reconnects: send a heartbeat straight away.
                        let subject = if announced { subjects::HEARTBEAT } else { subjects::DISCOVERY };
                        match publish_presence(&relay, &identity, &opts, subject).await {
                            Ok(()) => {
                                announced = true;
                                ticker.reset();
                            }
                            Err(e) => tracing::warn!("Could not publish to {}: {:#}", subject, e),
                        }
                    }
                    RelayEvent::Disconnected | RelayEvent::Error(_) => {}
                    RelayEvent::MessageReceived { .. } => {}
                }
            }
            _ = ticker.tick(), if opts.enable_heartbeat => {
                if !relay.is_connected() {
                    tracing::debug!("Heartbeat skipped: relay not connected");
                    continue;
                }
                let subject = if announced { subjects::HEARTBEAT } else { subjects::DISCOVERY };
                match publish_presence(&relay, &identity, &opts, subject).await {
                    Ok(()) => announced = true,
                    Err(e) => tracing::warn!("Heartbeat failed: {:#}", e),
                }
            }
            _ = &mut shutdown => {
                tracing::info!("Shutting down");
                break;
            }
        }
    }

    let _ = relay.disconnect().await;
    Ok(())
}

/// Publish a signed heartbeat to `subject` and wait until the relay has it.
async fn publish_presence(
    relay: &NatsRelay,
    identity: &NodeIdentity,
    opts: &RunOptions,
    subject: &str,
) -> anyhow::Result<()> {
    // Hostname and hardware leave the machine only on explicit opt-in.
    let hardware = if opts.share_hardware {
        Some(Hardware {
            hostname: alpha_protocol_core::resources::get_hostname(),
            resources: alpha_protocol_core::resources::collect_resources().await.ok(),
        })
    } else {
        None
    };

    // The claim code is added in the next change; until then the hash is empty.
    let claim_hash = "";

    let heartbeat = Heartbeat::new_signed(
        identity,
        chrono::Utc::now().timestamp(),
        claim_hash,
        opts.capabilities,
        opts.device_name.clone(),
        hardware,
    );
    relay
        .publish(subject, &serde_json::to_vec(&heartbeat)?)
        .await?;
    relay.flush().await?;
    tracing::debug!("Published signed heartbeat to {}", subject);
    Ok(())
}

/// Resolves on Ctrl+C or SIGTERM (what systemd sends on stop).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("APN_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// Called exactly once per identity, right after it was created.
///
/// The phrase is shown only on an interactive terminal. When the node is
/// started by a service manager, stdout is a log, so the phrase is not
/// written there; the operator is pointed at `identity show-phrase` instead.
fn announce_new_identity(identity: &NodeIdentity) -> anyhow::Result<()> {
    if std::io::stdout().is_terminal() {
        println!();
        println!("A new node identity was created: {}", identity.short_id());
        println!();
        println!("RECOVERY PHRASE (shown only this once, write it down and keep it private):");
        println!();
        println!("    {}", identity.mnemonic_phrase());
        println!();
        println!("Anyone with this phrase can impersonate this node.");
        println!("To see it again later: apn_node identity show-phrase");
        println!();
    } else {
        tracing::info!(
            "New node identity {} created. The recovery phrase is not written to logs; \
             run `apn_node identity show-phrase` as the node's user to see it.",
            identity.short_id()
        );
    }
    Ok(())
}

fn identity_command(args: &[String]) -> anyhow::Result<()> {
    match args.first().map(String::as_str) {
        Some("show-phrase") => {
            let Some(identity) = identity_storage::load_identity()? else {
                anyhow::bail!(
                    "No identity found in {}. Start the node once to create one.",
                    identity_storage::get_config_dir()?.display()
                );
            };
            eprintln!("Node {}", identity.short_id());
            eprintln!("Recovery phrase (keep it private; anyone with it can impersonate this node):");
            println!("{}", identity.mnemonic_phrase());
            Ok(())
        }
        Some("import") => {
            let force = args.iter().any(|a| a == "--force");
            if identity_storage::load_identity()?.is_some() && !force {
                anyhow::bail!(
                    "An identity already exists. Re-run with `identity import --force` to replace it \
                     (the old identity file is kept as node_identity.json.backup)."
                );
            }
            if std::io::stdin().is_terminal() {
                eprint!("Enter the recovery phrase, then press Enter: ");
                std::io::stderr().flush().ok();
            }
            let mut phrase = String::new();
            std::io::stdin().lock().read_line(&mut phrase)?;
            let identity = NodeIdentity::from_mnemonic_phrase(phrase.trim())
                .map_err(|_| anyhow::anyhow!("That is not a valid recovery phrase."))?;
            identity_storage::save_identity(&identity)?;
            println!("Identity imported: {}", identity.short_id());
            Ok(())
        }
        _ => {
            eprintln!("Usage: apn_node identity <show-phrase|import [--force]>");
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("APN Node - Alpha Protocol Network node\n");
    println!("Usage:");
    println!("  apn_node [run] [OPTIONS]        Run the node (default)");
    println!("  apn_node identity show-phrase   Show the recovery phrase");
    println!("  apn_node identity import        Replace the identity (phrase read from stdin)\n");
    println!("Options for run:");
    println!("  --relay <URL>                Relay URL (overrides APN_RELAY_URL)");
    println!("  --heartbeat-interval <SECS>  Heartbeat interval in seconds (default: 30)");
    println!("  --name <NAME>                Display name for this node (also APN_NODE_NAME)");
    println!("  --capabilities <LIST>        relay,compute,storage (default: all three)");
    println!("  --share-hardware             Also send hostname and hardware details");
    println!("                               (off by default; also APN_SHARE_HARDWARE=1)");
    println!("  --no-heartbeat               Announce once, send no heartbeats");
    println!("  -V, --version                Show the version");
    println!("  -h, --help                   Show this help\n");
    println!("Environment:");
    println!("  APN_RELAY_URL       nats://host:4222 or tls://host:4222 (TLS)");
    println!("                      default: {}", alpha_protocol_core::DEFAULT_NATS_RELAY);
    println!("  APN_RELAY_USER      relay user name   (with APN_RELAY_PASSWORD)");
    println!("  APN_RELAY_PASSWORD  relay password");
    println!("  APN_RELAY_CREDS     path to a NATS .creds file (instead of user/password)");
    println!("  APN_RELAY_CA        optional PEM file with the relay's CA certificate");
    println!("  APN_DATA_DIR        where the identity is kept (default ~/.apn)");
    println!("  APN_LOG             log filter, e.g. debug\n");
    println!("Identity:");
    println!("  Stored in $APN_DATA_DIR (default ~/.apn), readable only by its owner.");
    println!("  The recovery phrase is shown once, when the identity is created.");
}
