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
};

use alpha_protocol_core::{
    identity::NodeIdentity,
    identity_storage,
    node::{AlphaNodeBuilder, NodeEvent},
    DEFAULT_NATS_RELAY,
};
use tokio::sync::mpsc;

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

    init_logging("info");

    let mut port: u16 = 4001;
    let mut relay_url = DEFAULT_NATS_RELAY.to_string();
    let mut bootstrap_peers: Vec<String> = vec![];
    let mut heartbeat_interval: u64 = 30; // seconds
    let mut enable_heartbeat = true;
    let mut device_name: Option<String> = None;

    // Parse args
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                port = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--port requires a value"))?
                    .parse()?;
                i += 2;
            }
            "--relay" => {
                relay_url = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--relay requires a value"))?
                    .clone();
                i += 2;
            }
            "--bootstrap" => {
                let peer = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--bootstrap requires a value"))?
                    .clone();
                bootstrap_peers.push(peer);
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
            "--heartbeat-interval" => {
                heartbeat_interval = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--heartbeat-interval requires a value"))?
                    .parse()?;
                i += 2;
            }
            "--no-heartbeat" => {
                enable_heartbeat = false;
                i += 1;
            }
            "--name" => {
                device_name = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--name requires a value"))?
                        .clone(),
                );
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                print_help();
                return Ok(());
            }
        }
    }

    // Create event channel
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<NodeEvent>();

    // Load or create identity (with persistence)
    let (identity, identity_created) = identity_storage::load_or_create()?;
    if identity_created {
        announce_new_identity(&identity)?;
    }

    // Build the node with persistent identity
    let mut builder = AlphaNodeBuilder::new()
        .with_port(port)
        .with_relay(&relay_url)
        .with_bootstrap_peers(bootstrap_peers)
        .with_capabilities(vec![
            "compute".to_string(),
            "relay".to_string(),
            "storage".to_string(),
        ])
        .with_identity(identity);

    if let Some(ref name) = device_name {
        builder = builder.with_device_name(name);
    }

    let mut node = builder.build(event_tx)?;

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║              ALPHA PROTOCOL NETWORK - Node                       ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    if let Some(ref name) = device_name {
        println!("║  Name:     {:<53}║", name);
    }
    println!("║  Node ID:  {:<53}║", node.short_id());
    println!("║  Address:  {:<53}║", node.address());
    println!("║  P2P Port: {:<53}║", port);
    println!("║  Relay:    {:<53}║", relay_url);
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Start the node
    println!("🚀 Starting node...");
    node.start().await?;
    println!("✅ Node started!\n");

    // Announce to the network (may fail if no peers yet, that's OK)
    println!("📢 Announcing to network...");
    match node.announce().await {
        Ok(_) => println!("✅ Announced!\n"),
        Err(e) => println!("⚠️  Announce pending (no peers yet): {}\n", e),
    }

    // Setup heartbeat interval
    let mut heartbeat_timer = if enable_heartbeat {
        println!("💓 Heartbeat enabled (interval: {}s)\n", heartbeat_interval);
        Some(tokio::time::interval(std::time::Duration::from_secs(
            heartbeat_interval,
        )))
    } else {
        None
    };

    println!("👂 Listening for events... (Ctrl+C to quit)\n");

    // Event loop
    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    NodeEvent::Started { peer_id, address } => {
                        println!("🟢 Node started: {} @ {}", peer_id, address);
                    }
                    NodeEvent::PeerConnected(peer) => {
                        println!("🔗 Peer connected: {} ({} capabilities)",
                            peer.peer_id,
                            peer.capabilities.len()
                        );
                        if let Some(addr) = peer.wallet_address {
                            println!("   Wallet: {}", addr);
                        }
                        for cap in &peer.capabilities {
                            println!("   - {}", cap);
                        }
                    }
                    NodeEvent::PeerDisconnected(peer_id) => {
                        println!("🔴 Peer disconnected: {}", peer_id);
                    }
                    NodeEvent::MessageReceived { from, message } => {
                        println!("📨 Message from {}: {:?}", from, message);
                    }
                    NodeEvent::RelayConnected => {
                        println!("🌐 Relay connected");
                    }
                    NodeEvent::RelayDisconnected => {
                        println!("⚠️  Relay disconnected");
                    }
                    NodeEvent::Error(e) => {
                        eprintln!("❌ Error: {}", e);
                    }
                }
            }
            Some(_) = async {
                if let Some(ref mut timer) = heartbeat_timer {
                    Some(timer.tick().await)
                } else {
                    None
                }
            } => {
                // Send heartbeat
                tracing::debug!("Sending heartbeat...");
                if let Err(e) = node.send_heartbeat().await {
                    tracing::error!("Heartbeat failed: {}", e);
                } else {
                    tracing::debug!("Heartbeat sent successfully");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n👋 Shutting down...");
                break;
            }
        }
    }

    Ok(())
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
    println!("  --port <PORT>       P2P port (default: 4001)");
    println!("  --relay <URL>       NATS relay URL (default: nats://nonlocal.info:4222)");
    println!("  --bootstrap <ADDR>  Bootstrap peer multiaddr (can be used multiple times)");
    println!("  --heartbeat-interval <SECS>  Heartbeat interval in seconds (default: 30)");
    println!("  --name <NAME>       Display name for this node (e.g. \"Sirak Studios\")");
    println!("  --no-heartbeat      Disable heartbeat broadcasts");
    println!("  -h, --help          Show this help\n");
    println!("Identity:");
    println!("  Stored in $APN_DATA_DIR (default ~/.apn), readable only by its owner.");
    println!("  The recovery phrase is shown once, when the identity is created.");
}
