//! `hotpan` — Heuristically Orchestrated Transient Phone-as-Node.

#![forbid(unsafe_code)]

mod config;
mod sim;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hotpan_core::*;
use hotpan_heuristic::{plan, NodeView, PlanItem, Protection};
use hotpan_node::{run_session, AgentConfig, AgentError, Client, NodeSettings};
use hotpan_orchestrator::server::{Server, ServerConfig};
use hotpan_orchestrator::{ControlPlane, PlaneConfig};
use hotpan_probe::{Probe, SysProbe};
use hotpan_sandbox::{purge_stale, Policy};
use hotpan_seal::Keypair;
use hotpan_wire::{FleetEntry, FragmentState, JobReport, DEFAULT_PORT};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const SECRET_ENV: &str = "HOTPAN_PAIR_SECRET";

#[derive(Parser)]
#[command(
    name = "hotpan",
    version,
    about = "Promote devices into a transient compute fabric, exactly as long as work benefits."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an orchestrator keypair (owner-only file; never overwrites).
    Keygen {
        #[arg(long, default_value = "orchestrator.key")]
        out: PathBuf,
    },
    /// Run the control plane. Nodes and clients dial in; it never dials out.
    Orchestrate {
        #[arg(long, default_value_t = format!("0.0.0.0:{DEFAULT_PORT}"))]
        listen: String,
        #[arg(long, default_value = "orchestrator.key")]
        key: PathBuf,
        /// Append lifecycle events as JSON lines.
        #[arg(long)]
        events: Option<PathBuf>,
        /// Refuse peers that cannot prove the pairing secret (from $HOTPAN_PAIR_SECRET).
        #[arg(long)]
        require_pairing: bool,
        #[arg(long, default_value_t = 1000)]
        heartbeat_ms: u64,
    },
    /// Offer this device to a fabric as a transient node (outbound connection only).
    Node {
        #[arg(long)]
        connect: String,
        /// Expected orchestrator signing key (hex). Strongly recommended.
        #[arg(long)]
        pin: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        label: Option<String>,
        /// Rejoin after the control plane goes away (as a brand-new node).
        #[arg(long)]
        reconnect: bool,
    },
    /// Print what this device would advertise.
    Probe {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Submit a job (TOML or JSON) and optionally wait for it.
    Submit {
        job: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        pin: Option<String>,
        /// Persistent client key (from `hotpan keygen`); quotas are per identity.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Seconds to wait for completion (0 = return immediately).
        #[arg(long, default_value_t = 60)]
        wait: u64,
        #[arg(long)]
        json: bool,
    },
    /// Show a job's state.
    Status {
        job_id: JobId,
        #[arg(long)]
        to: String,
        #[arg(long)]
        pin: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List the nodes currently promoted into the fabric.
    Fleet {
        #[arg(long)]
        to: String,
        #[arg(long)]
        pin: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Explain how a job would be placed on a fleet (live or from `fleet --json`).
    Explain {
        job: PathBuf,
        #[arg(long, conflicts_with = "fleet")]
        to: Option<String>,
        #[arg(long)]
        fleet: Option<PathBuf>,
        #[arg(long)]
        pin: Option<String>,
    },
    /// Run the built-in "evening" scenario against the real control plane.
    Simulate,
}

fn secret() -> Option<String> {
    std::env::var(SECRET_ENV).ok().filter(|s| !s.is_empty())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let k = Keypair::generate();
            k.save(&out).with_context(|| format!("writing {}", out.display()))?;
            println!("wrote {}", out.display());
            println!("signing key (give to nodes as --pin): {}", k.public().signing);
        }
        Cmd::Orchestrate { listen, key, events, require_pairing, heartbeat_ms } => {
            let keys =
                Keypair::load(&key).with_context(|| format!("loading {} (run `hotpan keygen`)", key.display()))?;
            let pairing_secret = secret();
            if require_pairing && pairing_secret.is_none() {
                bail!("--require-pairing needs ${SECRET_ENV}");
            }
            let signing = keys.public().signing;
            let cfg = PlaneConfig { heartbeat_ms, node_timeout_ms: heartbeat_ms * 4, ..Default::default() };
            let server = Server::new(
                ControlPlane::new(keys, cfg),
                ServerConfig { pairing_secret, require_pairing, event_log: events, limits: Default::default() },
            )?;
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            tracing::info!(listen = %listener.local_addr()?, pin = %signing, "control plane up");
            let stopper = server.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("shutting down: dissolving every node's authority");
                stopper.shutdown();
            });
            server.serve(listener).await?;
        }
        Cmd::Node { connect, pin, config, label, reconnect } => {
            let file = config::load_node(config.as_deref())?;
            let workroot = file.workroot.clone().unwrap_or_else(config::default_workroot);
            let stale = purge_stale(&workroot);
            if stale > 0 {
                tracing::warn!(stale, "purged workspaces left by a previous session");
            }
            let probe: Arc<dyn Probe> = Arc::new(SysProbe::new(file.device.clone()));
            let label = label.or(file.label.clone()).unwrap_or_else(|| {
                std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_else(|_| "node".into())
            });
            let cfg = AgentConfig {
                addr: connect,
                settings: NodeSettings {
                    label,
                    policy: Policy {
                        allowed_programs: file.allowed_programs.clone(),
                        max: file.max.unwrap_or_default(),
                        workroot,
                    },
                    max_leases: file.max_leases.unwrap_or(1),
                    protection: file.protection.unwrap_or_default(),
                },
                pin,
                pairing_secret: secret(),
            };
            let mut backoff = Duration::from_secs(1);
            loop {
                let session = tokio::select! {
                    r = run_session(&cfg, probe.clone()) => r,
                    _ = tokio::signal::ctrl_c() => {
                        tracing::info!("leaving the fabric");
                        return Ok(());
                    }
                };
                match session {
                    Ok(end) => {
                        tracing::info!(node = %end.node_id.short(), completed = end.leases_completed, "session dissolved");
                        backoff = Duration::from_secs(1);
                    }
                    Err(e @ (AgentError::PinMismatch { .. } | AgentError::Refused(_) | AgentError::Protocol(_))) => {
                        return Err(e.into());
                    }
                    Err(e) => tracing::warn!("session ended: {e}"),
                }
                if !reconnect {
                    return Ok(());
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
        Cmd::Probe { config } => {
            let file = config::load_node(config.as_deref())?;
            let p = SysProbe::new(file.device);
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({ "device_class": p.device_class(), "vector": p.sample() })
                )?
            );
        }
        Cmd::Submit { job, to, pin, identity, wait, json } => {
            let spec = config::load_job(&job)?;
            let keys = match identity {
                Some(p) => Keypair::load(&p).with_context(|| format!("loading identity {}", p.display()))?,
                None => Keypair::generate(),
            };
            let mut c = Client::connect_as(&to, &keys, secret().as_deref(), pin.as_deref()).await?;
            let id = c.submit(spec).await?;
            if wait == 0 {
                println!("{id}");
                return Ok(());
            }
            eprintln!("submitted {id}; waiting up to {wait}s");
            let report = match c.wait(id, Duration::from_secs(wait)).await {
                Ok(r) => r,
                Err(hotpan_node::ClientError::Timeout) => c.status(id).await?,
                Err(e) => return Err(e.into()),
            };
            let fleet = c.fleet().await.unwrap_or_default();
            print_report(&report, &fleet, json)?;
            if !report.finished {
                bail!("job {id} still running");
            }
            if report.fragments.iter().any(|f| matches!(f.state, FragmentState::Failed { .. })) {
                std::process::exit(2);
            }
        }
        Cmd::Status { job_id, to, pin, json } => {
            let mut c = Client::connect(&to, secret().as_deref(), pin.as_deref()).await?;
            let report = c.status(job_id).await?;
            let fleet = c.fleet().await.unwrap_or_default();
            print_report(&report, &fleet, json)?;
        }
        Cmd::Fleet { to, pin, json } => {
            let mut c = Client::connect(&to, secret().as_deref(), pin.as_deref()).await?;
            let fleet = c.fleet().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&fleet)?);
            } else {
                print_fleet(&fleet);
            }
        }
        Cmd::Explain { job, to, fleet, pin } => {
            let spec = config::load_job(&job)?;
            let entries: Vec<FleetEntry> = match (to, fleet) {
                (Some(addr), _) => Client::connect(&addr, secret().as_deref(), pin.as_deref()).await?.fleet().await?,
                (None, Some(path)) => serde_json::from_str(&std::fs::read_to_string(path)?)?,
                (None, None) => bail!("give --to ADDR or --fleet FILE"),
            };
            explain(&spec, &entries);
        }
        Cmd::Simulate => {
            let dir = std::env::temp_dir().join(format!("hotpan-sim-{}", std::process::id()));
            let (s, job) = sim::evening(&dir);
            for l in &s.log {
                println!("{l}");
            }
            println!("\nplacement:");
            for l in s.report(job) {
                println!("{l}");
            }
            println!("\nlive leases after the run: {}", s.live_leases());
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    Ok(())
}

fn label_of(fleet: &[FleetEntry], n: NodeId) -> String {
    fleet.iter().find(|e| e.node_id == n).map(|e| e.label.clone()).unwrap_or_else(|| n.short())
}

fn print_report(r: &JobReport, fleet: &[FleetEntry], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(r)?);
        return Ok(());
    }
    println!("job {} `{}` — {}", r.job_id, r.name, if r.finished { "finished" } else { "running" });
    for f in &r.fragments {
        match &f.state {
            FragmentState::Done { node_id, result } => {
                println!(
                    "  ✓ {:<14} on {:<14} ({} attempt(s), {}ms)",
                    f.id,
                    label_of(fleet, *node_id),
                    f.attempts,
                    result.wall_ms
                );
                for line in result.stdout.lines().take(5) {
                    println!("      {line}");
                }
            }
            FragmentState::Failed { reason } => println!("  ✗ {:<14} {reason}", f.id),
            FragmentState::Leased { node_id, .. } => {
                println!("  … {:<14} leased to {}", f.id, label_of(fleet, *node_id))
            }
            FragmentState::Pending => println!("  ○ {:<14} pending; blocked by {:?}", f.id, f.blocked_by),
        }
    }
    Ok(())
}

fn print_fleet(fleet: &[FleetEntry]) {
    if fleet.is_empty() {
        println!("no nodes promoted");
    }
    for e in fleet {
        let v = &e.vector;
        let power = match v.power.battery_pct {
            None => "mains".to_string(),
            Some(p) => format!("{p:.0}%{}", if v.power.charging { "+" } else { "" }),
        };
        let caps: Vec<String> = v.capabilities.iter().map(|c| c.to_string()).collect();
        println!(
            "{:<14} {:<10?} {:<10?} leases {}/{}  power {:<6} thermal {:.2}  net {:?}  cpus {}  [{}]",
            e.label,
            e.device_class,
            e.trust,
            e.active_leases,
            e.max_leases,
            power,
            v.thermal_headroom,
            v.network.kind,
            v.compute.logical_cpus,
            caps.join(", ")
        );
    }
}

fn explain(spec: &JobSpec, fleet: &[FleetEntry]) {
    let p = Protection::default();
    let views: Vec<NodeView> = fleet
        .iter()
        .map(|e| NodeView {
            node_id: e.node_id,
            vector: e.vector.clone(),
            trust: e.trust,
            // `fleet` does not carry offers or allowlists; assume defaults and
            // say so, rather than inventing them.
            offer: ResourceCeiling::default(),
            allowed_programs: spec
                .fragments
                .iter()
                .filter_map(|f| match &f.task {
                    TaskSpec::Exec { program, .. } => Some(program.clone()),
                    _ => None,
                })
                .collect(),
            free_slots: e.max_leases.saturating_sub(e.active_leases),
        })
        .collect();
    println!("(explain assumes default node offers and that every node allows the job's programs)\n");
    for f in &spec.fragments {
        println!("{} [{:?}]", f.id, f.profile);
        let mut rows: Vec<_> = views.iter().map(|n| hotpan_heuristic::assess(f, n, &p)).collect();
        rows.sort_by(|a, b| b.score.total_cmp(&a.score));
        for a in rows {
            if a.eligible() {
                println!("    {:<14} {:.3}", label_of(fleet, a.node_id), a.score);
            } else {
                println!("    {:<14}   —   {:?}", label_of(fleet, a.node_id), a.gates);
            }
        }
    }
    let items: Vec<PlanItem<'_>> =
        spec.fragments.iter().map(|f| PlanItem { fragment: f, excluded: Default::default() }).collect();
    let placed = plan(&items, &views, &p);
    println!("\nplan:");
    for a in &placed.assignments {
        println!("    {:<14} → {} ({:.3})", a.fragment_id, label_of(fleet, a.node_id), a.score);
    }
    for u in &placed.unplaced {
        println!("    {:<14} → waits; blocked by {:?}", u.fragment_id, u.blocking);
    }
}
