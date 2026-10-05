use crate::core::{advertisement, NodeCore, NodeIdentity, NodeSettings};
use hotpan_core::*;
use hotpan_probe::Probe;
use hotpan_seal::{hello_proof, pairing_proof, verify_welcome_proof};
use hotpan_wire::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const OUTBOUND_QUEUE: usize = 256;

/// Background tasks die with the session, even if the session future itself
/// is dropped mid-flight (a node that is gone must stop heartbeating).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub addr: String,
    pub settings: NodeSettings,
    /// Expected orchestrator signing key (hex). Without it the first key seen
    /// is trusted for this session only.
    pub pin: Option<String>,
    pub pairing_secret: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("orchestrator key {got} does not match pinned key")]
    PinMismatch { got: String },
    #[error("orchestrator speaks protocol {0}")]
    Protocol(u32),
    #[error("refused by orchestrator: {0}")]
    Refused(String),
    #[error("unexpected message during handshake")]
    Handshake,
    #[error("orchestrator did not prove it terminates this channel")]
    ChannelBinding,
    #[error("control plane silent for {0:?}; treating it as gone")]
    Silent(Duration),
}

#[derive(Debug)]
pub struct SessionEnd {
    pub node_id: NodeId,
    pub orchestrator: String,
    pub leases_completed: u64,
}

/// One node session: connect out, advertise, serve leases until the control
/// plane goes away, then cancel and purge everything.
pub async fn run_session(cfg: &AgentConfig, probe: Arc<dyn Probe>) -> Result<SessionEnd, AgentError> {
    let id = NodeIdentity::fresh();
    let stream = TcpStream::connect(&cfg.addr).await?;
    stream.set_nodelay(true)?;
    let (rd, wr) = stream.into_split();
    let kex = id.keys.kex_secret_bytes();
    let (mut rd, mut wr, session) = tokio::time::timeout(Duration::from_secs(10), initiate(rd, wr, &kex))
        .await
        .map_err(|_| AgentError::Wire(WireError::Closed))??;
    drop(kex);
    let binding = session.binding();

    let welcome: Welcome = rd.recv().await?;
    if welcome.protocol != PROTOCOL_VERSION {
        return Err(AgentError::Protocol(welcome.protocol));
    }
    match &cfg.pin {
        Some(pin) if *pin != welcome.orchestrator.signing => {
            return Err(AgentError::PinMismatch { got: welcome.orchestrator.signing });
        }
        Some(_) => {}
        None => {
            tracing::warn!(key = %welcome.orchestrator.signing, "orchestrator key not pinned; trusting it for this session")
        }
    }
    // The orchestrator must be the far end of *this* channel, not a relay.
    if verify_welcome_proof(&welcome.orchestrator.signing, &binding, &welcome.proof).is_err()
        || welcome.orchestrator.kex != session.remote_static_hex()
    {
        return Err(AgentError::ChannelBinding);
    }

    let advert = advertisement(&id, &cfg.settings, probe.as_ref());
    let hello = Hello::Node {
        protocol: PROTOCOL_VERSION,
        proof: hello_proof(&id.keys, &binding),
        pairing: cfg.pairing_secret.as_ref().map(|s| pairing_proof(s, &binding, &advert.signing_key)),
        advertisement: Box::new(advert),
    };
    wr.send(&hello).await?;
    match rd.recv::<OrchMsg>().await? {
        OrchMsg::Registered { node_id, trust } => {
            rd.set_max_frame(MAX_FRAME);
            tracing::info!(node = %node_id.short(), ?trust, "promoted into fabric");
        }
        OrchMsg::Refused { reason } => return Err(AgentError::Refused(reason)),
        _ => return Err(AgentError::Handshake),
    }

    let node_id = id.node_id;
    let core = Arc::new(Mutex::new(NodeCore::new(id, welcome.orchestrator.clone(), cfg.settings.clone())));
    // Bounded: heartbeats are dropped when full (the next one supersedes
    // them); results and receipts wait for room.
    let (tx, mut rx) = mpsc::channel::<NodeMsg>(OUTBOUND_QUEUE);
    let writer = AbortOnDrop(tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if wr.send(&m).await.is_err() {
                break;
            }
        }
    }));
    let hb = {
        let (tx, probe) = (tx.clone(), probe.clone());
        let period = Duration::from_millis(welcome.heartbeat_ms.max(100));
        AbortOnDrop(tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let p = probe.clone();
                let Ok(v) = tokio::task::spawn_blocking(move || p.sample()).await else { break };
                if let Err(mpsc::error::TrySendError::Closed(_)) =
                    tx.try_send(NodeMsg::Heartbeat { vector: Box::new(v) })
                {
                    break;
                }
            }
        }))
    };

    // The control plane pings every heartbeat; several missed means it is
    // gone (or the connection is half-open), and so is our authority.
    let silence = Duration::from_millis(welcome.heartbeat_ms.max(100) * 4).max(Duration::from_secs(2));
    let mut workers = JoinSet::new();
    let end = loop {
        let msg = tokio::select! {
            m = tokio::time::timeout(silence, rd.recv::<OrchMsg>()) => match m {
                Ok(m) => m,
                Err(_) => break Err(AgentError::Silent(silence)),
            },
            Some(_) = workers.join_next(), if !workers.is_empty() => continue,
        };
        match msg {
            Ok(OrchMsg::Provision { lease, task }) => {
                let vector = probe.sample();
                let prepared = lock(&core).provision(lease, task, &vector, now_millis());
                let prep = match prepared {
                    Ok(p) => p,
                    Err(rejection) => {
                        let _ = tx.send(rejection.into()).await;
                        continue;
                    }
                };
                let lease_id = prep.grant.lease_id;
                let _ = tx.send(NodeMsg::Accepted { lease_id }).await;
                let _ = tx.send(NodeMsg::Executing { lease_id }).await;
                let guard = lock(&core).guard_for(&prep, probe.clone());
                let policy = cfg.settings.policy.clone();
                let (core, tx) = (core.clone(), tx.clone());
                workers.spawn(async move {
                    let done = tokio::task::spawn_blocking(move || {
                        let report = prep.run(&policy, &|| guard.check());
                        (prep, report)
                    })
                    .await;
                    if let Ok((prep, report)) = done {
                        let msgs = lock(&core).complete(prep, report);
                        for m in msgs {
                            let _ = tx.send(m).await;
                        }
                    }
                });
            }
            Ok(OrchMsg::Revoke { lease_id, reason }) => {
                tracing::info!(lease = %lease_id.short(), ?reason, "lease revoked");
                let m = lock(&core).revoke(lease_id);
                if let Some(m) = m {
                    let _ = tx.send(m).await;
                }
            }
            Ok(OrchMsg::Purge { lease_id }) => {
                let m = lock(&core).purge(lease_id);
                if let Some(m) = m {
                    let _ = tx.send(m).await;
                }
            }
            Ok(OrchMsg::Refused { reason }) => break Err(AgentError::Refused(reason)),
            Ok(OrchMsg::Ping { nonce }) => {
                let _ = tx.try_send(NodeMsg::Pong { nonce });
            }
            Ok(OrchMsg::Registered { .. }) => {}
            Err(WireError::Closed) => break Ok(()),
            Err(e) => break Err(e.into()),
        }
    };

    // Dissolve: no control plane, no authority.
    lock(&core).abandon_all();
    drop(hb);
    drop(writer);
    let drain = async { while workers.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(10), drain).await;
    let completed = lock(&core).completed();
    end.map(|_| SessionEnd { node_id, orchestrator: welcome.orchestrator.signing, leases_completed: completed })
}
