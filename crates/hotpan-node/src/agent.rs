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
            tracing::info!(node = %node_id.short(), ?trust, "promoted into fabric");
        }
        OrchMsg::Refused { reason } => return Err(AgentError::Refused(reason)),
        _ => return Err(AgentError::Handshake),
    }

    let node_id = id.node_id;
    let core = Arc::new(Mutex::new(NodeCore::new(id, welcome.orchestrator.clone(), cfg.settings.clone())));
    let (tx, mut rx) = mpsc::unbounded_channel::<NodeMsg>();
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
                if tx.send(NodeMsg::Heartbeat { vector: Box::new(v) }).is_err() {
                    break;
                }
            }
        }))
    };

    let mut workers = JoinSet::new();
    let end = loop {
        let msg = tokio::select! {
            m = rd.recv::<OrchMsg>() => m,
            Some(_) = workers.join_next(), if !workers.is_empty() => continue,
        };
        match msg {
            Ok(OrchMsg::Provision { lease, task }) => {
                let vector = probe.sample();
                let prepared = core.lock().unwrap().provision(lease, task, &vector, now_millis());
                let prep = match prepared {
                    Ok(p) => p,
                    Err(rejection) => {
                        let _ = tx.send(rejection.into());
                        continue;
                    }
                };
                let lease_id = prep.grant.lease_id;
                let _ = tx.send(NodeMsg::Accepted { lease_id });
                let _ = tx.send(NodeMsg::Executing { lease_id });
                let guard = core.lock().unwrap().guard_for(&prep, probe.clone());
                let policy = cfg.settings.policy.clone();
                let (core, tx) = (core.clone(), tx.clone());
                workers.spawn(async move {
                    let done = tokio::task::spawn_blocking(move || {
                        let report = prep.run(&policy, &|| guard.check());
                        (prep, report)
                    })
                    .await;
                    if let Ok((prep, report)) = done {
                        for m in core.lock().unwrap().complete(prep, report) {
                            let _ = tx.send(m);
                        }
                    }
                });
            }
            Ok(OrchMsg::Revoke { lease_id, reason }) => {
                tracing::info!(lease = %lease_id.short(), ?reason, "lease revoked");
                if let Some(m) = core.lock().unwrap().revoke(lease_id) {
                    let _ = tx.send(m);
                }
            }
            Ok(OrchMsg::Purge { lease_id }) => {
                if let Some(m) = core.lock().unwrap().purge(lease_id) {
                    let _ = tx.send(m);
                }
            }
            Ok(OrchMsg::Refused { reason }) => break Err(AgentError::Refused(reason)),
            Ok(OrchMsg::Registered { .. }) => {}
            Err(WireError::Closed) => break Ok(()),
            Err(e) => break Err(e.into()),
        }
    };

    // Dissolve: no control plane, no authority.
    core.lock().unwrap().abandon_all();
    drop(hb);
    drop(writer);
    let drain = async { while workers.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(10), drain).await;
    let completed = core.lock().unwrap().completed();
    end.map(|_| SessionEnd { node_id, orchestrator: welcome.orchestrator.signing, leases_completed: completed })
}
