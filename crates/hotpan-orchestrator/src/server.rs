//! TCP front end for [`ControlPlane`]. Nodes and clients both dial in; the
//! server never dials out, and nodes never need to accept connections.

use crate::{ControlPlane, Event, Outbound};
use hotpan_core::*;
use hotpan_seal::{verify_hello_proof, verify_pairing_proof, welcome_proof};
use hotpan_wire::*;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Fabric pairing secret. Peers proving it are `Paired`.
    pub pairing_secret: Option<String>,
    /// Refuse nodes and clients that cannot prove the pairing secret.
    pub require_pairing: bool,
    /// Append lifecycle events as JSON lines here.
    pub event_log: Option<std::path::PathBuf>,
}

type Peers = Arc<Mutex<HashMap<NodeId, mpsc::UnboundedSender<OrchMsg>>>>;

#[derive(Clone)]
pub struct Server {
    plane: Arc<Mutex<ControlPlane>>,
    peers: Peers,
    cfg: Arc<ServerConfig>,
    log: Arc<Mutex<Option<std::fs::File>>>,
    stop: watch::Sender<bool>,
}

impl Server {
    pub fn new(plane: ControlPlane, cfg: ServerConfig) -> std::io::Result<Self> {
        let log = match &cfg.event_log {
            Some(p) => Some(std::fs::OpenOptions::new().create(true).append(true).open(p)?),
            None => None,
        };
        Ok(Self {
            plane: Arc::new(Mutex::new(plane)),
            peers: Arc::default(),
            cfg: Arc::new(cfg),
            log: Arc::new(Mutex::new(log)),
            stop: watch::channel(false).0,
        })
    }

    pub fn plane(&self) -> Arc<Mutex<ControlPlane>> {
        self.plane.clone()
    }

    /// Stop accepting, and drop every live connection. Nodes treat this as
    /// the control plane vanishing: they cancel and purge everything.
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }

    /// Accept connections until [`Server::shutdown`], ticking the plane in the background.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let ticker = self.clone();
        let mut stop = self.stop.subscribe();
        let tick_task = tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(200));
            loop {
                iv.tick().await;
                ticker.pump(|p, now| {
                    let mut out = p.tick(now);
                    out.extend(p.schedule(now));
                    out
                });
            }
        });
        let result = loop {
            let (stream, addr) = tokio::select! {
                r = listener.accept() => match r {
                    Ok(x) => x,
                    Err(e) => break Err(e),
                },
                _ = stop.wait_for(|s| *s) => break Ok(()),
            };
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.connection(stream).await {
                    tracing::debug!(%addr, "connection ended: {e}");
                }
            });
        };
        tick_task.abort();
        result
    }

    /// Run `f` against the plane, then deliver what it produced.
    fn pump(&self, f: impl FnOnce(&mut ControlPlane, Millis) -> Vec<Outbound>) {
        let (out, events) = {
            let mut p = self.plane.lock().unwrap();
            let out = f(&mut p, now_millis());
            (out, p.drain_events())
        };
        self.deliver(out);
        self.record(events);
    }

    fn deliver(&self, out: Vec<Outbound>) {
        let peers = self.peers.lock().unwrap();
        for Outbound(node, msg) in out {
            if let Some(tx) = peers.get(&node) {
                let _ = tx.send(msg);
            }
        }
    }

    fn record(&self, events: Vec<Event>) {
        if events.is_empty() {
            return;
        }
        let mut log = self.log.lock().unwrap();
        for e in events {
            tracing::info!(target: "hotpan::event", "{}", serde_json::to_string(&e.kind).unwrap_or_default());
            if let Some(f) = log.as_mut() {
                let _ = writeln!(f, "{}", serde_json::to_string(&e).unwrap_or_default());
            }
        }
    }

    fn trust_for(&self, binding: &str, signing_key: &str, pairing: Option<&str>) -> Result<TrustLevel, String> {
        match (&self.cfg.pairing_secret, pairing) {
            (Some(secret), Some(proof)) if verify_pairing_proof(secret, binding, signing_key, proof) => {
                Ok(TrustLevel::Paired)
            }
            _ if self.cfg.require_pairing => Err("pairing required".into()),
            _ => Ok(TrustLevel::Unverified),
        }
    }

    async fn connection(&self, stream: TcpStream) -> Result<(), WireError> {
        stream.set_nodelay(true)?;
        let (rd, wr) = stream.into_split();
        let kex = self.plane.lock().unwrap().keys().kex_secret_bytes();
        let (mut rd, mut wr, session) = tokio::time::timeout(Duration::from_secs(10), respond(rd, wr, &kex))
            .await
            .map_err(|_| WireError::Closed)??;
        drop(kex);
        let binding = session.binding();
        let welcome = {
            let p = self.plane.lock().unwrap();
            Welcome {
                protocol: PROTOCOL_VERSION,
                orchestrator: p.public(),
                proof: welcome_proof(p.keys(), &binding),
                heartbeat_ms: p.config().heartbeat_ms,
            }
        };
        wr.send(&welcome).await?;
        let hello: Hello =
            tokio::time::timeout(Duration::from_secs(10), rd.recv()).await.map_err(|_| WireError::Closed)??;

        match hello {
            Hello::Node { protocol, advertisement, proof, pairing } => {
                let refuse = |reason: String| OrchMsg::Refused { reason };
                if protocol != PROTOCOL_VERSION {
                    return wr.send(&refuse(format!("protocol {protocol} unsupported"))).await;
                }
                if verify_hello_proof(&advertisement.signing_key, &binding, &proof).is_err() {
                    return wr.send(&refuse("bad session-key proof".into())).await;
                }
                // Envelopes are sealed to the advertised key; it must be the
                // key that is actually on the other end of this channel.
                if advertisement.kex_key != session.remote_static_hex() {
                    return wr.send(&refuse("advertised kex key does not match the channel".into())).await;
                }
                let trust = match self.trust_for(&binding, &advertisement.signing_key, pairing.as_deref()) {
                    Ok(t) => t,
                    Err(e) => return wr.send(&refuse(e)).await,
                };
                let node = advertisement.node_id;
                let registered = {
                    let mut p = self.plane.lock().unwrap();
                    p.register(*advertisement, trust, now_millis())
                };
                if let Err(e) = registered {
                    return wr.send(&refuse(e)).await;
                }
                wr.send(&OrchMsg::Registered { node_id: node, trust }).await?;

                let (tx, mut rx) = mpsc::unbounded_channel::<OrchMsg>();
                self.peers.lock().unwrap().insert(node, tx);
                let writer = tokio::spawn(async move {
                    while let Some(m) = rx.recv().await {
                        if wr.send(&m).await.is_err() {
                            break;
                        }
                    }
                });
                // Flush the join event and offer the new node work immediately.
                self.pump(|p, now| p.schedule(now));

                let mut stop = self.stop.subscribe();
                let result = loop {
                    let next = tokio::select! {
                        m = rd.recv::<NodeMsg>() => m,
                        _ = stop.wait_for(|s| *s) => Err(WireError::Closed),
                    };
                    match next {
                        Ok(NodeMsg::Withdraw) => {
                            self.pump(|p, now| p.handle(node, NodeMsg::Withdraw, now));
                            break Ok(());
                        }
                        Ok(msg) => self.pump(|p, now| {
                            let mut out = p.handle(node, msg, now);
                            out.extend(p.schedule(now));
                            out
                        }),
                        Err(e) => break Err(e),
                    }
                };
                self.peers.lock().unwrap().remove(&node);
                writer.abort();
                // Disconnect means the node is gone; no grace for transient nodes.
                self.pump(|p, now| {
                    p.node_gone(node, false, now);
                    p.schedule(now)
                });
                match result {
                    Err(WireError::Closed) => Ok(()),
                    other => other,
                }
            }
            Hello::Client { protocol, signing_key, proof, pairing } => {
                let reply = |m: String| ClientReply::Error { message: m };
                if protocol != PROTOCOL_VERSION {
                    return wr.send(&reply("protocol unsupported".into())).await;
                }
                if verify_hello_proof(&signing_key, &binding, &proof).is_err() {
                    return wr.send(&reply("bad session-key proof".into())).await;
                }
                if let Err(e) = self.trust_for(&binding, &signing_key, pairing.as_deref()) {
                    return wr.send(&reply(e)).await;
                }
                let mut stop = self.stop.subscribe();
                loop {
                    let next = tokio::select! {
                        m = rd.recv() => m,
                        _ = stop.wait_for(|s| *s) => Err(WireError::Closed),
                    };
                    let msg: ClientMsg = match next {
                        Ok(m) => m,
                        Err(WireError::Closed) => return Ok(()),
                        Err(e) => return Err(e),
                    };
                    let reply = match msg {
                        ClientMsg::Submit { job } => {
                            let mut id = None;
                            let mut err = None;
                            self.pump(|p, now| match p.submit(job, now) {
                                Ok(j) => {
                                    id = Some(j);
                                    p.schedule(now)
                                }
                                Err(e) => {
                                    err = Some(e.to_string());
                                    vec![]
                                }
                            });
                            match (id, err) {
                                (Some(job_id), _) => ClientReply::Submitted { job_id },
                                (_, e) => reply(e.unwrap_or_default()),
                            }
                        }
                        ClientMsg::Status { job_id } => match self.plane.lock().unwrap().job_report(job_id) {
                            Some(report) => ClientReply::Job { report },
                            None => reply("no such job".into()),
                        },
                        ClientMsg::Fleet => ClientReply::Fleet { nodes: self.plane.lock().unwrap().fleet() },
                    };
                    wr.send(&reply).await?;
                }
            }
        }
    }
}
