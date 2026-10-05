//! TCP front end for [`ControlPlane`]. Nodes and clients both dial in; the
//! server never dials out, and nodes never need to accept connections.
//!
//! Everything a peer can make the server hold is bounded (DIRECTIVE P4):
//! live connections, concurrent handshakes, per-node outbound queues, idle
//! time, and (in the plane) nodes, jobs and fragment sizes. Overload is
//! answered by refusing new work, never by growing without limit.

use crate::{ControlPlane, Event, Outbound};
use hotpan_core::*;
use hotpan_seal::{verify_hello_proof, verify_pairing_proof, welcome_proof};
use hotpan_wire::*;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Notify, Semaphore};

#[derive(Clone, Debug)]
pub struct ServerLimits {
    /// Live TCP connections (nodes + clients + handshakes in progress).
    pub max_connections: usize,
    /// Connections allowed to be mid-handshake at once.
    pub max_handshakes: usize,
    /// Time allowed for the Noise handshake plus Welcome/Hello.
    pub handshake_timeout: Duration,
    /// A client connection with no request for this long is closed.
    pub client_idle_timeout: Duration,
    /// Messages queued for one node; a node that falls this far behind is evicted.
    pub outbound_queue: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_handshakes: 64,
            handshake_timeout: Duration::from_secs(10),
            client_idle_timeout: Duration::from_secs(120),
            outbound_queue: 256,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Fabric pairing secret. Peers proving it are `Paired`.
    pub pairing_secret: Option<String>,
    /// Refuse nodes and clients that cannot prove the pairing secret.
    pub require_pairing: bool,
    /// Append lifecycle events as JSON lines here.
    pub event_log: Option<std::path::PathBuf>,
    pub limits: ServerLimits,
}

/// Monotonic counters, exported for operations (Phase 2 metrics).
#[derive(Default, Debug)]
struct Counters {
    connections_live: AtomicU64,
    connections_accepted: AtomicU64,
    connections_refused: AtomicU64,
    handshakes_failed: AtomicU64,
    peers_evicted: AtomicU64,
    peers_refused: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ServerStats {
    pub connections_live: u64,
    pub connections_accepted: u64,
    pub connections_refused: u64,
    pub handshakes_failed: u64,
    pub peers_evicted: u64,
    pub peers_refused: u64,
}

struct Peer {
    tx: mpsc::Sender<OrchMsg>,
    /// Signalled to make the connection task drop the peer.
    kick: Arc<Notify>,
}

type Peers = Arc<Mutex<HashMap<NodeId, Peer>>>;

#[derive(Clone)]
pub struct Server {
    plane: Arc<Mutex<ControlPlane>>,
    peers: Peers,
    cfg: Arc<ServerConfig>,
    log: Arc<Mutex<Option<std::fs::File>>>,
    stop: watch::Sender<bool>,
    counters: Arc<Counters>,
    conn_slots: Arc<Semaphore>,
    handshake_slots: Arc<Semaphore>,
}

/// Decrements the live-connection gauge however the connection ends.
struct LiveGuard(Arc<Counters>);
impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.connections_live.fetch_sub(1, Ordering::Relaxed);
    }
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
            conn_slots: Arc::new(Semaphore::new(cfg.limits.max_connections)),
            handshake_slots: Arc::new(Semaphore::new(cfg.limits.max_handshakes)),
            cfg: Arc::new(cfg),
            log: Arc::new(Mutex::new(log)),
            stop: watch::channel(false).0,
            counters: Arc::default(),
        })
    }

    pub fn plane(&self) -> Arc<Mutex<ControlPlane>> {
        self.plane.clone()
    }

    pub fn stats(&self) -> ServerStats {
        let c = &self.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        ServerStats {
            connections_live: g(&c.connections_live),
            connections_accepted: g(&c.connections_accepted),
            connections_refused: g(&c.connections_refused),
            handshakes_failed: g(&c.handshakes_failed),
            peers_evicted: g(&c.peers_evicted),
            peers_refused: g(&c.peers_refused),
        }
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
        let heartbeat = Duration::from_millis(lock(&self.plane).config().heartbeat_ms.max(100));
        let tick_task = tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(200));
            let mut last_ping = tokio::time::Instant::now();
            let mut nonce = 0u64;
            loop {
                iv.tick().await;
                ticker.pump(|p, now| {
                    let mut out = p.tick(now);
                    out.extend(p.schedule(now));
                    out
                });
                if last_ping.elapsed() >= heartbeat {
                    last_ping = tokio::time::Instant::now();
                    nonce = nonce.wrapping_add(1);
                    ticker.ping_all(nonce);
                }
            }
        });
        let result = loop {
            let accepted = tokio::select! {
                r = listener.accept() => r,
                _ = stop.wait_for(|s| *s) => break Ok(()),
            };
            let (stream, addr) = match accepted {
                Ok(x) => x,
                Err(e) => {
                    // EMFILE and friends are transient: back off, keep serving.
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Ok(slot) = self.conn_slots.clone().try_acquire_owned() else {
                self.counters.connections_refused.fetch_add(1, Ordering::Relaxed);
                drop(stream);
                continue;
            };
            self.counters.connections_accepted.fetch_add(1, Ordering::Relaxed);
            self.counters.connections_live.fetch_add(1, Ordering::Relaxed);
            let me = self.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let _live = LiveGuard(me.counters.clone());
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
            let mut p = lock(&self.plane);
            let out = f(&mut p, now_millis());
            (out, p.drain_events())
        };
        self.deliver(out);
        self.record(events);
    }

    /// Queue messages for nodes. A node whose queue is full is too slow to
    /// keep up with the fabric and is evicted rather than buffered without bound.
    fn deliver(&self, out: Vec<Outbound>) {
        let mut evict = Vec::new();
        {
            let peers = lock(&self.peers);
            for Outbound(node, msg) in out {
                if let Some(p) = peers.get(&node) {
                    if let Err(mpsc::error::TrySendError::Full(_)) = p.tx.try_send(msg) {
                        evict.push(node);
                    }
                }
            }
        }
        self.evict(evict);
    }

    fn evict(&self, nodes: Vec<NodeId>) {
        if nodes.is_empty() {
            return;
        }
        let mut peers = lock(&self.peers);
        for n in nodes {
            if let Some(p) = peers.remove(&n) {
                tracing::warn!(node = %n.short(), "evicting slow peer");
                self.counters.peers_evicted.fetch_add(1, Ordering::Relaxed);
                p.kick.notify_one();
            }
        }
    }

    fn ping_all(&self, nonce: u64) {
        let out: Vec<Outbound> = lock(&self.peers).keys().map(|n| Outbound(*n, OrchMsg::Ping { nonce })).collect();
        self.deliver(out);
    }

    fn record(&self, events: Vec<Event>) {
        if events.is_empty() {
            return;
        }
        let mut log = lock(&self.log);
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
        // Handshakes are the expensive, unauthenticated part: cap them separately.
        let Ok(hs_slot) = self.handshake_slots.clone().try_acquire_owned() else {
            self.counters.connections_refused.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        let handshake = async {
            let (rd, wr) = stream.into_split();
            let kex = lock(&self.plane).keys().kex_secret_bytes();
            let (mut rd, mut wr, session) = respond(rd, wr, &kex).await?;
            drop(kex);
            let binding = session.binding();
            let welcome = {
                let p = lock(&self.plane);
                Welcome {
                    protocol: PROTOCOL_VERSION,
                    orchestrator: p.public(),
                    proof: welcome_proof(p.keys(), &binding),
                    heartbeat_ms: p.config().heartbeat_ms,
                }
            };
            wr.send(&welcome).await?;
            let hello: Hello = rd.recv().await?;
            Ok::<_, WireError>((rd, wr, session, binding, hello))
        };
        let (mut rd, mut wr, session, binding, hello) =
            match tokio::time::timeout(self.cfg.limits.handshake_timeout, handshake).await {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => {
                    self.counters.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
                Err(_) => {
                    self.counters.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                    return Err(WireError::Closed);
                }
            };
        drop(hs_slot);

        match hello {
            Hello::Node { protocol, advertisement, proof, pairing } => {
                let refuse = |reason: String| OrchMsg::Refused { reason };
                let refused = |me: &Self| me.counters.peers_refused.fetch_add(1, Ordering::Relaxed);
                if protocol != PROTOCOL_VERSION {
                    refused(self);
                    return wr.send(&refuse(format!("protocol {protocol} unsupported"))).await;
                }
                if verify_hello_proof(&advertisement.signing_key, &binding, &proof).is_err() {
                    refused(self);
                    return wr.send(&refuse("bad session-key proof".into())).await;
                }
                // Envelopes are sealed to the advertised key; it must be the
                // key that is actually on the other end of this channel.
                if advertisement.kex_key != session.remote_static_hex() {
                    refused(self);
                    return wr.send(&refuse("advertised kex key does not match the channel".into())).await;
                }
                let trust = match self.trust_for(&binding, &advertisement.signing_key, pairing.as_deref()) {
                    Ok(t) => t,
                    Err(e) => {
                        refused(self);
                        return wr.send(&refuse(e)).await;
                    }
                };
                let node = advertisement.node_id;
                let registered = lock(&self.plane).register(*advertisement, trust, now_millis());
                if let Err(e) = registered {
                    refused(self);
                    return wr.send(&refuse(e)).await;
                }
                wr.send(&OrchMsg::Registered { node_id: node, trust }).await?;
                // Registered nodes may return results up to the full frame size.
                rd.set_max_frame(MAX_FRAME);

                let (tx, mut rx) = mpsc::channel::<OrchMsg>(self.cfg.limits.outbound_queue.max(1));
                let kick = Arc::new(Notify::new());
                lock(&self.peers).insert(node, Peer { tx, kick: kick.clone() });
                let writer = tokio::spawn(async move {
                    while let Some(m) = rx.recv().await {
                        if wr.send(&m).await.is_err() {
                            break;
                        }
                    }
                });
                // Flush the join event and offer the new node work immediately.
                self.pump(|p, now| p.schedule(now));

                let idle = {
                    let p = lock(&self.plane);
                    Duration::from_millis(p.config().node_timeout_ms.max(p.config().heartbeat_ms * 2))
                };
                let mut stop = self.stop.subscribe();
                let result = loop {
                    let next = tokio::select! {
                        m = tokio::time::timeout(idle, rd.recv::<NodeMsg>()) => m.unwrap_or(Err(WireError::Closed)),
                        _ = stop.wait_for(|s| *s) => Err(WireError::Closed),
                        _ = kick.notified() => Err(WireError::Closed),
                    };
                    match next {
                        Ok(NodeMsg::Withdraw) => {
                            self.pump(|p, now| p.handle(node, NodeMsg::Withdraw, now));
                            break Ok(());
                        }
                        Ok(msg) => {
                            self.pump(|p, now| {
                                let mut out = p.handle(node, msg, now);
                                out.extend(p.schedule(now));
                                out
                            });
                            // The plane ejects misbehaving nodes; drop their connection too.
                            if !lock(&self.plane).is_registered(node) {
                                break Ok(());
                            }
                        }
                        Err(e) => break Err(e),
                    }
                };
                lock(&self.peers).remove(&node);
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
                    return wr.send(&reply(format!("protocol {protocol} unsupported"))).await;
                }
                if verify_hello_proof(&signing_key, &binding, &proof).is_err() {
                    return wr.send(&reply("bad session-key proof".into())).await;
                }
                if let Err(e) = self.trust_for(&binding, &signing_key, pairing.as_deref()) {
                    self.counters.peers_refused.fetch_add(1, Ordering::Relaxed);
                    return wr.send(&reply(e)).await;
                }
                rd.set_max_frame(CLIENT_FRAME);
                let mut stop = self.stop.subscribe();
                loop {
                    let next = tokio::select! {
                        m = tokio::time::timeout(self.cfg.limits.client_idle_timeout, rd.recv()) => {
                            m.unwrap_or(Err(WireError::Closed))
                        }
                        _ = stop.wait_for(|s| *s) => Err(WireError::Closed),
                    };
                    let msg: ClientMsg = match next {
                        Ok(m) => m,
                        Err(WireError::Closed) => return Ok(()),
                        Err(e) => return Err(e),
                    };
                    let reply = match msg {
                        ClientMsg::Submit { job } => {
                            let mut result = None;
                            // Quotas are keyed by the client's signing key.
                            self.pump(|p, now| match p.submit_as(job, &signing_key, now) {
                                Ok(j) => {
                                    result = Some(Ok(j));
                                    p.schedule(now)
                                }
                                Err(e) => {
                                    result = Some(Err(e.to_string()));
                                    vec![]
                                }
                            });
                            match result {
                                Some(Ok(job_id)) => ClientReply::Submitted { job_id },
                                Some(Err(e)) => reply(e),
                                None => reply("internal error".into()),
                            }
                        }
                        ClientMsg::Status { job_id } => match lock(&self.plane).job_report(job_id) {
                            Some(report) => ClientReply::Job { report },
                            None => reply("no such job".into()),
                        },
                        ClientMsg::Fleet => ClientReply::Fleet { nodes: lock(&self.plane).fleet() },
                    };
                    wr.send(&reply).await?;
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_test_peer(&self, node: NodeId, capacity: usize) -> (mpsc::Receiver<OrchMsg>, Arc<Notify>) {
        let (tx, rx) = mpsc::channel(capacity);
        let kick = Arc::new(Notify::new());
        lock(&self.peers).insert(node, Peer { tx, kick: kick.clone() });
        (rx, kick)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlaneConfig;
    use hotpan_seal::Keypair;

    #[tokio::test]
    async fn slow_peers_are_evicted_not_buffered() {
        let s = Server::new(ControlPlane::new(Keypair::generate(), PlaneConfig::default()), ServerConfig::default())
            .unwrap();
        let node = NodeId::random();
        let (_rx, kick) = s.insert_test_peer(node, 2);
        s.ping_all(1);
        s.ping_all(2);
        assert_eq!(s.stats().peers_evicted, 0);
        // The third message does not fit: the peer is evicted and kicked.
        s.ping_all(3);
        assert_eq!(s.stats().peers_evicted, 1);
        tokio::time::timeout(Duration::from_secs(1), kick.notified()).await.unwrap();
        assert!(lock(&s.peers).is_empty());
    }
}
