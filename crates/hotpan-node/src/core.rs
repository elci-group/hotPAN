use hotpan_core::*;
use hotpan_heuristic::{protection_gates, Protection};
use hotpan_probe::Probe;
use hotpan_sandbox::{execute, ExecReport, Policy, Workspace};
use hotpan_seal::{
    attest, open, seal, task_permitted, Envelope, Keypair, LeaseGrant, PublicKeys, RevocationList, SignedLease,
};
use hotpan_wire::{NodeMsg, ResultPayload};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A node's identity for one session only.
pub struct NodeIdentity {
    pub node_id: NodeId,
    pub keys: Keypair,
}

impl NodeIdentity {
    pub fn fresh() -> Self {
        Self { node_id: NodeId::random(), keys: Keypair::generate() }
    }
}

#[derive(Clone, Debug)]
pub struct NodeSettings {
    pub label: String,
    pub policy: Policy,
    pub max_leases: u32,
    pub protection: Protection,
}

pub fn advertisement(id: &NodeIdentity, s: &NodeSettings, probe: &dyn Probe) -> Advertisement {
    let pk = id.keys.public();
    Advertisement {
        node_id: id.node_id,
        label: s.label.clone(),
        device_class: probe.device_class(),
        vector: probe.sample(),
        signing_key: pk.signing,
        kex_key: pk.kex,
        offer: s.policy.max,
        max_leases: s.max_leases,
        allowed_programs: s.policy.allowed_programs.clone(),
    }
}

/// Why a lease was refused; becomes [`NodeMsg::Rejected`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub lease_id: LeaseId,
    pub reason: String,
}

impl From<Rejection> for NodeMsg {
    fn from(r: Rejection) -> Self {
        NodeMsg::Rejected { lease_id: r.lease_id, reason: r.reason }
    }
}

/// A verified, decrypted lease ready to execute.
pub struct Prepared {
    pub grant: LeaseGrant,
    pub task: TaskSpec,
    pub workspace: Workspace,
    pub cancel: Arc<AtomicBool>,
}

impl Prepared {
    /// Run the task. Blocking; call from a worker thread.
    pub fn run(&self, policy: &Policy, guard: &(dyn Fn() -> Option<String> + Sync)) -> ExecReport {
        execute(policy, &self.workspace, &self.task, &self.grant.ceiling, &self.grant.scopes, guard)
    }
}

struct Held {
    cancel: Arc<AtomicBool>,
    /// `None` while the workspace is out on a worker thread.
    workspace: Option<Workspace>,
    expires_at: Millis,
}

/// Node-side lease bookkeeping, independent of transport.
pub struct NodeCore {
    pub id: NodeIdentity,
    orch: PublicKeys,
    settings: NodeSettings,
    revoked: RevocationList,
    held: HashMap<LeaseId, Held>,
    completed: u64,
}

impl NodeCore {
    pub fn new(id: NodeIdentity, orch: PublicKeys, settings: NodeSettings) -> Self {
        Self { id, orch, settings, revoked: RevocationList::default(), held: HashMap::new(), completed: 0 }
    }

    pub fn settings(&self) -> &NodeSettings {
        &self.settings
    }

    pub fn active(&self) -> usize {
        self.held.len()
    }

    pub fn completed(&self) -> u64 {
        self.completed
    }

    /// Verify and accept a lease, or produce the rejection to send back.
    pub fn provision(
        &mut self,
        lease: SignedLease,
        task: Envelope,
        vector: &CapabilityVector,
        now: Millis,
    ) -> Result<Prepared, Rejection> {
        let lease_id = lease.grant.lease_id;
        let reject = |reason: String| Rejection { lease_id, reason };
        lease.verify(&self.orch.signing, self.id.node_id, now).map_err(|e| reject(e.to_string()))?;
        if self.revoked.is_revoked(&lease_id) || self.held.contains_key(&lease_id) {
            return Err(reject("lease already seen".into()));
        }
        if self.held.len() as u32 >= self.settings.max_leases {
            return Err(reject("no free lease slot".into()));
        }
        let g = lease.grant;
        if !g.ceiling.fits_within(&self.settings.policy.max) {
            return Err(reject("ceiling exceeds what this node offers".into()));
        }
        let gates = protection_gates(g.profile, vector, &self.settings.protection);
        if !gates.is_empty() {
            return Err(reject(format!("device protection: {gates:?}")));
        }
        let plain = open(&self.id.keys, &task, lease_id.0.as_bytes()).map_err(|e| reject(e.to_string()))?;
        let task: TaskSpec = serde_json::from_slice(&plain).map_err(|e| reject(format!("task decode: {e}")))?;
        task_permitted(&task, &g.scopes).map_err(reject)?;
        if let TaskSpec::Exec { program, .. } = &task {
            if !self.settings.policy.allowed_programs.contains(program) {
                return Err(reject(format!("{program} not in local allowlist")));
            }
        }
        let workspace = Workspace::create(&self.settings.policy.workroot, lease_id)
            .map_err(|e| reject(format!("workspace: {e}")))?;
        let cancel = Arc::new(AtomicBool::new(false));
        self.held.insert(lease_id, Held { cancel: cancel.clone(), workspace: None, expires_at: g.expires_at });
        Ok(Prepared { grant: g, task, workspace, cancel })
    }

    /// Package an execution report. If the lease was revoked while running,
    /// authority is gone: nothing is returned, the workspace is purged, and
    /// the purge receipt is reported instead.
    pub fn complete(&mut self, prep: Prepared, report: ExecReport) -> Vec<NodeMsg> {
        let lease_id = prep.grant.lease_id;
        let Some(held) = self.held.get_mut(&lease_id) else {
            // Abandoned (session ended): dropping the workspace purges it.
            return vec![];
        };
        if prep.cancel.load(Ordering::SeqCst) && self.revoked.is_revoked(&lease_id) {
            self.held.remove(&lease_id);
            return prep.workspace.purge().map(|receipt| vec![NodeMsg::Purged { receipt }]).unwrap_or_default();
        }
        held.workspace = Some(prep.workspace);
        self.completed += 1;
        let payload = ResultPayload {
            lease_id,
            fragment_id: prep.grant.fragment_id.clone(),
            outcome: report.outcome,
            stdout: report.stdout,
            stderr: report.stderr,
            truncated: report.truncated,
            wall_ms: report.wall_ms,
        };
        #[allow(clippy::expect_used)] // plain struct of strings and integers: cannot fail
        let plain = serde_json::to_vec(&payload).expect("payload serializes");
        let attestation = attest(&self.id.keys, lease_id, &prep.grant.fragment_id, self.id.node_id, &plain);
        match seal(&self.orch.kex, lease_id.0.as_bytes(), &plain) {
            Ok(envelope) => vec![NodeMsg::Result { lease_id, envelope, attestation }],
            Err(e) => {
                tracing::error!("cannot seal result: {e}");
                self.purge(lease_id).into_iter().collect()
            }
        }
    }

    /// End of lease: purge the workspace and report the receipt.
    pub fn purge(&mut self, lease_id: LeaseId) -> Option<NodeMsg> {
        let held = self.held.get_mut(&lease_id)?;
        // Still executing: revoke instead, the worker will purge on return.
        let ws = held.workspace.take()?;
        self.held.remove(&lease_id);
        ws.purge().ok().map(|receipt| NodeMsg::Purged { receipt })
    }

    pub fn revoke(&mut self, lease_id: LeaseId) -> Option<NodeMsg> {
        let held = self.held.get(&lease_id)?;
        held.cancel.store(true, Ordering::SeqCst);
        self.revoked.revoke(lease_id, held.expires_at);
        self.purge(lease_id)
    }

    /// The control plane is gone: cancel and purge everything.
    pub fn abandon_all(&mut self) {
        for (id, held) in self.held.drain() {
            held.cancel.store(true, Ordering::SeqCst);
            self.revoked.revoke(id, held.expires_at);
            if let Some(ws) = held.workspace {
                let _ = ws.purge();
            }
        }
    }

    /// The guard a worker polls while executing `prep`.
    pub fn guard_for(&self, prep: &Prepared, probe: Arc<dyn Probe>) -> ProtectionGuard {
        ProtectionGuard {
            probe,
            protection: self.settings.protection,
            profile: prep.grant.profile,
            cancel: prep.cancel.clone(),
            expires_at: prep.grant.expires_at,
            cache: Mutex::new(None),
        }
    }
}

/// Stops work when the lease is revoked or expires, or when the device's own
/// battery/thermal state crosses the protection line for this profile.
pub struct ProtectionGuard {
    probe: Arc<dyn Probe>,
    protection: Protection,
    profile: WorkloadProfile,
    cancel: Arc<AtomicBool>,
    expires_at: Millis,
    cache: Mutex<Option<(Instant, Option<String>)>>,
}

const RESAMPLE: Duration = Duration::from_millis(250);

impl ProtectionGuard {
    pub fn check(&self) -> Option<String> {
        if self.cancel.load(Ordering::SeqCst) {
            return Some("lease revoked".into());
        }
        if now_millis() >= self.expires_at {
            return Some("lease expired".into());
        }
        let mut cache = hotpan_core::lock(&self.cache);
        if let Some((at, verdict)) = cache.as_ref() {
            if at.elapsed() < RESAMPLE {
                return verdict.clone();
            }
        }
        let gates = protection_gates(self.profile, &self.probe.sample(), &self.protection);
        let verdict = (!gates.is_empty()).then(|| format!("device protection: {gates:?}"));
        *cache = Some((Instant::now(), verdict.clone()));
        verdict
    }
}
