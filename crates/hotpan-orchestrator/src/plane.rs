use hotpan_core::*;
use hotpan_heuristic::{plan, Gate, NodeView, PlanItem, Protection};
use hotpan_seal::{open, scopes_for, seal, Keypair, LeaseGrant, PublicKeys, RevocationList, SignedLease};
use hotpan_wire::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct PlaneConfig {
    pub heartbeat_ms: u64,
    /// A node silent for this long is considered lost.
    pub node_timeout_ms: u64,
    /// Added to a fragment's wall ceiling to get its lease expiry.
    pub lease_slack_ms: u64,
    /// After expiry, how long to wait for a purge receipt before dissolving.
    pub purge_grace_ms: u64,
    pub protection: Protection,
}

impl Default for PlaneConfig {
    fn default() -> Self {
        Self {
            heartbeat_ms: 1_000,
            node_timeout_ms: 4_000,
            lease_slack_ms: 10_000,
            purge_grace_ms: 10_000,
            protection: Protection::default(),
        }
    }
}

/// A message the plane wants delivered to a node.
#[derive(Clone, Debug)]
pub struct Outbound(pub NodeId, pub OrchMsg);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub at: Millis,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum EventKind {
    NodeJoined {
        node: NodeId,
        label: String,
        class: DeviceClass,
        trust: TrustLevel,
    },
    NodeLost {
        node: NodeId,
        label: String,
    },
    NodeWithdrew {
        node: NodeId,
        label: String,
    },
    JobSubmitted {
        job: JobId,
        name: String,
        fragments: usize,
    },
    Lease {
        lease: LeaseId,
        job: JobId,
        fragment: String,
        node: NodeId,
        phase: Phase,
        score: Option<f32>,
        reason: Option<RevokeReason>,
    },
    FragmentDone {
        job: JobId,
        fragment: String,
        node: NodeId,
    },
    FragmentFailed {
        job: JobId,
        fragment: String,
        reason: String,
    },
    JobFinished {
        job: JobId,
        name: String,
        ok: bool,
    },
    BadMessage {
        node: NodeId,
        detail: String,
    },
}

struct NodeEntry {
    advert: Advertisement,
    trust: TrustLevel,
    last_seen: Millis,
    /// Leases that still occupy a slot (not yet dissolved).
    active: BTreeSet<LeaseId>,
}

struct FragState {
    attempts: u32,
    state: FragmentState,
    excluded: BTreeSet<NodeId>,
    blocked_by: Vec<Gate>,
}

struct Job {
    spec: JobSpec,
    fragments: Vec<FragState>,
    finished: bool,
}

struct LeaseRecord {
    signed: SignedLease,
    job: JobId,
    frag: usize,
    node: NodeId,
    lifecycle: Lifecycle,
}

pub struct ControlPlane {
    keys: Keypair,
    cfg: PlaneConfig,
    nodes: BTreeMap<NodeId, NodeEntry>,
    jobs: BTreeMap<JobId, Job>,
    job_order: Vec<JobId>,
    leases: BTreeMap<LeaseId, LeaseRecord>,
    revoked: RevocationList,
    events: Vec<Event>,
}

impl ControlPlane {
    pub fn new(keys: Keypair, cfg: PlaneConfig) -> Self {
        Self {
            keys,
            cfg,
            nodes: BTreeMap::new(),
            jobs: BTreeMap::new(),
            job_order: Vec::new(),
            leases: BTreeMap::new(),
            revoked: RevocationList::default(),
            events: Vec::new(),
        }
    }

    pub fn public(&self) -> PublicKeys {
        self.keys.public()
    }

    pub fn keys(&self) -> &Keypair {
        &self.keys
    }

    pub fn config(&self) -> &PlaneConfig {
        &self.cfg
    }

    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    fn emit(&mut self, at: Millis, kind: EventKind) {
        self.events.push(Event { at, kind });
    }

    // ---------------------------------------------------------------- nodes

    pub fn register(&mut self, advert: Advertisement, trust: TrustLevel, now: Millis) -> Result<NodeId, String> {
        let id = advert.node_id;
        if self.nodes.contains_key(&id) {
            return Err("node id already registered".into());
        }
        if advert.max_leases == 0 {
            return Err("node offers zero lease slots".into());
        }
        self.emit(
            now,
            EventKind::NodeJoined { node: id, label: advert.label.clone(), class: advert.device_class, trust },
        );
        self.nodes.insert(id, NodeEntry { advert, trust, last_seen: now, active: BTreeSet::new() });
        Ok(id)
    }

    pub fn heartbeat(&mut self, node: NodeId, vector: CapabilityVector, now: Millis) {
        if let Some(n) = self.nodes.get_mut(&node) {
            n.advert.vector = vector;
            n.last_seen = now;
        }
    }

    /// The node is gone (disconnect, timeout, or withdrawal). Everything it
    /// held is revoked and dissolved; its fragments go back to the queue.
    pub fn node_gone(&mut self, node: NodeId, withdrew: bool, now: Millis) {
        let Some(entry) = self.nodes.remove(&node) else { return };
        let label = entry.advert.label.clone();
        self.emit(
            now,
            if withdrew { EventKind::NodeWithdrew { node, label } } else { EventKind::NodeLost { node, label } },
        );
        for lease in entry.active {
            // Leases that already returned keep their result; only live
            // authority is revoked.
            if self.leases.get(&lease).is_some_and(|r| r.lifecycle.phase.holds_authority()) {
                self.abort_lease(lease, RevokeReason::NodeLost, now);
            }
            self.dissolve(lease, now);
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn node_signing_key(&self, node: NodeId) -> Option<&str> {
        self.nodes.get(&node).map(|n| n.advert.signing_key.as_str())
    }

    // ----------------------------------------------------------------- jobs

    pub fn submit(&mut self, spec: JobSpec, now: Millis) -> Result<JobId, SpecError> {
        spec.validate()?;
        let id = JobId::random();
        self.emit(now, EventKind::JobSubmitted { job: id, name: spec.name.clone(), fragments: spec.fragments.len() });
        let fragments = spec
            .fragments
            .iter()
            .map(|_| FragState {
                attempts: 0,
                state: FragmentState::Pending,
                excluded: BTreeSet::new(),
                blocked_by: vec![],
            })
            .collect();
        self.jobs.insert(id, Job { spec, fragments, finished: false });
        self.job_order.push(id);
        Ok(id)
    }

    /// Place every pending fragment the current fleet can serve.
    pub fn schedule(&mut self, now: Millis) -> Vec<Outbound> {
        let views: Vec<NodeView> = self
            .nodes
            .values()
            .map(|n| NodeView {
                node_id: n.advert.node_id,
                vector: n.advert.vector.clone(),
                trust: n.trust,
                offer: n.advert.offer,
                allowed_programs: n.advert.allowed_programs.clone(),
                free_slots: n.advert.max_leases.saturating_sub(n.active.len() as u32),
            })
            .collect();

        let mut keys: Vec<(JobId, usize)> = Vec::new();
        let mut items: Vec<PlanItem<'_>> = Vec::new();
        for jid in &self.job_order {
            let job = &self.jobs[jid];
            for (i, f) in job.fragments.iter().enumerate() {
                if f.state == FragmentState::Pending {
                    keys.push((*jid, i));
                    items.push(PlanItem { fragment: &job.spec.fragments[i], excluded: f.excluded.clone() });
                }
            }
        }
        if items.is_empty() {
            return vec![];
        }
        let placement = plan(&items, &views, &self.cfg.protection);
        drop(items);

        let mut out = Vec::new();
        for a in &placement.assignments {
            let (jid, fi) = keys[a.item];
            if let Some(msg) = self.promote(jid, fi, a.node_id, a.score, now) {
                out.push(msg);
            }
        }
        for u in &placement.unplaced {
            let (jid, fi) = keys[u.item];
            self.jobs.get_mut(&jid).unwrap().fragments[fi].blocked_by = u.blocking.iter().cloned().collect();
        }
        out
    }

    /// observe → score → promote → provision for one assignment.
    fn promote(&mut self, jid: JobId, fi: usize, node: NodeId, score: f32, now: Millis) -> Option<Outbound> {
        let spec = self.jobs[&jid].spec.fragments[fi].clone();
        let n = self.nodes.get(&node)?;
        let lease_id = LeaseId::random();
        let grant = LeaseGrant {
            lease_id,
            job_id: jid,
            fragment_id: spec.id.clone(),
            node_id: node,
            scopes: scopes_for(&spec),
            ceiling: spec.ceiling,
            profile: spec.profile,
            issued_at: now,
            expires_at: now + spec.ceiling.wall_ms + self.cfg.lease_slack_ms,
            issuer: String::new(),
        };
        let task_bytes = serde_json::to_vec(&spec.task).expect("task serializes");
        let envelope = match seal(&n.advert.kex_key, lease_id.0.as_bytes(), &task_bytes) {
            Ok(e) => e,
            Err(e) => {
                self.emit(now, EventKind::BadMessage { node, detail: format!("cannot seal to node: {e}") });
                return None;
            }
        };
        let signed = grant.sign(&self.keys);

        let mut lifecycle = Lifecycle::new(now);
        let mut rec_phases = vec![Phase::Observed];
        for p in [Phase::Scored, Phase::Promoted, Phase::Provisioned] {
            lifecycle.advance(p, now).expect("fresh lease advances");
            rec_phases.push(p);
        }
        self.leases.insert(lease_id, LeaseRecord { signed: signed.clone(), job: jid, frag: fi, node, lifecycle });
        self.nodes.get_mut(&node).unwrap().active.insert(lease_id);
        let f = &mut self.jobs.get_mut(&jid).unwrap().fragments[fi];
        f.attempts += 1;
        f.blocked_by.clear();
        f.state = FragmentState::Leased { lease_id, node_id: node };
        for p in rec_phases {
            self.emit(
                now,
                EventKind::Lease {
                    lease: lease_id,
                    job: jid,
                    fragment: spec.id.clone(),
                    node,
                    phase: p,
                    score: (p == Phase::Scored).then_some(score),
                    reason: None,
                },
            );
        }
        Some(Outbound(node, OrchMsg::Provision { lease: signed, task: envelope }))
    }

    // ------------------------------------------------------ lease lifecycle

    fn advance(&mut self, lease: LeaseId, to: Phase, now: Millis) -> bool {
        let Some(r) = self.leases.get_mut(&lease) else { return false };
        if r.lifecycle.advance(to, now).is_err() {
            return false;
        }
        let (job, fragment, node) = (r.job, r.signed.grant.fragment_id.clone(), r.node);
        let reason = r.lifecycle.revoke_reason.clone().filter(|_| to == Phase::Revoked);
        self.emit(now, EventKind::Lease { lease, job, fragment, node, phase: to, score: None, reason });
        true
    }

    /// Revoke a lease and send its fragment back to the queue (or fail it).
    fn abort_lease(&mut self, lease: LeaseId, reason: RevokeReason, now: Millis) {
        let Some(r) = self.leases.get_mut(&lease) else { return };
        if r.lifecycle.revoke(reason.clone(), now).is_err() {
            return;
        }
        let (job, frag, node, expires) = (r.job, r.frag, r.node, r.signed.grant.expires_at);
        let fragment = r.signed.grant.fragment_id.clone();
        self.revoked.revoke(lease, expires);
        self.emit(
            now,
            EventKind::Lease {
                lease,
                job,
                fragment,
                node,
                phase: Phase::Revoked,
                score: None,
                reason: Some(reason.clone()),
            },
        );
        self.requeue(job, frag, lease, node, &reason, now);
    }

    fn requeue(&mut self, jid: JobId, fi: usize, lease: LeaseId, node: NodeId, reason: &RevokeReason, now: Millis) {
        let Some(job) = self.jobs.get_mut(&jid) else { return };
        let max = job.spec.max_attempts;
        let f = &mut job.fragments[fi];
        if !matches!(f.state, FragmentState::Leased { lease_id, .. } if lease_id == lease) {
            return;
        }
        f.excluded.insert(node);
        if f.attempts >= max {
            let reason = format!("{} attempts exhausted; last: {}", f.attempts, describe(reason));
            f.state = FragmentState::Failed { reason: reason.clone() };
            let fragment = job.spec.fragments[fi].id.clone();
            self.emit(now, EventKind::FragmentFailed { job: jid, fragment, reason });
            self.check_finished(jid, now);
        } else {
            f.state = FragmentState::Pending;
        }
    }

    fn dissolve(&mut self, lease: LeaseId, now: Millis) {
        if !self.advance(lease, Phase::Dissolved, now) {
            return;
        }
        if let Some(r) = self.leases.remove(&lease) {
            if let Some(n) = self.nodes.get_mut(&r.node) {
                n.active.remove(&lease);
            }
        }
    }

    fn check_finished(&mut self, jid: JobId, now: Millis) {
        let Some(job) = self.jobs.get_mut(&jid) else { return };
        if job.finished {
            return;
        }
        let done =
            job.fragments.iter().all(|f| matches!(f.state, FragmentState::Done { .. } | FragmentState::Failed { .. }));
        if done {
            job.finished = true;
            let ok = job.fragments.iter().all(|f| matches!(f.state, FragmentState::Done { .. }));
            let name = job.spec.name.clone();
            self.emit(now, EventKind::JobFinished { job: jid, name, ok });
        }
    }

    /// Validate that `node` really holds `lease`.
    fn owned(&self, node: NodeId, lease: LeaseId) -> bool {
        self.leases.get(&lease).is_some_and(|r| r.node == node)
    }

    pub fn handle(&mut self, node: NodeId, msg: NodeMsg, now: Millis) -> Vec<Outbound> {
        if let Some(n) = self.nodes.get_mut(&node) {
            n.last_seen = now;
        } else {
            return vec![];
        }
        match msg {
            NodeMsg::Heartbeat { vector } => {
                self.heartbeat(node, *vector, now);
                vec![]
            }
            NodeMsg::Accepted { .. } => vec![],
            NodeMsg::Executing { lease_id } => {
                if self.owned(node, lease_id) {
                    self.advance(lease_id, Phase::Executing, now);
                }
                vec![]
            }
            NodeMsg::Rejected { lease_id, reason } => {
                if !self.owned(node, lease_id) {
                    return vec![];
                }
                self.abort_lease(lease_id, RevokeReason::Rejected(reason), now);
                // A rejecting node never created anything to purge.
                self.dissolve(lease_id, now);
                vec![]
            }
            NodeMsg::Result { lease_id, envelope, attestation } => {
                self.on_result(node, lease_id, envelope, attestation, now)
            }
            NodeMsg::Purged { receipt } => {
                let lease = receipt.lease_id;
                if self.owned(node, lease) {
                    self.advance(lease, Phase::Purged, now);
                    self.dissolve(lease, now);
                }
                vec![]
            }
            NodeMsg::Withdraw => {
                self.node_gone(node, true, now);
                vec![]
            }
        }
    }

    fn on_result(
        &mut self,
        node: NodeId,
        lease: LeaseId,
        envelope: hotpan_seal::Envelope,
        attestation: hotpan_seal::Attestation,
        now: Millis,
    ) -> Vec<Outbound> {
        let Some(r) = self.leases.get(&lease) else { return vec![] };
        if r.node != node || !matches!(r.lifecycle.phase, Phase::Provisioned | Phase::Executing) {
            return vec![];
        }
        let fragment = r.signed.grant.fragment_id.clone();
        let node_key = self.nodes[&node].advert.signing_key.clone();
        let verified = open(&self.keys, &envelope, lease.0.as_bytes()).map_err(|e| e.to_string()).and_then(|plain| {
            attestation.verify(&node_key, lease, &fragment, node, &plain).map_err(|e| e.to_string())?;
            let payload: ResultPayload = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
            if payload.lease_id != lease || payload.fragment_id != fragment {
                return Err("payload is bound to another lease".into());
            }
            Ok(payload)
        });

        if self.leases[&lease].lifecycle.phase == Phase::Provisioned {
            self.advance(lease, Phase::Executing, now);
        }
        let purge = vec![Outbound(node, OrchMsg::Purge { lease_id: lease })];
        let payload = match verified {
            Ok(p) => p,
            Err(detail) => {
                self.emit(now, EventKind::BadMessage { node, detail: detail.clone() });
                self.abort_lease(lease, RevokeReason::BadResult(detail), now);
                return purge;
            }
        };
        self.advance(lease, Phase::Attested, now);
        self.advance(lease, Phase::Returned, now);

        use hotpan_sandbox::Outcome;
        let failure = match &payload.outcome {
            o if o.succeeded() => None,
            Outcome::Preempted(why) => Some(RevokeReason::Preempted(why.clone())),
            Outcome::Rejected(why) => Some(RevokeReason::Rejected(why.clone())),
            Outcome::Completed { exit_code } => {
                Some(RevokeReason::TaskFailed(format!("exit {exit_code}: {}", payload.stderr.trim())))
            }
            other => Some(RevokeReason::TaskFailed(format!("{other:?}"))),
        };
        match failure {
            Some(reason) => self.abort_lease(lease, reason, now),
            None => {
                let (jid, fi) = (self.leases[&lease].job, self.leases[&lease].frag);
                let job = self.jobs.get_mut(&jid).unwrap();
                job.fragments[fi].state = FragmentState::Done { node_id: node, result: payload };
                self.emit(now, EventKind::FragmentDone { job: jid, fragment, node });
                self.check_finished(jid, now);
            }
        }
        purge
    }

    /// Advance time: lose silent nodes, expire overdue leases, dissolve
    /// leases whose purge receipt never came.
    pub fn tick(&mut self, now: Millis) -> Vec<Outbound> {
        let silent: Vec<NodeId> = self
            .nodes
            .iter()
            .filter(|(_, n)| now.saturating_sub(n.last_seen) > self.cfg.node_timeout_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in silent {
            self.node_gone(id, false, now);
        }

        let mut out = Vec::new();
        let leases: Vec<(LeaseId, Phase, Millis, NodeId)> =
            self.leases.iter().map(|(id, r)| (*id, r.lifecycle.phase, r.signed.grant.expires_at, r.node)).collect();
        for (id, phase, expires, node) in leases {
            if phase.holds_authority() && now >= expires {
                self.abort_lease(id, RevokeReason::Expired, now);
                out.push(Outbound(node, OrchMsg::Revoke { lease_id: id, reason: RevokeReason::Expired }));
            } else if matches!(phase, Phase::Revoked | Phase::Returned) && now >= expires + self.cfg.purge_grace_ms {
                self.dissolve(id, now);
            }
        }
        self.revoked.gc(now);
        out
    }

    // ------------------------------------------------------------- reports

    pub fn job_report(&self, id: JobId) -> Option<JobReport> {
        let job = self.jobs.get(&id)?;
        Some(JobReport {
            job_id: id,
            name: job.spec.name.clone(),
            finished: job.finished,
            fragments: job
                .spec
                .fragments
                .iter()
                .zip(&job.fragments)
                .map(|(spec, f)| FragmentReport {
                    id: spec.id.clone(),
                    attempts: f.attempts,
                    state: f.state.clone(),
                    blocked_by: f.blocked_by.clone(),
                })
                .collect(),
        })
    }

    pub fn fleet(&self) -> Vec<FleetEntry> {
        self.nodes
            .values()
            .map(|n| FleetEntry {
                node_id: n.advert.node_id,
                label: n.advert.label.clone(),
                device_class: n.advert.device_class,
                trust: n.trust,
                active_leases: n.active.len() as u32,
                max_leases: n.advert.max_leases,
                vector: n.advert.vector.clone(),
            })
            .collect()
    }

    pub fn lease_phase(&self, id: LeaseId) -> Option<Phase> {
        self.leases.get(&id).map(|r| r.lifecycle.phase)
    }

    pub fn live_leases(&self) -> usize {
        self.leases.len()
    }
}

fn describe(r: &RevokeReason) -> String {
    match r {
        RevokeReason::NodeLost => "node lost".into(),
        RevokeReason::Preempted(w) => format!("preempted: {w}"),
        RevokeReason::Expired => "lease expired".into(),
        RevokeReason::Rejected(w) => format!("rejected: {w}"),
        RevokeReason::BadResult(w) => format!("bad result: {w}"),
        RevokeReason::TaskFailed(w) => format!("task failed: {w}"),
        RevokeReason::Withdrawn => "withdrawn".into(),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
