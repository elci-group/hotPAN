//! Control-plane behaviour, driven in-process against real `NodeCore`s:
//! real leases, real envelopes, real sandbox execution, synthetic clock.

use super::*;
use hotpan_heuristic::Protection;
use hotpan_node::{advertisement, NodeCore, NodeIdentity, NodeSettings};
use hotpan_probe::{template, Probe, ScriptedProbe};
use hotpan_sandbox::{Outcome, Policy};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

struct Sim {
    core: NodeCore,
    probe: ScriptedProbe,
    /// A vanished node silently drops everything.
    gone: bool,
    _dir: tempfile::TempDir,
}

struct World {
    plane: ControlPlane,
    nodes: HashMap<NodeId, Sim>,
    now: Millis,
}

fn settings(label: &str, dir: &std::path::Path) -> NodeSettings {
    NodeSettings {
        label: label.into(),
        policy: Policy {
            allowed_programs: BTreeSet::from(["/bin/sh".to_string()]),
            max: ResourceCeiling::default(),
            workroot: dir.to_path_buf(),
        },
        max_leases: 1,
        protection: Protection::default(),
    }
}

impl World {
    fn new() -> Self {
        Self {
            plane: ControlPlane::new(Keypair::generate(), PlaneConfig::default()),
            nodes: HashMap::new(),
            now: now_millis(),
        }
    }

    fn join(&mut self, label: &str, class: DeviceClass, tweak: impl FnOnce(&mut CapabilityVector)) -> NodeId {
        let mut v = template(class);
        tweak(&mut v);
        let probe = ScriptedProbe::new(class, v);
        let dir = tempfile::tempdir().unwrap();
        let id = NodeIdentity::fresh();
        let advert = advertisement(&id, &settings(label, dir.path()), &probe);
        let node_id = id.node_id;
        self.plane.register(advert, TrustLevel::Paired, self.now).unwrap();
        let core = NodeCore::new(id, self.plane.public(), settings(label, dir.path()));
        self.nodes.insert(node_id, Sim { core, probe, gone: false, _dir: dir });
        node_id
    }

    /// Deliver messages until the system is quiescent.
    fn run(&mut self, initial: Vec<Outbound>) {
        let mut q: VecDeque<Outbound> = initial.into();
        while let Some(Outbound(node, msg)) = q.pop_front() {
            let Some(sim) = self.nodes.get_mut(&node) else { continue };
            if sim.gone {
                continue;
            }
            let replies: Vec<NodeMsg> = match msg {
                OrchMsg::Provision { lease, task } => {
                    let v = sim.probe.sample();
                    match sim.core.provision(lease, task, &v, self.now) {
                        Err(rej) => vec![rej.into()],
                        Ok(prep) => {
                            let probe: Arc<dyn Probe> = Arc::new(sim.probe.clone());
                            let guard = sim.core.guard_for(&prep, probe);
                            let report = prep.run(&sim.core.settings().policy.clone(), &|| guard.check());
                            let mut m = vec![NodeMsg::Executing { lease_id: prep.grant.lease_id }];
                            m.extend(sim.core.complete(prep, report));
                            m
                        }
                    }
                }
                OrchMsg::Purge { lease_id } => sim.core.purge(lease_id).into_iter().collect(),
                OrchMsg::Revoke { lease_id, .. } => sim.core.revoke(lease_id).into_iter().collect(),
                _ => vec![],
            };
            for r in replies {
                q.extend(self.plane.handle(node, r, self.now));
            }
            q.extend(self.plane.schedule(self.now));
        }
    }

    fn step(&mut self) {
        let out = self.plane.schedule(self.now);
        self.run(out);
    }

    fn advance(&mut self, ms: u64) {
        self.now += ms;
        // Live nodes heartbeat.
        let live: Vec<(NodeId, CapabilityVector)> =
            self.nodes.iter().filter(|(_, s)| !s.gone).map(|(id, s)| (*id, s.probe.sample())).collect();
        for (id, v) in live {
            self.plane.heartbeat(id, v, self.now);
        }
        let mut out = self.plane.tick(self.now);
        out.extend(self.plane.schedule(self.now));
        self.run(out);
    }
}

fn frag(id: &str, profile: WorkloadProfile, task: TaskSpec) -> FragmentSpec {
    FragmentSpec {
        id: id.into(),
        profile,
        requires: BTreeSet::new(),
        locality: None,
        privacy: Privacy::Anywhere,
        min_trust: TrustLevel::Unverified,
        ceiling: ResourceCeiling::default(),
        task,
    }
}

fn primes(n: u64) -> TaskSpec {
    TaskSpec::Builtin(BuiltinTask::PrimeCount { upto: n })
}

fn job(fragments: Vec<FragmentSpec>) -> JobSpec {
    JobSpec { name: "t".into(), max_attempts: 3, fragments }
}

fn done_on(r: &JobReport, frag: &str) -> Option<(NodeId, String)> {
    r.fragments.iter().find(|f| f.id == frag).and_then(|f| match &f.state {
        FragmentState::Done { node_id, result } => Some((*node_id, result.stdout.clone())),
        _ => None,
    })
}

fn lease_phases(events: &[Event], fragment: &str) -> Vec<Vec<Phase>> {
    let mut by: Vec<(LeaseId, Vec<Phase>)> = vec![];
    for e in events {
        if let EventKind::Lease { lease, fragment: f, phase, .. } = &e.kind {
            if f == fragment {
                match by.iter_mut().find(|(l, _)| l == lease) {
                    Some((_, v)) => v.push(*phase),
                    None => by.push((*lease, vec![*phase])),
                }
            }
        }
    }
    by.into_iter().map(|(_, v)| v).collect()
}

#[test]
fn workload_relative_placement_and_full_lifecycle() {
    let mut w = World::new();
    // The concept's two phones: a drained, in-use one with a camera and a
    // charging idle one overnight.
    let drained = w.join("pocket", DeviceClass::Phone, |v| {
        v.power = PowerState::battery(18.0, false);
        v.user_activity = UserActivity::Active;
        v.capabilities.insert(Capability::Camera);
    });
    let charging = w.join("nightstand", DeviceClass::Phone, |v| {
        v.power = PowerState::battery(70.0, true);
    });

    let mut capture =
        frag("capture", WorkloadProfile::SensorBound, TaskSpec::Builtin(BuiltinTask::Echo { payload: "frame".into() }));
    capture.requires.insert(Capability::Camera);
    let jid = w
        .plane
        .submit(job(vec![frag("compile", WorkloadProfile::ComputeBound, primes(100_000)), capture]), w.now)
        .unwrap();
    w.step();

    let r = w.plane.job_report(jid).unwrap();
    assert!(r.finished, "{r:?}");
    assert_eq!(done_on(&r, "compile"), Some((charging, "9592".into())));
    assert_eq!(done_on(&r, "capture"), Some((drained, "frame".into())));
    assert_eq!(w.plane.live_leases(), 0, "every lease dissolved");

    let events = w.plane.drain_events();
    use Phase::*;
    assert_eq!(
        lease_phases(&events, "compile"),
        vec![vec![Observed, Scored, Promoted, Provisioned, Executing, Attested, Returned, Purged, Dissolved]]
    );
    assert!(events.iter().any(|e| matches!(e.kind, EventKind::JobFinished { ok: true, .. })));
}

#[test]
fn vanished_node_mid_job_is_revoked_and_work_moves() {
    let mut w = World::new();
    let a = w.join("a", DeviceClass::Desktop, |v| v.compute.logical_cpus = 32);
    let jid = w.plane.submit(job(vec![frag("f", WorkloadProfile::ComputeBound, primes(1000))]), w.now).unwrap();
    // A gets the lease and vanishes before running it.
    w.nodes.get_mut(&a).unwrap().gone = true;
    w.step();
    assert!(
        matches!(w.plane.job_report(jid).unwrap().fragments[0].state, FragmentState::Leased { node_id, .. } if node_id == a)
    );

    let b = w.join("b", DeviceClass::Phone, |_| {});
    // B has nothing to do yet: the fragment is leased to A.
    w.step();
    assert!(!w.plane.job_report(jid).unwrap().finished);

    w.advance(PlaneConfig::default().node_timeout_ms + 1);
    let r = w.plane.job_report(jid).unwrap();
    assert!(r.finished);
    assert_eq!(r.fragments[0].attempts, 2);
    assert_eq!(done_on(&r, "f").unwrap().0, b);
    let ev = w.plane.drain_events();
    assert!(ev.iter().any(|e| matches!(&e.kind, EventKind::NodeLost { node, .. } if *node == a)));
    assert!(ev.iter().any(|e| matches!(
        &e.kind,
        EventKind::Lease { phase: Phase::Revoked, reason: Some(RevokeReason::NodeLost), .. }
    )));
    assert_eq!(w.plane.node_count(), 1);
}

#[test]
fn battery_preemption_reschedules_elsewhere() {
    let mut w = World::new();
    let phone = w.join("phone", DeviceClass::Phone, |v| v.compute.logical_cpus = 64);
    // The phone drops below the compute floor between scheduling and execution.
    let sim_probe = w.nodes[&phone].probe.clone();
    let jid = w.plane.submit(job(vec![frag("f", WorkloadProfile::ComputeBound, primes(1000))]), w.now).unwrap();
    let out = w.plane.schedule(w.now);
    sim_probe.update(|v| v.power = PowerState::battery(9.0, false));
    w.run(out);
    let r = w.plane.job_report(jid).unwrap();
    assert!(matches!(r.fragments[0].state, FragmentState::Pending), "{r:?}");
    assert!(w.plane.drain_events().iter().any(|e| matches!(&e.kind, EventKind::Lease { reason: Some(RevokeReason::Rejected(m)), .. } if m.contains("BatteryLowForProfile"))));

    let desk = w.join("desk", DeviceClass::Desktop, |_| {});
    w.step();
    let r = w.plane.job_report(jid).unwrap();
    assert_eq!(done_on(&r, "f").unwrap().0, desk);
}

#[test]
fn in_flight_preemption_is_reported_and_retried() {
    let mut w = World::new();
    let phone = w.join("phone", DeviceClass::Phone, |_| {});
    let probe = w.nodes[&phone].probe.clone();
    let jid = w
        .plane
        .submit(
            job(vec![frag("f", WorkloadProfile::ComputeBound, TaskSpec::Builtin(BuiltinTask::Sleep { ms: 5_000 }))]),
            w.now,
        )
        .unwrap();
    // Drain the battery while the task sleeps.
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        probe.update(|v| v.power = PowerState::battery(4.0, false));
    });
    w.step();
    t.join().unwrap();
    let ev = w.plane.drain_events();
    assert!(ev.iter().any(|e| matches!(&e.kind, EventKind::Lease { reason: Some(RevokeReason::Preempted(m)), .. } if m.contains("BatteryCritical"))), "{ev:#?}");
    let r = w.plane.job_report(jid).unwrap();
    assert_eq!(r.fragments[0].attempts, 1);
    assert!(matches!(r.fragments[0].state, FragmentState::Pending));
    assert_eq!(w.plane.live_leases(), 0);
}

#[test]
fn exhausted_attempts_fail_the_fragment() {
    let mut w = World::new();
    for i in 0..3 {
        w.join(&format!("n{i}"), DeviceClass::Desktop, |_| {});
    }
    let jid = w
        .plane
        .submit(
            job(vec![frag(
                "f",
                WorkloadProfile::ComputeBound,
                TaskSpec::Exec {
                    program: "/bin/sh".into(),
                    args: vec!["-c".into(), "echo boom >&2; exit 7".into()],
                    stdin: None,
                },
            )]),
            w.now,
        )
        .unwrap();
    w.step();
    let r = w.plane.job_report(jid).unwrap();
    assert!(r.finished);
    assert_eq!(r.fragments[0].attempts, 3);
    match &r.fragments[0].state {
        FragmentState::Failed { reason } => assert!(reason.contains("exit 7: boom"), "{reason}"),
        s => panic!("{s:?}"),
    }
    assert!(w.plane.drain_events().iter().any(|e| matches!(e.kind, EventKind::JobFinished { ok: false, .. })));
}

#[test]
fn forged_results_are_rejected() {
    let mut w = World::new();
    let n = w.join("n", DeviceClass::Desktop, |_| {});
    let jid = w.plane.submit(job(vec![frag("f", WorkloadProfile::ComputeBound, primes(10))]), w.now).unwrap();
    let out = w.plane.schedule(w.now);
    let OrchMsg::Provision { lease, .. } = &out[0].1 else { panic!() };
    let lease_id = lease.grant.lease_id;
    // An impostor seals a plausible result but signs with the wrong key.
    let impostor = Keypair::generate();
    let payload = ResultPayload {
        lease_id,
        fragment_id: "f".into(),
        outcome: Outcome::Completed { exit_code: 0 },
        stdout: "999".into(),
        stderr: String::new(),
        truncated: false,
        wall_ms: 1,
    };
    let plain = serde_json::to_vec(&payload).unwrap();
    let envelope = seal(&w.plane.public().kex, lease_id.0.as_bytes(), &plain).unwrap();
    let attestation = hotpan_seal::attest(&impostor, lease_id, "f", n, &plain);
    let out = w.plane.handle(n, NodeMsg::Result { lease_id, envelope, attestation }, w.now);
    assert!(matches!(out[0].1, OrchMsg::Purge { .. }));
    assert!(matches!(w.plane.job_report(jid).unwrap().fragments[0].state, FragmentState::Pending));
    assert!(w
        .plane
        .drain_events()
        .iter()
        .any(|e| matches!(&e.kind, EventKind::Lease { reason: Some(RevokeReason::BadResult(_)), .. })));
    // A different node cannot report on someone else's lease.
    assert!(w.plane.handle(NodeId::random(), NodeMsg::Withdraw, w.now).is_empty());
}

#[test]
fn overdue_leases_expire_and_dissolve() {
    let mut w = World::new();
    let n = w.join("n", DeviceClass::Desktop, |_| {});
    let mut f = frag("f", WorkloadProfile::ComputeBound, primes(10));
    f.ceiling.wall_ms = 1_000;
    let jid = w.plane.submit(job(vec![f]), w.now).unwrap();
    let out = w.plane.schedule(w.now);
    let OrchMsg::Provision { lease, .. } = &out[0].1 else { panic!() };
    let lease_id = lease.grant.lease_id;
    // The node accepted but never answers (yet keeps heartbeating).
    let cfg = PlaneConfig::default();
    w.now += 1_000 + cfg.lease_slack_ms;
    w.plane.heartbeat(n, template(DeviceClass::Desktop), w.now);
    let out = w.plane.tick(w.now);
    assert!(matches!(out[0].1, OrchMsg::Revoke { reason: RevokeReason::Expired, .. }));
    assert_eq!(w.plane.lease_phase(lease_id), Some(Phase::Revoked));
    assert!(matches!(w.plane.job_report(jid).unwrap().fragments[0].state, FragmentState::Pending));
    // No purge receipt arrives either: dissolve after the grace period.
    w.now += cfg.purge_grace_ms;
    w.plane.heartbeat(n, template(DeviceClass::Desktop), w.now);
    w.plane.tick(w.now);
    assert_eq!(w.plane.lease_phase(lease_id), None);
}

#[test]
fn unplaceable_fragments_explain_themselves() {
    let mut w = World::new();
    w.join("desk", DeviceClass::Desktop, |_| {});
    let mut f = frag("gps", WorkloadProfile::SensorBound, primes(10));
    f.requires.insert(Capability::Gps);
    f.privacy = Privacy::MustStayOn("location-history".into());
    let jid = w.plane.submit(job(vec![f]), w.now).unwrap();
    w.step();
    let r = w.plane.job_report(jid).unwrap();
    assert!(!r.finished);
    assert!(r.fragments[0].blocked_by.contains(&Gate::MissingCapability("gps".into())));
    assert!(r.fragments[0].blocked_by.contains(&Gate::PrivacyLocality("location-history".into())));
}

#[test]
fn node_rejects_tampered_and_foreign_leases() {
    let mut w = World::new();
    let n = w.join("n", DeviceClass::Desktop, |_| {});
    w.plane.submit(job(vec![frag("f", WorkloadProfile::ComputeBound, primes(10))]), w.now).unwrap();
    let out = w.plane.schedule(w.now);
    let OrchMsg::Provision { lease, task } = out[0].1.clone() else { panic!() };
    let sim = w.nodes.get_mut(&n).unwrap();
    let v = sim.probe.sample();

    let mut tampered = lease.clone();
    tampered.grant.scopes.push(hotpan_seal::Scope::Exec("/bin/sh".into()));
    assert!(
        matches!(sim.core.provision(tampered, task.clone(), &v, w.now), Err(hotpan_node::Rejection { reason, .. }) if reason.contains("signature"))
    );

    let foreign = lease.grant.clone().sign(&Keypair::generate());
    assert!(
        matches!(sim.core.provision(foreign, task.clone(), &v, w.now), Err(hotpan_node::Rejection { reason, .. }) if reason.contains("orchestrator"))
    );

    // The genuine lease works once, never twice.
    let prep = sim.core.provision(lease.clone(), task.clone(), &v, w.now).ok().unwrap();
    assert!(sim.core.provision(lease, task, &v, w.now).is_err());
    // Revoked while "running": no result is released, workspace is purged.
    let ws = prep.workspace.path().to_path_buf();
    assert!(sim.core.revoke(prep.grant.lease_id).is_none());
    let report = prep.run(&sim.core.settings().policy.clone(), &|| None);
    let msgs = sim.core.complete(prep, report);
    assert!(matches!(msgs.as_slice(), [NodeMsg::Purged { .. }]), "{msgs:?}");
    assert!(!ws.exists());
    assert_eq!(sim.core.active(), 0);
}
