//! `hotpan simulate`: a scripted evening in a household fabric, run against
//! the real control plane, real leases and envelopes, and the real sandbox.
//! Only the devices' sensors (battery, thermal, presence) are scripted.

use hotpan_core::*;
use hotpan_heuristic::Protection;
use hotpan_node::{advertisement, NodeCore, NodeIdentity, NodeSettings};
use hotpan_orchestrator::{ControlPlane, Event, EventKind, Outbound, PlaneConfig};
use hotpan_probe::{template, Probe, ScriptedProbe};
use hotpan_sandbox::Policy;
use hotpan_seal::Keypair;
use hotpan_wire::{FragmentState, NodeMsg, OrchMsg};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

struct SimNode {
    label: String,
    core: NodeCore,
    probe: ScriptedProbe,
    gone: bool,
}

pub struct Sim {
    plane: ControlPlane,
    nodes: BTreeMap<NodeId, SimNode>,
    now: Millis,
    start: Millis,
    workroot: std::path::PathBuf,
    pub log: Vec<String>,
}

impl Sim {
    pub fn new(workroot: &std::path::Path) -> Self {
        let now = now_millis();
        Self {
            plane: ControlPlane::new(Keypair::generate(), PlaneConfig::default()),
            nodes: BTreeMap::new(),
            now,
            start: now,
            workroot: workroot.to_path_buf(),
            log: vec![],
        }
    }

    pub fn join(&mut self, label: &str, class: DeviceClass, tweak: impl FnOnce(&mut CapabilityVector)) -> NodeId {
        let mut v = template(class);
        tweak(&mut v);
        let probe = ScriptedProbe::new(class, v);
        let settings = NodeSettings {
            label: label.into(),
            policy: Policy {
                allowed_programs: BTreeSet::new(),
                max: ResourceCeiling::default(),
                workroot: self.workroot.join(label),
            },
            max_leases: if matches!(class, DeviceClass::HomeServer | DeviceClass::Desktop) { 2 } else { 1 },
            protection: Protection::default(),
        };
        let id = NodeIdentity::fresh();
        let node_id = id.node_id;
        self.plane.register(advertisement(&id, &settings, &probe), TrustLevel::Paired, self.now).expect("fresh id");
        let core = NodeCore::new(id, self.plane.public(), settings);
        self.nodes.insert(node_id, SimNode { label: label.into(), core, probe, gone: false });
        self.flush();
        node_id
    }

    pub fn update(&mut self, node: NodeId, note: &str, f: impl FnOnce(&mut CapabilityVector)) {
        let n = &self.nodes[&node];
        n.probe.update(f);
        let v = n.probe.sample();
        self.plane.heartbeat(node, v, self.now);
        self.note(note);
    }

    pub fn vanish(&mut self, node: NodeId, note: &str) {
        self.nodes.get_mut(&node).unwrap().gone = true;
        self.note(note);
    }

    pub fn note(&mut self, s: &str) {
        let line = format!("{:>6}  ── {s}", self.clock());
        self.log.push(line);
    }

    fn clock(&self) -> String {
        format!("+{:.1}s", (self.now - self.start) as f64 / 1000.0)
    }

    pub fn submit(&mut self, job: JobSpec) -> JobId {
        let id = self.plane.submit(job, self.now).expect("valid job");
        self.flush();
        id
    }

    /// Schedule and deliver everything until quiescent.
    pub fn step(&mut self) {
        let out = self.plane.schedule(self.now);
        self.deliver(out);
    }

    pub fn advance(&mut self, ms: u64) {
        self.now += ms;
        let live: Vec<(NodeId, CapabilityVector)> =
            self.nodes.iter().filter(|(_, n)| !n.gone).map(|(id, n)| (*id, n.probe.sample())).collect();
        for (id, v) in live {
            self.plane.heartbeat(id, v, self.now);
        }
        let mut out = self.plane.tick(self.now);
        out.extend(self.plane.schedule(self.now));
        self.deliver(out);
    }

    fn deliver(&mut self, initial: Vec<Outbound>) {
        let mut q: VecDeque<Outbound> = initial.into();
        while let Some(Outbound(node, msg)) = q.pop_front() {
            self.flush();
            let Some(n) = self.nodes.get_mut(&node) else { continue };
            if n.gone {
                continue;
            }
            let replies: Vec<NodeMsg> = match msg {
                OrchMsg::Provision { lease, task } => {
                    match n.core.provision(lease, task, &n.probe.sample(), self.now) {
                        Err(r) => vec![r.into()],
                        Ok(prep) => {
                            let probe: Arc<dyn Probe> = Arc::new(n.probe.clone());
                            let guard = n.core.guard_for(&prep, probe);
                            let policy = n.core.settings().policy.clone();
                            let report = prep.run(&policy, &|| guard.check());
                            let mut m = vec![NodeMsg::Executing { lease_id: prep.grant.lease_id }];
                            m.extend(n.core.complete(prep, report));
                            m
                        }
                    }
                }
                OrchMsg::Purge { lease_id } => n.core.purge(lease_id).into_iter().collect(),
                OrchMsg::Revoke { lease_id, .. } => n.core.revoke(lease_id).into_iter().collect(),
                _ => vec![],
            };
            for r in replies {
                q.extend(self.plane.handle(node, r, self.now));
            }
            q.extend(self.plane.schedule(self.now));
        }
        self.flush();
    }

    fn label(&self, n: &NodeId) -> String {
        self.nodes.get(n).map(|s| s.label.clone()).unwrap_or_else(|| n.short())
    }

    fn flush(&mut self) {
        let events: Vec<Event> = self.plane.drain_events();
        for e in events {
            let line = match &e.kind {
                EventKind::NodeJoined { node, class, trust, .. } => {
                    format!("{} joined as {class:?} ({trust:?})", self.label(node))
                }
                EventKind::NodeLost { label, .. } => format!("{label} lost: missed heartbeats"),
                EventKind::NodeWithdrew { label, .. } => format!("{label} withdrew"),
                EventKind::JobSubmitted { name, fragments, .. } => {
                    format!("job `{name}` submitted ({fragments} fragments)")
                }
                EventKind::Lease { fragment, node, phase: Phase::Scored, score, .. } => {
                    format!("{fragment:<10} → {:<12} scored {:.3}", self.label(node), score.unwrap_or(0.0))
                }
                EventKind::Lease { fragment, node, phase: Phase::Revoked, reason, .. } => {
                    format!("{fragment:<10} ✗ {:<12} revoked: {reason:?}", self.label(node))
                }
                EventKind::Lease { fragment, node, phase, .. }
                    if matches!(phase, Phase::Attested | Phase::Dissolved) =>
                {
                    format!("{fragment:<10} · {:<12} {phase:?}", self.label(node))
                }
                EventKind::Lease { .. } => continue,
                EventKind::FragmentDone { fragment, node, .. } => {
                    format!("{fragment:<10} ✓ {:<12} done", self.label(node))
                }
                EventKind::FragmentFailed { fragment, reason, .. } => format!("{fragment:<10} FAILED: {reason}"),
                EventKind::JobFinished { name, ok, .. } => {
                    format!("job `{name}` finished: {}", if *ok { "ok" } else { "with failures" })
                }
                EventKind::BadMessage { node, detail } => format!("bad message from {}: {detail}", self.label(node)),
            };
            let stamp = format!("+{:.1}s", (e.at - self.start) as f64 / 1000.0);
            self.log.push(format!("{stamp:>6}  {line}"));
        }
    }

    pub fn report(&self, job: JobId) -> Vec<String> {
        let r = self.plane.job_report(job).expect("job exists");
        r.fragments
            .iter()
            .map(|f| match &f.state {
                FragmentState::Done { node_id, result } => format!(
                    "  {:<10} {:<12} attempts={} output={}",
                    f.id,
                    self.label(node_id),
                    f.attempts,
                    result.stdout.trim()
                ),
                FragmentState::Failed { reason } => format!("  {:<10} FAILED {reason}", f.id),
                other => format!("  {:<10} {:?} blocked_by={:?}", f.id, other, f.blocked_by),
            })
            .collect()
    }

    pub fn finished(&self, job: JobId) -> bool {
        self.plane.job_report(job).is_some_and(|r| r.finished)
    }

    pub fn live_leases(&self) -> usize {
        self.plane.live_leases()
    }
}

/// The built-in "evening" scenario.
pub fn evening(workroot: &std::path::Path) -> (Sim, JobId) {
    let mut s = Sim::new(workroot);
    let pocket = s.join("pocket", DeviceClass::Phone, |v| {
        v.power = PowerState::battery(18.0, false);
        v.user_activity = UserActivity::Active;
        v.network = NetworkState { kind: NetworkKind::Cellular, metered: true, rtt_ms: Some(90) };
        v.cost = 1.0;
        v.capabilities.extend([
            Capability::Camera,
            Capability::Gps,
            Capability::Cellular,
            Capability::LocalData("location-history".into()),
        ]);
    });
    let nightstand = s.join("nightstand", DeviceClass::Phone, |v| {
        v.power = PowerState::battery(55.0, true);
        v.capabilities.insert(Capability::Camera);
    });
    let _laptop = s.join("laptop", DeviceClass::Laptop, |v| {
        v.power = PowerState::battery(60.0, false);
        v.user_activity = UserActivity::Light;
    });
    let server = s.join("homeserver", DeviceClass::HomeServer, |v| v.compute.logical_cpus = 16);
    let _ = pocket;

    let mut frags = vec![];
    let mut capture = FragmentSpec {
        id: "capture".into(),
        profile: WorkloadProfile::SensorBound,
        requires: [Capability::Camera].into(),
        locality: None,
        privacy: Privacy::Anywhere,
        min_trust: TrustLevel::Paired,
        ceiling: ResourceCeiling::default(),
        task: TaskSpec::Builtin(BuiltinTask::Echo { payload: "frame-0001.jpg".into() }),
    };
    frags.push(capture.clone());
    capture.id = "geotag".into();
    capture.requires = [Capability::Gps].into();
    capture.privacy = Privacy::MustStayOn("location-history".into());
    capture.task = TaskSpec::Builtin(BuiltinTask::Blake3 { data: "51.5072,-0.1276".into() });
    frags.push(capture.clone());
    for i in 0..6 {
        let mut f = capture.clone();
        f.id = format!("tile-{i}");
        f.profile = WorkloadProfile::ParallelLowRelational;
        f.requires = BTreeSet::new();
        f.privacy = Privacy::Anywhere;
        f.task = TaskSpec::Builtin(BuiltinTask::PrimeCount { upto: 200_000 + 50_000 * i as u64 });
        frags.push(f);
    }
    let job = s.submit(JobSpec { name: "photo-pipeline".into(), max_attempts: 3, fragments: frags });

    // The nightstand phone heats up before it gets its work; then the home
    // server falls off the network with leases in flight.
    s.update(nightstand, "nightstand phone heats up under its case (thermal headroom 0.12)", |v| {
        v.thermal_headroom = 0.12
    });
    s.vanish(server, "homeserver loses power — it will hold its leases silently");
    s.step();
    s.advance(PlaneConfig::default().node_timeout_ms + 1);
    s.update(nightstand, "nightstand phone cools down (thermal headroom 0.8)", |v| v.thermal_headroom = 0.8);
    for _ in 0..5 {
        if s.finished(job) {
            break;
        }
        s.advance(500);
    }
    (s, job)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evening_scenario_completes_with_handoffs() {
        let d = tempfile::tempdir().unwrap();
        let (s, job) = evening(d.path());
        let text = s.log.join("\n");
        assert!(s.finished(job), "{text}");
        assert_eq!(s.live_leases(), 0, "{text}");
        let report = s.report(job).join("\n");
        assert!(!report.contains("FAILED"), "{report}");
        // Sensor and private-data work stays on the only phone that can do it.
        assert!(report.lines().any(|l| l.contains("capture") && (l.contains("pocket") || l.contains("nightstand"))));
        assert!(report.lines().any(|l| l.contains("geotag") && l.contains("pocket")));
        // The drained, in-use pocket phone never gets compute tiles.
        assert!(!report.lines().any(|l| l.contains("tile-") && l.contains("pocket")), "{report}");
        assert!(text.contains("homeserver lost"));
        assert!(text.contains("NodeLost"));
    }
}
