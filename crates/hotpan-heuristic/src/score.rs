use hotpan_core::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Device-protection thresholds. These are invariants, not preferences.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Protection {
    /// Below this (on battery, not charging) compute-heavy work is refused.
    pub battery_floor_pct: f32,
    /// Below this (on battery, not charging) all work is refused.
    pub battery_critical_pct: f32,
    /// Below this headroom compute-heavy work is refused.
    pub thermal_floor: f32,
    /// Below this headroom all work is refused.
    pub thermal_critical: f32,
    /// Eligible nodes scoring below this are not worth promoting: the work
    /// waits for a better node rather than draining a poor fit.
    pub promotion_threshold: f32,
}

impl Default for Protection {
    fn default() -> Self {
        Self {
            battery_floor_pct: 15.0,
            battery_critical_pct: 5.0,
            thermal_floor: 0.2,
            thermal_critical: 0.05,
            promotion_threshold: 0.05,
        }
    }
}

/// The orchestrator's view of one candidate node.
#[derive(Clone, Debug)]
pub struct NodeView {
    pub node_id: NodeId,
    pub vector: CapabilityVector,
    pub trust: TrustLevel,
    pub offer: ResourceCeiling,
    pub allowed_programs: BTreeSet<String>,
    pub free_slots: u32,
}

/// A hard gate a node failed for a fragment.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", tag = "gate", content = "detail")]
pub enum Gate {
    MissingCapability(String),
    PrivacyLocality(String),
    LocalityMismatch,
    InsufficientTrust,
    CeilingExceedsOffer,
    ProgramNotAllowed(String),
    InsufficientMemory,
    Offline,
    BatteryCritical,
    BatteryLowForProfile,
    ThermalCritical,
    ThermalLowForProfile,
    NoFreeSlot,
    BelowPromotionThreshold,
}

/// Each component is in `0..=1`; higher is better.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Components {
    pub energy: f32,
    pub thermal: f32,
    pub compute: f32,
    pub memory: f32,
    pub network: f32,
    pub idle: f32,
    pub cost: f32,
    pub trust: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assessment {
    pub node_id: NodeId,
    pub fragment_id: String,
    /// Final score in `0..=1`; `0` whenever any gate failed.
    pub score: f32,
    pub gates: Vec<Gate>,
    pub components: Components,
}

impl Assessment {
    pub fn eligible(&self) -> bool {
        self.gates.is_empty()
    }
}

fn compute_heavy(p: WorkloadProfile) -> bool {
    matches!(p, WorkloadProfile::ComputeBound | WorkloadProfile::ParallelLowRelational)
}

/// Weights in the order of [`Components`]; each row sums to 1.
#[rustfmt::skip]
fn weights(p: WorkloadProfile) -> [f32; 8] {
    use WorkloadProfile::*;
    match p {
        //                     energy thermal compute memory network idle  cost  trust
        ComputeBound =>          [0.20, 0.15, 0.30, 0.10, 0.05, 0.15, 0.03, 0.02],
        ParallelLowRelational => [0.20, 0.15, 0.25, 0.05, 0.05, 0.15, 0.10, 0.05],
        SensorBound =>           [0.15, 0.05, 0.05, 0.05, 0.20, 0.15, 0.10, 0.25],
        CredentialBound =>       [0.10, 0.05, 0.05, 0.05, 0.20, 0.10, 0.05, 0.40],
        NetworkBound =>          [0.20, 0.05, 0.05, 0.05, 0.40, 0.10, 0.10, 0.05],
        Monitoring =>            [0.35, 0.10, 0.02, 0.03, 0.15, 0.05, 0.20, 0.10],
    }
}

fn components(v: &CapabilityVector, trust: TrustLevel, ceiling: &ResourceCeiling) -> Components {
    let energy = match v.power.battery_pct {
        _ if v.power.externally_powered() => 1.0,
        Some(pct) => (pct / 100.0).clamp(0.0, 1.0).powf(1.5),
        None => 1.0,
    };
    let throughput =
        v.compute.logical_cpus as f32 * v.compute.relative_perf.max(0.0) * (1.0 - v.compute.busy.clamp(0.0, 1.0));
    let compute = 1.0 - (-throughput / 4.0).exp();
    let memory = (v.memory.available_mb as f32 / (4.0 * ceiling.memory_mb.max(1) as f32)).min(1.0);
    let kind = match v.network.kind {
        NetworkKind::Ethernet => 1.0,
        NetworkKind::Wifi => 0.9,
        NetworkKind::Cellular => 0.5,
        NetworkKind::Offline => 0.0,
    };
    let metered = if v.network.metered { 0.6 } else { 1.0 };
    let rtt = v.network.rtt_ms.map(|r| 1.0 / (1.0 + r as f32 / 200.0)).unwrap_or(0.8);
    let idle = match v.user_activity {
        UserActivity::Idle => 1.0,
        UserActivity::Unknown => 0.6,
        UserActivity::Light => 0.4,
        UserActivity::Active => 0.05,
    };
    let trust = match trust {
        TrustLevel::Unverified => 0.5,
        TrustLevel::Paired => 0.8,
        TrustLevel::HardwareAttested => 1.0,
    };
    Components {
        energy,
        thermal: v.thermal_headroom.clamp(0.0, 1.0),
        compute,
        memory,
        network: kind * metered * rtt,
        idle,
        cost: 1.0 / (1.0 + v.cost.max(0.0)),
        trust,
    }
}

fn gates(f: &FragmentSpec, n: &NodeView, p: &Protection) -> Vec<Gate> {
    let v = &n.vector;
    let mut g = Vec::new();
    for c in &f.requires {
        if !v.has(c) {
            g.push(Gate::MissingCapability(c.to_string()));
        }
    }
    if let Privacy::MustStayOn(tag) = &f.privacy {
        if !v.has(&Capability::LocalData(tag.clone())) {
            g.push(Gate::PrivacyLocality(tag.clone()));
        }
    }
    if let Some(loc) = &f.locality {
        let site_ok = loc.site.as_ref().is_none_or(|s| v.locality.site.as_ref() == Some(s));
        let lan_ok = loc.lan.as_ref().is_none_or(|l| v.locality.lan.as_ref() == Some(l));
        if !(site_ok && lan_ok) {
            g.push(Gate::LocalityMismatch);
        }
    }
    if n.trust < f.min_trust {
        g.push(Gate::InsufficientTrust);
    }
    if !f.ceiling.fits_within(&n.offer) {
        g.push(Gate::CeilingExceedsOffer);
    }
    if let TaskSpec::Exec { program, .. } = &f.task {
        if !n.allowed_programs.contains(program) {
            g.push(Gate::ProgramNotAllowed(program.clone()));
        }
    }
    if v.memory.available_mb < f.ceiling.memory_mb {
        g.push(Gate::InsufficientMemory);
    }
    if v.network.kind == NetworkKind::Offline {
        g.push(Gate::Offline);
    }
    g.extend(protection_gates(f.profile, v, p));
    if n.free_slots == 0 {
        g.push(Gate::NoFreeSlot);
    }
    g
}

/// Battery and thermal protection for running `profile` on a device in
/// state `v`. The scheduler uses this to gate placement and the node uses it
/// to preempt work in flight, so both sides apply one rule.
pub fn protection_gates(profile: WorkloadProfile, v: &CapabilityVector, p: &Protection) -> Vec<Gate> {
    let mut g = Vec::new();
    if !v.power.externally_powered() {
        let pct = v.power.battery_pct.unwrap_or(100.0);
        if pct < p.battery_critical_pct {
            g.push(Gate::BatteryCritical);
        } else if pct < p.battery_floor_pct && compute_heavy(profile) {
            g.push(Gate::BatteryLowForProfile);
        }
    }
    if v.thermal_headroom < p.thermal_critical {
        g.push(Gate::ThermalCritical);
    } else if v.thermal_headroom < p.thermal_floor && compute_heavy(profile) {
        g.push(Gate::ThermalLowForProfile);
    }
    g
}

/// Score one node for one fragment.
pub fn assess(f: &FragmentSpec, n: &NodeView, p: &Protection) -> Assessment {
    let c = components(&n.vector, n.trust, &f.ceiling);
    let mut gates = gates(f, n, p);
    let score = if gates.is_empty() {
        let w = weights(f.profile);
        let vals = [c.energy, c.thermal, c.compute, c.memory, c.network, c.idle, c.cost, c.trust];
        let base: f32 = w.iter().zip(vals).map(|(w, v)| w * v).sum();
        // Compute-heavy work must not steal from a user or a draining battery:
        // energy and idleness act multiplicatively, not just additively.
        let protect = if compute_heavy(f.profile) { c.energy * c.idle } else { 1.0 };
        (base * protect).clamp(0.0, 1.0)
    } else {
        0.0
    };
    if gates.is_empty() && score < p.promotion_threshold {
        gates.push(Gate::BelowPromotionThreshold);
    }
    Assessment { node_id: n.node_id, fragment_id: f.id.clone(), score, gates, components: c }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn vector() -> CapabilityVector {
        CapabilityVector {
            power: PowerState::mains(),
            thermal_headroom: 0.9,
            network: NetworkState { kind: NetworkKind::Wifi, metered: false, rtt_ms: Some(20) },
            compute: ComputeState { logical_cpus: 8, busy: 0.1, relative_perf: 0.6 },
            memory: MemoryState { total_mb: 8192, available_mb: 4096 },
            capabilities: BTreeSet::new(),
            locality: Locality::default(),
            user_activity: UserActivity::Idle,
            cost: 0.0,
            observed_at: 0,
        }
    }

    pub fn node(v: CapabilityVector) -> NodeView {
        NodeView {
            node_id: NodeId::random(),
            vector: v,
            trust: TrustLevel::Paired,
            offer: ResourceCeiling::default(),
            allowed_programs: BTreeSet::new(),
            free_slots: 1,
        }
    }

    pub fn fragment(id: &str, profile: WorkloadProfile) -> FragmentSpec {
        FragmentSpec {
            id: id.into(),
            profile,
            requires: BTreeSet::new(),
            locality: None,
            privacy: Privacy::Anywhere,
            min_trust: TrustLevel::Unverified,
            ceiling: ResourceCeiling::default(),
            task: TaskSpec::Builtin(BuiltinTask::Echo { payload: "x".into() }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn drained_active_camera_phone() -> NodeView {
        let mut v = vector();
        v.power = PowerState::battery(18.0, false);
        v.user_activity = UserActivity::Active;
        v.network = NetworkState { kind: NetworkKind::Cellular, metered: true, rtt_ms: Some(80) };
        v.capabilities.insert(Capability::Camera);
        node(v)
    }

    fn charging_idle_phone() -> NodeView {
        let mut v = vector();
        v.power = PowerState::battery(64.0, true);
        node(v)
    }

    #[test]
    fn busy_drained_phone_scores_near_zero_for_compute() {
        let p = Protection::default();
        let compile = fragment("compile", WorkloadProfile::ComputeBound);
        let a = assess(&compile, &drained_active_camera_phone(), &p);
        assert!(a.score < 0.01, "score {}", a.score);
        assert_eq!(a.gates, vec![Gate::BelowPromotionThreshold]);
        let b = assess(&compile, &charging_idle_phone(), &p);
        assert!(b.score > 0.6, "score {}", b.score);
    }

    #[test]
    fn same_phone_stays_valuable_for_its_camera() {
        let p = Protection::default();
        let mut capture = fragment("capture", WorkloadProfile::SensorBound);
        capture.requires.insert(Capability::Camera);
        let a = assess(&capture, &drained_active_camera_phone(), &p);
        assert!(a.eligible());
        assert!(a.score > 0.3, "score {}", a.score);
        let b = assess(&capture, &charging_idle_phone(), &p);
        assert_eq!(b.gates, vec![Gate::MissingCapability("camera".into())]);
        assert_eq!(b.score, 0.0);
    }

    #[test]
    fn protection_gates_are_hard() {
        let p = Protection::default();
        let mut v = vector();
        v.power = PowerState::battery(10.0, false);
        let n = node(v.clone());
        let compile = fragment("c", WorkloadProfile::ComputeBound);
        assert_eq!(assess(&compile, &n, &p).gates, vec![Gate::BatteryLowForProfile]);
        // Light sensor work is still allowed at 10%...
        assert!(assess(&fragment("s", WorkloadProfile::SensorBound), &n, &p).eligible());
        // ...but nothing at 3%.
        v.power = PowerState::battery(3.0, false);
        let n = node(v.clone());
        assert_eq!(assess(&fragment("s", WorkloadProfile::SensorBound), &n, &p).gates, vec![Gate::BatteryCritical]);
        // Charging lifts battery gates entirely.
        v.power = PowerState::battery(3.0, true);
        assert!(assess(&compile, &node(v.clone()), &p).eligible());
        // Thermal.
        v.thermal_headroom = 0.1;
        assert_eq!(assess(&compile, &node(v.clone()), &p).gates, vec![Gate::ThermalLowForProfile]);
        v.thermal_headroom = 0.01;
        assert_eq!(
            assess(&fragment("m", WorkloadProfile::Monitoring), &node(v), &p).gates,
            vec![Gate::ThermalCritical]
        );
    }

    #[test]
    fn privacy_trust_locality_ceiling_program_gates() {
        let p = Protection::default();
        let mut f = fragment("f", WorkloadProfile::CredentialBound);
        f.privacy = Privacy::MustStayOn("health".into());
        f.min_trust = TrustLevel::HardwareAttested;
        f.locality = Some(LocalityConstraint { site: Some("home".into()), lan: None });
        f.ceiling.wall_ms = 10_000_000;
        f.task = TaskSpec::Exec { program: "/usr/bin/true".into(), args: vec![], stdin: None };
        let n = node(vector());
        let gates = assess(&f, &n, &p).gates;
        assert!(gates.contains(&Gate::PrivacyLocality("health".into())));
        assert!(gates.contains(&Gate::InsufficientTrust));
        assert!(gates.contains(&Gate::LocalityMismatch));
        assert!(gates.contains(&Gate::CeilingExceedsOffer));
        assert!(gates.contains(&Gate::ProgramNotAllowed("/usr/bin/true".into())));

        let mut v = vector();
        v.capabilities.insert(Capability::LocalData("health".into()));
        v.locality.site = Some("home".into());
        let mut n = node(v);
        n.trust = TrustLevel::HardwareAttested;
        n.offer.wall_ms = u64::MAX;
        n.allowed_programs.insert("/usr/bin/true".into());
        assert!(assess(&f, &n, &p).eligible());
    }

    #[test]
    fn scores_are_bounded() {
        let p = Protection::default();
        for profile in [
            WorkloadProfile::ComputeBound,
            WorkloadProfile::ParallelLowRelational,
            WorkloadProfile::SensorBound,
            WorkloadProfile::CredentialBound,
            WorkloadProfile::NetworkBound,
            WorkloadProfile::Monitoring,
        ] {
            let s = assess(&fragment("f", profile), &node(vector()), &p).score;
            assert!((0.0..=1.0).contains(&s));
            assert!(s > 0.5, "{profile:?} {s}");
        }
    }
}
