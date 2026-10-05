//! Planner invariants under arbitrary fleets and workloads (DIRECTIVE P1.7).

use crate::*;
use hotpan_core::*;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

fn arb_node() -> impl Strategy<Value = NodeView> {
    (0.0f32..100.0, any::<bool>(), 0.0f32..1.0, 1u32..32, 0.0f32..1.0, 0u32..4, any::<bool>(), 0u8..4).prop_map(
        |(pct, charging, thermal, cpus, busy, slots, camera, activity)| {
            let mut caps = BTreeSet::new();
            if camera {
                caps.insert(Capability::Camera);
            }
            NodeView {
                node_id: NodeId::random(),
                vector: CapabilityVector {
                    power: PowerState::battery(pct, charging),
                    thermal_headroom: thermal,
                    network: NetworkState { kind: NetworkKind::Wifi, metered: false, rtt_ms: Some(10) },
                    compute: ComputeState { logical_cpus: cpus, busy, relative_perf: 0.7 },
                    memory: MemoryState { total_mb: 8192, available_mb: 4096 },
                    capabilities: caps,
                    locality: Locality::default(),
                    user_activity: [
                        UserActivity::Idle,
                        UserActivity::Light,
                        UserActivity::Active,
                        UserActivity::Unknown,
                    ][activity as usize],
                    cost: 0.0,
                    observed_at: 0,
                },
                trust: TrustLevel::Paired,
                offer: ResourceCeiling::default(),
                allowed_programs: BTreeSet::new(),
                free_slots: slots,
            }
        },
    )
}

fn arb_fragment(i: usize) -> impl Strategy<Value = FragmentSpec> {
    (0u8..6, any::<bool>()).prop_map(move |(p, camera)| FragmentSpec {
        id: format!("f{i}"),
        profile: [
            WorkloadProfile::ComputeBound,
            WorkloadProfile::ParallelLowRelational,
            WorkloadProfile::SensorBound,
            WorkloadProfile::CredentialBound,
            WorkloadProfile::NetworkBound,
            WorkloadProfile::Monitoring,
        ][p as usize],
        requires: if camera { BTreeSet::from([Capability::Camera]) } else { BTreeSet::new() },
        locality: None,
        privacy: Privacy::Anywhere,
        min_trust: TrustLevel::Unverified,
        ceiling: ResourceCeiling::default(),
        task: TaskSpec::Builtin(BuiltinTask::Echo { payload: String::new() }),
    })
}

proptest! {
    #[test]
    fn plans_respect_slots_eligibility_and_exclusions(
        nodes in proptest::collection::vec(arb_node(), 0..8),
        frags in (0usize..12).prop_flat_map(|n| (0..n).map(arb_fragment).collect::<Vec<_>>()),
        exclude_mask in any::<u64>(),
    ) {
        let p = Protection::default();
        let items: Vec<PlanItem<'_>> = frags
            .iter()
            .enumerate()
            .map(|(i, f)| PlanItem {
                fragment: f,
                excluded: nodes.iter().enumerate()
                    .filter(|(j, _)| exclude_mask >> ((i * 3 + j) % 64) & 1 == 1)
                    .map(|(_, n)| n.node_id)
                    .collect(),
            })
            .collect();
        let plan = plan(&items, &nodes, &p);

        // Every fragment is either placed once or reported unplaced.
        prop_assert_eq!(plan.assignments.len() + plan.unplaced.len(), items.len());
        let placed: BTreeSet<usize> = plan.assignments.iter().map(|a| a.item).collect();
        prop_assert_eq!(placed.len(), plan.assignments.len());

        let mut per_node: BTreeMap<NodeId, u32> = BTreeMap::new();
        for a in &plan.assignments {
            *per_node.entry(a.node_id).or_default() += 1;
            let node = nodes.iter().find(|n| n.node_id == a.node_id).unwrap();
            // Assigned nodes passed every gate (slots aside) and are not excluded.
            let mut probe = node.clone();
            probe.free_slots = 1;
            prop_assert!(assess(items[a.item].fragment, &probe, &p).eligible());
            prop_assert!(!items[a.item].excluded.contains(&a.node_id));
            prop_assert!((0.0..=1.0).contains(&a.score));
        }
        for (id, used) in per_node {
            let slots = nodes.iter().find(|n| n.node_id == id).unwrap().free_slots;
            prop_assert!(used <= slots);
        }
    }
}
