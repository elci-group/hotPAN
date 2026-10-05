//! Comparative-advantage assignment.
//!
//! Fragments are placed scarcest-first (fewest eligible nodes), and each
//! placement pays an opportunity cost: taking a node that is one of very few
//! able to serve some other pending fragment is discounted. This keeps the
//! only camera-bearing phone free for the capture fragment even when it is
//! also the fastest compiler in the room.

use crate::score::{assess, Assessment, Gate, NodeView, Protection};
use hotpan_core::{FragmentSpec, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A fragment awaiting placement, with nodes it must not go to again.
#[derive(Clone, Debug)]
pub struct PlanItem<'a> {
    pub fragment: &'a FragmentSpec,
    pub excluded: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assignment {
    /// Index into the `items` passed to [`plan`].
    pub item: usize,
    pub fragment_id: String,
    pub node_id: NodeId,
    pub score: f32,
    pub assessment: Assessment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unplaced {
    pub item: usize,
    pub fragment_id: String,
    /// Every distinct gate that blocked some node, for explanation.
    pub blocking: BTreeSet<Gate>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Plan {
    pub assignments: Vec<Assignment>,
    pub unplaced: Vec<Unplaced>,
}

/// Opportunity-cost weight: how strongly to protect scarce nodes.
const LAMBDA: f32 = 0.6;

pub fn plan(items: &[PlanItem<'_>], nodes: &[NodeView], protection: &Protection) -> Plan {
    let mut slots: BTreeMap<NodeId, u32> = nodes.iter().map(|n| (n.node_id, n.free_slots)).collect();
    // Assess ignoring slot availability; slots are tracked by the planner.
    let matrix: Vec<Vec<Assessment>> = items
        .iter()
        .map(|it| {
            nodes
                .iter()
                .map(|n| {
                    let mut n = n.clone();
                    n.free_slots = n.free_slots.max(1);
                    assess(it.fragment, &n, protection)
                })
                .collect()
        })
        .collect();

    let usable = |fi: usize, ni: usize, slots: &BTreeMap<NodeId, u32>| -> bool {
        let a = &matrix[fi][ni];
        a.eligible() && !items[fi].excluded.contains(&a.node_id) && slots[&a.node_id] > 0
    };

    let mut pending: BTreeSet<usize> = (0..items.len()).collect();
    let mut out = Plan::default();

    loop {
        let candidates = |fi: usize, slots: &BTreeMap<NodeId, u32>| -> Vec<usize> {
            (0..nodes.len()).filter(|&ni| usable(fi, ni, slots)).collect()
        };
        // Scarcest placeable fragment first; ties broken by input order.
        let next = pending
            .iter()
            .map(|&fi| (fi, candidates(fi, &slots).len()))
            .filter(|&(_, n)| n > 0)
            .min_by_key(|&(fi, n)| (n, fi));
        let Some((fi, _)) = next else { break };
        pending.remove(&fi);

        let best = candidates(fi, &slots)
            .into_iter()
            .map(|ni| {
                let own = matrix[fi][ni].score;
                // What would the rest of the job lose if we spent this node here?
                let opportunity = pending
                    .iter()
                    .filter(|&&other| usable(other, ni, &slots))
                    .map(|&other| {
                        let alternatives = candidates(other, &slots).len() as f32;
                        let remaining_slots = slots[&nodes[ni].node_id] as f32;
                        // Only a real cost when this node is (nearly) the
                        // only way to serve `other` and has no spare slot.
                        matrix[other][ni].score / alternatives / remaining_slots
                    })
                    .fold(0.0_f32, f32::max);
                (ni, own - LAMBDA * opportunity, own)
            })
            .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(&a.0)));

        if let Some((ni, _, own)) = best {
            let id = nodes[ni].node_id;
            *slots.get_mut(&id).unwrap() -= 1;
            out.assignments.push(Assignment {
                item: fi,
                fragment_id: items[fi].fragment.id.clone(),
                node_id: id,
                score: own,
                assessment: matrix[fi][ni].clone(),
            });
        }
    }

    for fi in pending {
        let mut blocking: BTreeSet<Gate> = matrix[fi].iter().flat_map(|a| a.gates.iter().cloned()).collect();
        if blocking.is_empty() {
            blocking.insert(Gate::NoFreeSlot);
        }
        out.unplaced.push(Unplaced { item: fi, fragment_id: items[fi].fragment.id.clone(), blocking });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::fixtures::*;
    use hotpan_core::*;

    fn items(fs: &[FragmentSpec]) -> Vec<PlanItem<'_>> {
        fs.iter().map(|f| PlanItem { fragment: f, excluded: BTreeSet::new() }).collect()
    }

    #[test]
    fn scarce_capability_is_preserved_for_its_fragment() {
        // X has a camera AND is the fastest compiler; Y can only compile.
        let mut vx = vector();
        vx.capabilities.insert(Capability::Camera);
        vx.compute.logical_cpus = 16;
        let x = node(vx);
        let mut vy = vector();
        vy.compute.logical_cpus = 4;
        let y = node(vy);

        let compile = fragment("compile", WorkloadProfile::ComputeBound);
        let mut capture = fragment("capture", WorkloadProfile::SensorBound);
        capture.requires.insert(Capability::Camera);
        // Compile listed first: a naive greedy would hand it X and strand capture.
        let fs = vec![compile, capture];
        let p = plan(&items(&fs), &[x.clone(), y.clone()], &Protection::default());
        assert!(p.unplaced.is_empty(), "{:?}", p.unplaced);
        let by: BTreeMap<_, _> = p.assignments.iter().map(|a| (a.fragment_id.as_str(), a.node_id)).collect();
        assert_eq!(by["capture"], x.node_id);
        assert_eq!(by["compile"], y.node_id);
    }

    #[test]
    fn opportunity_cost_steers_away_from_scarce_nodes() {
        // Three fragments: two generic, one camera. X (camera, fast, 2 slots),
        // Y (no camera, slower, 1 slot). Placement must still fit everything.
        let mut vx = vector();
        vx.capabilities.insert(Capability::Camera);
        vx.compute.logical_cpus = 16;
        let mut x = node(vx);
        x.free_slots = 2;
        let y = node(vector());
        let mut capture = fragment("capture", WorkloadProfile::SensorBound);
        capture.requires.insert(Capability::Camera);
        let fs =
            vec![fragment("a", WorkloadProfile::ComputeBound), fragment("b", WorkloadProfile::ComputeBound), capture];
        let p = plan(&items(&fs), &[x.clone(), y], &Protection::default());
        assert!(p.unplaced.is_empty());
        assert_eq!(p.assignments.len(), 3);
        let on_x = p.assignments.iter().filter(|a| a.node_id == x.node_id).count();
        assert_eq!(on_x, 2);
    }

    #[test]
    fn exclusions_and_unplaceable_are_reported() {
        let n = node(vector());
        let mut capture = fragment("capture", WorkloadProfile::SensorBound);
        capture.requires.insert(Capability::Camera);
        let compile = fragment("compile", WorkloadProfile::ComputeBound);
        let mut its = items(std::slice::from_ref(&compile));
        its[0].excluded.insert(n.node_id);
        let p = plan(&its, std::slice::from_ref(&n), &Protection::default());
        assert!(p.assignments.is_empty());
        assert_eq!(p.unplaced[0].blocking, BTreeSet::from([Gate::NoFreeSlot]));

        let fs = vec![capture];
        let p = plan(&items(&fs), &[n], &Protection::default());
        assert_eq!(p.unplaced[0].blocking, BTreeSet::from([Gate::MissingCapability("camera".into())]));
    }

    #[test]
    fn slots_are_respected() {
        let n = node(vector());
        let fs = vec![fragment("a", WorkloadProfile::ComputeBound), fragment("b", WorkloadProfile::ComputeBound)];
        let p = plan(&items(&fs), &[n], &Protection::default());
        assert_eq!(p.assignments.len(), 1);
        assert_eq!(p.unplaced.len(), 1);
    }
}
