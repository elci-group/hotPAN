//! Heuristic orchestration: score every (node, fragment) pair, then assign
//! fragments to nodes by comparative advantage.
//!
//! Scoring is workload-relative. A phone at 18% battery that is in active use
//! scores near zero for compilation yet can be the *only* eligible node for a
//! camera capture. Protection gates (battery, thermal) are hard: no score can
//! buy its way past them.

#![forbid(unsafe_code)]

mod assign;
#[cfg(test)]
mod props;
mod score;

pub use assign::{plan, Assignment, Plan, PlanItem, Unplaced};
pub use score::{assess, protection_gates, Assessment, Components, Gate, NodeView, Protection};
