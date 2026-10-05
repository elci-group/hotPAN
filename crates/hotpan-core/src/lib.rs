//! hotPAN core model.
//!
//! hotPAN (Heuristically Orchestrated Transient Phone-as-Node) treats a device
//! as a *transient* execution node: it is promoted into the fabric for exactly
//! as long as a workload fragment benefits from its participation, then its
//! authority is dissolved. This crate holds the vocabulary every other crate
//! shares: what a device can do ([`CapabilityVector`]), what work wants
//! ([`FragmentSpec`]), and the lifecycle a lease walks through ([`Lifecycle`]).

pub mod capability;
pub mod ids;
pub mod lifecycle;
pub mod vector;
pub mod workload;

pub use capability::Capability;
pub use ids::{JobId, LeaseId, NodeId};
pub use lifecycle::{Lifecycle, LifecycleError, Phase, RevokeReason};
pub use vector::*;
pub use workload::*;

/// Milliseconds since the Unix epoch. All hotPAN logic takes `now` explicitly
/// so the control plane can be driven deterministically in tests and sims.
pub type Millis = u64;

pub fn now_millis() -> Millis {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
