//! The hotPAN control plane.
//!
//! [`ControlPlane`] is a synchronous state machine: every input (a node
//! joining, a heartbeat, a result, the passage of time) is a method call with
//! an explicit `now`, and every output is a list of [`Outbound`] messages and
//! [`Event`]s. [`server::serve`] drives it over TCP; simulations and tests
//! drive it directly.
//!
//! It assumes nothing about node persistence. A node that misses heartbeats
//! is lost; its leases are revoked and their fragments rescheduled elsewhere.

#![forbid(unsafe_code)]
// No panics reachable from peer input (DIRECTIVE P1.6): fallible paths
// return errors; the few infallible serializations carry a local allow.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod plane;
pub mod server;

pub use plane::{ControlPlane, Event, EventKind, Outbound, PlaneConfig, SubmitError};
