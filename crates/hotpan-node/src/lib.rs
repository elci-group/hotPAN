//! The hotPAN node agent.
//!
//! A node session is transient by construction: it generates a fresh node id
//! and fresh session keys on connect, never persists them, and when the
//! control plane goes away it cancels and purges everything it holds. There
//! is no "resume": a reconnecting device is a new node.

#![forbid(unsafe_code)]
// No panics reachable from peer input (DIRECTIVE P1.6): fallible paths
// return errors; the few infallible serializations carry a local allow.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod agent;
mod client;
mod core;

pub use agent::{run_session, AgentConfig, AgentError, SessionEnd};
pub use client::{Client, ClientError};
pub use core::{advertisement, NodeCore, NodeIdentity, NodeSettings, Prepared, ProtectionGuard, Rejection};
