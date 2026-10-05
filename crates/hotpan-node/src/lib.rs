//! The hotPAN node agent.
//!
//! A node session is transient by construction: it generates a fresh node id
//! and fresh session keys on connect, never persists them, and when the
//! control plane goes away it cancels and purges everything it holds. There
//! is no "resume": a reconnecting device is a new node.

mod agent;
mod client;
mod core;

pub use agent::{run_session, AgentConfig, AgentError, SessionEnd};
pub use client::{Client, ClientError};
pub use core::{advertisement, NodeCore, NodeIdentity, NodeSettings, Prepared, ProtectionGuard, Rejection};
