//! The capability vector: everything the heuristic orchestrator reasons over,
//! `H = f(battery, thermal_headroom, network, latency, compute, memory,
//! sensors, locality, trust, privacy, cost, user_activity)`.
//!
//! The orchestrator sees capabilities, not product categories; `DeviceClass`
//! is carried for humans and for coarse defaults only.

use crate::{Capability, Millis};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    #[default]
    Phone,
    Tablet,
    Laptop,
    Desktop,
    Tv,
    Console,
    Vehicle,
    HomeServer,
    EdgeAppliance,
    Other,
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct PowerState {
    /// Battery charge 0..=100, or `None` for mains-only devices.
    pub battery_pct: Option<f32>,
    pub charging: bool,
}

impl PowerState {
    pub fn mains() -> Self {
        Self { battery_pct: None, charging: true }
    }
    pub fn battery(pct: f32, charging: bool) -> Self {
        Self { battery_pct: Some(pct.clamp(0.0, 100.0)), charging }
    }
    /// True when the device is drawing from external power.
    pub fn externally_powered(&self) -> bool {
        self.battery_pct.is_none() || self.charging
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    Offline,
    Cellular,
    Wifi,
    Ethernet,
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct NetworkState {
    pub kind: NetworkKind,
    pub metered: bool,
    /// Round-trip latency to the control plane, when known.
    pub rtt_ms: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct ComputeState {
    pub logical_cpus: u32,
    /// Fraction of compute already in use, 0..=1 (load average / cpus).
    pub busy: f32,
    /// Per-core performance relative to a reference desktop core (1.0).
    pub relative_perf: f32,
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct MemoryState {
    pub total_mb: u64,
    pub available_mb: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct Locality {
    /// Operator-assigned physical site ("home", "office", "car").
    pub site: Option<String>,
    /// LAN segment identifier, if the node shares a LAN with others.
    pub lan: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    #[default]
    Unverified,
    /// Proved knowledge of the fabric pairing secret.
    Paired,
    /// Paired, and results are signed by a hardware-backed key.
    HardwareAttested,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserActivity {
    Idle,
    Light,
    Active,
    #[default]
    Unknown,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CapabilityVector {
    pub power: PowerState,
    /// Thermal headroom 0..=1: 1 is cold, 0 is at throttling/critical.
    pub thermal_headroom: f32,
    pub network: NetworkState,
    pub compute: ComputeState,
    pub memory: MemoryState,
    pub capabilities: BTreeSet<Capability>,
    pub locality: Locality,
    pub user_activity: UserActivity,
    /// Relative cost of using this node (0 = free). Metered links add to it.
    pub cost: f32,
    pub observed_at: Millis,
}

impl CapabilityVector {
    pub fn has(&self, c: &Capability) -> bool {
        self.capabilities.contains(c)
    }
}

/// What a device advertises when it offers itself to the fabric.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Advertisement {
    pub node_id: crate::NodeId,
    pub label: String,
    pub device_class: DeviceClass,
    pub vector: CapabilityVector,
    /// Session ed25519 verifying key (hex). Ephemeral: regenerated per session.
    pub signing_key: String,
    /// Session x25519 public key (hex) for sealed task envelopes.
    pub kex_key: String,
    /// Upper bounds this node is willing to accept for any single lease.
    pub offer: crate::ResourceCeiling,
    /// Concurrent leases this node will hold.
    pub max_leases: u32,
    /// Programs the node operator allows `exec` tasks to run.
    pub allowed_programs: BTreeSet<String>,
}
