//! Workloads are execution graphs of fragments. Node selection is
//! workload-relative: the question is never "is this phone powerful enough?"
//! but "is there a fragment for which this phone has comparative advantage?"

use crate::{Capability, TrustLevel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadProfile {
    /// Inference, compilation, tests, transcoding: wants sustained compute.
    #[default]
    ComputeBound,
    /// Highly parallel, low-relational map-style work.
    ParallelLowRelational,
    /// Needs a physical sensor (camera, mic, GPS...).
    SensorBound,
    /// Needs a credential, key, or session that only exists on the device.
    CredentialBound,
    /// Throughput/latency to the network matters most (sync, fetch).
    NetworkBound,
    /// Long-lived, light-touch observation.
    Monitoring,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "kind", content = "tag")]
pub enum Privacy {
    #[default]
    Anywhere,
    /// The fragment touches data tagged `tag` and must run where it lives.
    MustStayOn(String),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct LocalityConstraint {
    pub site: Option<String>,
    pub lan: Option<String>,
}

/// Explicit resource ceiling for a single lease. Every lease carries one; the
/// node enforces it and refuses leases above what it offered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResourceCeiling {
    pub wall_ms: u64,
    pub cpu_ms: u64,
    pub memory_mb: u64,
    pub output_bytes: u64,
}

impl Default for ResourceCeiling {
    fn default() -> Self {
        Self { wall_ms: 30_000, cpu_ms: 30_000, memory_mb: 256, output_bytes: 1 << 20 }
    }
}

impl ResourceCeiling {
    /// True when every bound in `self` fits within `limit`.
    pub fn fits_within(&self, limit: &ResourceCeiling) -> bool {
        self.wall_ms <= limit.wall_ms
            && self.cpu_ms <= limit.cpu_ms
            && self.memory_mb <= limit.memory_mb
            && self.output_bytes <= limit.output_bytes
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum BuiltinTask {
    Echo {
        payload: String,
    },
    Blake3 {
        data: String,
    },
    /// Count primes `<= upto`. A portable, checkable compute kernel.
    PrimeCount {
        upto: u64,
    },
    /// Sleep for `ms`. Used to model long-running fragments.
    Sleep {
        ms: u64,
    },
}

impl BuiltinTask {
    pub fn name(&self) -> &'static str {
        match self {
            BuiltinTask::Echo { .. } => "echo",
            BuiltinTask::Blake3 { .. } => "blake3",
            BuiltinTask::PrimeCount { .. } => "prime_count",
            BuiltinTask::Sleep { .. } => "sleep",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TaskSpec {
    Builtin(BuiltinTask),
    Exec {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        stdin: Option<String>,
    },
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct FragmentSpec {
    pub id: String,
    #[serde(default)]
    pub profile: WorkloadProfile,
    #[serde(default)]
    pub requires: BTreeSet<Capability>,
    #[serde(default)]
    pub locality: Option<LocalityConstraint>,
    #[serde(default)]
    pub privacy: Privacy,
    #[serde(default)]
    pub min_trust: TrustLevel,
    #[serde(default)]
    pub ceiling: ResourceCeiling,
    pub task: TaskSpec,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct JobSpec {
    pub name: String,
    /// How many leases a fragment may burn through (nodes vanishing,
    /// preemption) before the fragment is declared failed.
    #[serde(default = "default_attempts")]
    pub max_attempts: u32,
    pub fragments: Vec<FragmentSpec>,
}

fn default_attempts() -> u32 {
    3
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SpecError {
    #[error("job has no fragments")]
    Empty,
    #[error("duplicate fragment id `{0}`")]
    DuplicateFragment(String),
    #[error("fragment `{0}` has a zero resource ceiling")]
    ZeroCeiling(String),
    #[error("max_attempts must be >= 1")]
    NoAttempts,
}

impl JobSpec {
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.fragments.is_empty() {
            return Err(SpecError::Empty);
        }
        if self.max_attempts == 0 {
            return Err(SpecError::NoAttempts);
        }
        let mut seen = BTreeSet::new();
        for f in &self.fragments {
            if !seen.insert(f.id.as_str()) {
                return Err(SpecError::DuplicateFragment(f.id.clone()));
            }
            let c = f.ceiling;
            if c.wall_ms == 0 || c.cpu_ms == 0 || c.memory_mb == 0 || c.output_bytes == 0 {
                return Err(SpecError::ZeroCeiling(f.id.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frag(id: &str) -> FragmentSpec {
        FragmentSpec {
            id: id.into(),
            profile: WorkloadProfile::ComputeBound,
            requires: BTreeSet::new(),
            locality: None,
            privacy: Privacy::Anywhere,
            min_trust: TrustLevel::Unverified,
            ceiling: ResourceCeiling::default(),
            task: TaskSpec::Builtin(BuiltinTask::Echo { payload: "x".into() }),
        }
    }

    #[test]
    fn validation_catches_bad_specs() {
        let mut job = JobSpec { name: "j".into(), max_attempts: 3, fragments: vec![] };
        assert_eq!(job.validate(), Err(SpecError::Empty));
        job.fragments = vec![frag("a"), frag("a")];
        assert_eq!(job.validate(), Err(SpecError::DuplicateFragment("a".into())));
        job.fragments = vec![frag("a")];
        job.fragments[0].ceiling.memory_mb = 0;
        assert_eq!(job.validate(), Err(SpecError::ZeroCeiling("a".into())));
        job.fragments[0].ceiling.memory_mb = 1;
        assert!(job.validate().is_ok());
    }

    #[test]
    fn ceiling_fit() {
        let small = ResourceCeiling { wall_ms: 1, cpu_ms: 1, memory_mb: 1, output_bytes: 1 };
        assert!(small.fits_within(&ResourceCeiling::default()));
        assert!(!ResourceCeiling::default().fits_within(&small));
    }
}
