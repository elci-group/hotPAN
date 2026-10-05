//! Validation of everything a peer can send (DIRECTIVE P4: bounded).
//!
//! Every advertisement, heartbeat vector and job spec that crosses the wire
//! is checked against [`Limits`] before the control plane acts on it. The
//! limits are deliberately generous for legitimate use but small enough
//! that no single message can exhaust memory or make a later step (such as
//! fitting a result into one frame) impossible.

use crate::*;

/// Hard input bounds. The defaults are the protocol's limits; operators may
/// tighten them, but they are never relaxed past what fits in one frame.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_label: usize,
    pub max_token: usize,
    pub max_capabilities: usize,
    pub max_programs: usize,
    pub max_path: usize,
    pub max_fragments: usize,
    pub max_args: usize,
    pub max_arg: usize,
    pub max_inline_bytes: usize,
    pub max_wall_ms: u64,
    pub max_memory_mb: u64,
    /// Captured output per lease. It must still fit in one result frame after
    /// worst-case JSON escaping (6x) and hex sealing (2x), so it stays well
    /// below `MAX_FRAME / 12`.
    pub max_output_bytes: u64,
    pub max_leases_per_node: u32,
    pub max_cpus: u32,
    pub max_prime_upto: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_label: 64,
            max_token: 128,
            max_capabilities: 64,
            max_programs: 256,
            max_path: 4096,
            max_fragments: 1024,
            max_args: 256,
            max_arg: 4096,
            max_inline_bytes: 256 << 10,
            max_wall_ms: 24 * 3600 * 1000,
            max_memory_mb: 1 << 20,
            max_output_bytes: 512 << 10,
            max_leases_per_node: 64,
            max_cpus: 4096,
            max_prime_upto: 10_000_000_000,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid {field}: {reason}")]
pub struct Invalid {
    pub field: String,
    pub reason: String,
}

fn bad(field: impl Into<String>, reason: impl Into<String>) -> Invalid {
    Invalid { field: field.into(), reason: reason.into() }
}

fn printable(field: &str, s: &str, max: usize) -> Result<(), Invalid> {
    if s.is_empty() {
        return Err(bad(field, "empty"));
    }
    if s.len() > max {
        return Err(bad(field, format!("longer than {max} bytes")));
    }
    if s.chars().any(char::is_control) {
        return Err(bad(field, "contains control characters"));
    }
    Ok(())
}

/// Fragment ids end up in events, file names and logs: keep them boring.
fn identifier(field: &str, s: &str, max: usize) -> Result<(), Invalid> {
    printable(field, s, max)?;
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(bad(field, "only [A-Za-z0-9._-] allowed"));
    }
    Ok(())
}

fn unit(field: &str, v: f32) -> Result<(), Invalid> {
    if !v.is_finite() || !(0.0..=1.0).contains(&v) {
        return Err(bad(field, "must be a finite number in 0..=1"));
    }
    Ok(())
}

fn range(field: &str, v: f32, lo: f32, hi: f32) -> Result<(), Invalid> {
    if !v.is_finite() || v < lo || v > hi {
        return Err(bad(field, format!("must be a finite number in {lo}..={hi}")));
    }
    Ok(())
}

fn hex32(field: &str, s: &str) -> Result<(), Invalid> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(field, "must be 64 hex characters"));
    }
    Ok(())
}

fn capability(field: &str, c: &Capability, l: &Limits) -> Result<(), Invalid> {
    match c {
        Capability::LocalData(t) | Capability::Session(t) => identifier(field, t, l.max_token),
        _ => Ok(()),
    }
}

impl ResourceCeiling {
    pub fn validate(&self, field: &str, l: &Limits) -> Result<(), Invalid> {
        let c = self;
        if c.wall_ms == 0 || c.cpu_ms == 0 || c.memory_mb == 0 || c.output_bytes == 0 {
            return Err(bad(field, "every ceiling must be non-zero"));
        }
        if c.wall_ms > l.max_wall_ms || c.cpu_ms > l.max_wall_ms {
            return Err(bad(field, format!("time ceilings above {}ms", l.max_wall_ms)));
        }
        if c.memory_mb > l.max_memory_mb {
            return Err(bad(field, "memory ceiling too large"));
        }
        if c.output_bytes > l.max_output_bytes {
            return Err(bad(field, format!("output ceiling above {} bytes", l.max_output_bytes)));
        }
        Ok(())
    }
}

impl CapabilityVector {
    pub fn validate(&self, l: &Limits) -> Result<(), Invalid> {
        if let Some(p) = self.power.battery_pct {
            range("power.battery_pct", p, 0.0, 100.0)?;
        }
        unit("thermal_headroom", self.thermal_headroom)?;
        unit("compute.busy", self.compute.busy)?;
        range("compute.relative_perf", self.compute.relative_perf, 0.0, 100.0)?;
        if self.compute.logical_cpus == 0 || self.compute.logical_cpus > l.max_cpus {
            return Err(bad("compute.logical_cpus", format!("must be 1..={}", l.max_cpus)));
        }
        if self.memory.available_mb > self.memory.total_mb || self.memory.total_mb > l.max_memory_mb {
            return Err(bad("memory", "available exceeds total, or total implausibly large"));
        }
        range("cost", self.cost, 0.0, 1e6)?;
        if self.capabilities.len() > l.max_capabilities {
            return Err(bad("capabilities", format!("more than {}", l.max_capabilities)));
        }
        for c in &self.capabilities {
            capability("capabilities", c, l)?;
        }
        if let Some(s) = &self.locality.site {
            printable("locality.site", s, l.max_token)?;
        }
        if let Some(s) = &self.locality.lan {
            printable("locality.lan", s, l.max_token)?;
        }
        Ok(())
    }
}

impl Advertisement {
    pub fn validate(&self, l: &Limits) -> Result<(), Invalid> {
        printable("label", &self.label, l.max_label)?;
        hex32("signing_key", &self.signing_key)?;
        hex32("kex_key", &self.kex_key)?;
        self.vector.validate(l)?;
        self.offer.validate("offer", l)?;
        if self.max_leases == 0 || self.max_leases > l.max_leases_per_node {
            return Err(bad("max_leases", format!("must be 1..={}", l.max_leases_per_node)));
        }
        if self.allowed_programs.len() > l.max_programs {
            return Err(bad("allowed_programs", format!("more than {}", l.max_programs)));
        }
        for p in &self.allowed_programs {
            printable("allowed_programs", p, l.max_path)?;
            if !p.starts_with('/') {
                return Err(bad("allowed_programs", "must be absolute paths"));
            }
        }
        Ok(())
    }
}

impl FragmentSpec {
    pub fn validate_with(&self, l: &Limits) -> Result<(), Invalid> {
        let f = format!("fragment `{}`", self.id.chars().take(32).collect::<String>());
        identifier("fragment id", &self.id, l.max_token)?;
        self.ceiling.validate(&f, l)?;
        if self.requires.len() > l.max_capabilities {
            return Err(bad(&f, "too many required capabilities"));
        }
        for c in &self.requires {
            capability(&f, c, l)?;
        }
        if let Privacy::MustStayOn(tag) = &self.privacy {
            identifier(&f, tag, l.max_token)?;
        }
        if let Some(loc) = &self.locality {
            for s in [&loc.site, &loc.lan].into_iter().flatten() {
                printable(&f, s, l.max_token)?;
            }
        }
        match &self.task {
            TaskSpec::Exec { program, args, stdin } => {
                printable(&f, program, l.max_path)?;
                if !program.starts_with('/') {
                    return Err(bad(&f, "exec program must be an absolute path"));
                }
                if args.len() > l.max_args || args.iter().any(|a| a.len() > l.max_arg) {
                    return Err(bad(&f, "too many or too long arguments"));
                }
                if stdin.as_ref().is_some_and(|s| s.len() > l.max_inline_bytes) {
                    return Err(bad(&f, "stdin too large"));
                }
            }
            TaskSpec::Builtin(b) => match b {
                BuiltinTask::Echo { payload: d } | BuiltinTask::Blake3 { data: d } if d.len() > l.max_inline_bytes => {
                    return Err(bad(&f, "inline data too large"));
                }
                BuiltinTask::PrimeCount { upto } if *upto > l.max_prime_upto => {
                    return Err(bad(&f, "prime_count bound too large"));
                }
                BuiltinTask::Sleep { ms } if *ms > self.ceiling.wall_ms => {
                    return Err(bad(&f, "sleep longer than its wall ceiling"));
                }
                _ => {}
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    pub(crate) fn vector() -> CapabilityVector {
        CapabilityVector {
            power: PowerState::battery(50.0, false),
            thermal_headroom: 0.5,
            network: NetworkState { kind: NetworkKind::Wifi, metered: false, rtt_ms: None },
            compute: ComputeState { logical_cpus: 8, busy: 0.1, relative_perf: 0.5 },
            memory: MemoryState { total_mb: 4096, available_mb: 1024 },
            capabilities: BTreeSet::new(),
            locality: Locality::default(),
            user_activity: UserActivity::Idle,
            cost: 0.0,
            observed_at: 0,
        }
    }

    fn advert() -> Advertisement {
        Advertisement {
            node_id: NodeId::random(),
            label: "phone".into(),
            device_class: DeviceClass::Phone,
            vector: vector(),
            signing_key: "a".repeat(64),
            kex_key: "b".repeat(64),
            offer: ResourceCeiling::default(),
            max_leases: 1,
            allowed_programs: BTreeSet::from(["/bin/sh".to_string()]),
        }
    }

    #[test]
    fn rejects_hostile_vectors() {
        let l = Limits::default();
        assert!(vector().validate(&l).is_ok());
        for f in [f32::NAN, f32::INFINITY, -0.1, 1.5] {
            let mut v = vector();
            v.thermal_headroom = f;
            assert!(v.validate(&l).is_err(), "{f}");
        }
        let mut v = vector();
        v.power.battery_pct = Some(f32::NAN);
        assert!(v.validate(&l).is_err());
        let mut v = vector();
        v.compute.logical_cpus = 0;
        assert!(v.validate(&l).is_err());
        let mut v = vector();
        v.capabilities = (0..100).map(|i| Capability::LocalData(format!("t{i}"))).collect();
        assert!(v.validate(&l).is_err());
        let mut v = vector();
        v.capabilities.insert(Capability::LocalData("bad tag\n".into()));
        assert!(v.validate(&l).is_err());
    }

    #[test]
    fn rejects_hostile_adverts() {
        let l = Limits::default();
        assert!(advert().validate(&l).is_ok());
        let mut a = advert();
        a.label = "x".repeat(65);
        assert!(a.validate(&l).is_err());
        let mut a = advert();
        a.label = "evil\u{1b}[2J".into();
        assert!(a.validate(&l).is_err());
        let mut a = advert();
        a.kex_key = "zz".into();
        assert!(a.validate(&l).is_err());
        let mut a = advert();
        a.max_leases = 10_000;
        assert!(a.validate(&l).is_err());
        let mut a = advert();
        a.allowed_programs.insert("relative/prog".into());
        assert!(a.validate(&l).is_err());
        let mut a = advert();
        a.offer.output_bytes = 100 << 20;
        assert!(a.validate(&l).is_err());
    }

    #[test]
    fn default_output_ceiling_fits_a_frame() {
        let l = Limits::default();
        // 6x JSON escaping, 2x hex, plus stderr and envelope overhead.
        assert!(l.max_output_bytes * 12 + (1 << 20) <= 8 << 20);
        assert!(ResourceCeiling::default().validate("d", &l).is_ok());
    }
}
