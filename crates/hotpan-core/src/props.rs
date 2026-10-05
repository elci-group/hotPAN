//! Property tests (DIRECTIVE P1.7): lifecycle invariants, parsing and
//! validation never panic on arbitrary input.

use crate::*;
use proptest::prelude::*;

const PHASES: [Phase; 10] = [
    Phase::Observed,
    Phase::Scored,
    Phase::Promoted,
    Phase::Provisioned,
    Phase::Executing,
    Phase::Attested,
    Phase::Returned,
    Phase::Revoked,
    Phase::Purged,
    Phase::Dissolved,
];

proptest! {
    /// Whatever sequence of transitions is attempted, the recorded history
    /// is always a legal path, dissolution is final, and authority never
    /// reappears after revocation.
    #[test]
    fn lifecycle_history_is_always_legal(attempts in proptest::collection::vec(0usize..10, 0..64)) {
        let mut l = Lifecycle::new(0);
        let mut revoked_seen = false;
        for (t, i) in attempts.into_iter().enumerate() {
            let before = l.phase;
            let ok = l.advance(PHASES[i], t as u64 + 1).is_ok();
            prop_assert_eq!(ok, before.can_advance_to(PHASES[i]));
            if before == Phase::Dissolved {
                prop_assert!(!ok);
            }
            revoked_seen |= l.phase == Phase::Revoked;
            if revoked_seen {
                prop_assert!(!l.phase.holds_authority());
            }
        }
        for w in l.history.windows(2) {
            prop_assert!(w[0].0.can_advance_to(w[1].0));
        }
    }

    #[test]
    fn capability_parsing_never_panics_and_round_trips(s in ".{0,40}") {
        if let Ok(c) = s.parse::<Capability>() {
            prop_assert_eq!(c.to_string().parse::<Capability>().ok(), Some(c));
        }
    }

    #[test]
    fn vector_validation_never_panics(
        battery in proptest::option::of(any::<f32>()),
        thermal in any::<f32>(),
        busy in any::<f32>(),
        perf in any::<f32>(),
        cost in any::<f32>(),
        cpus in any::<u32>(),
        total in any::<u64>(),
        avail in any::<u64>(),
    ) {
        let v = CapabilityVector {
            power: PowerState { battery_pct: battery, charging: false },
            thermal_headroom: thermal,
            network: NetworkState { kind: NetworkKind::Wifi, metered: false, rtt_ms: None },
            compute: ComputeState { logical_cpus: cpus, busy, relative_perf: perf },
            memory: MemoryState { total_mb: total, available_mb: avail },
            capabilities: Default::default(),
            locality: Locality::default(),
            user_activity: UserActivity::Unknown,
            cost,
            observed_at: 0,
        };
        if v.validate(&Limits::default()).is_ok() {
            prop_assert!(thermal.is_finite() && busy.is_finite() && cost.is_finite());
        }
    }

    /// Arbitrary JSON-ish text into a job spec: parse may fail, validation
    /// may fail, nothing panics.
    #[test]
    fn job_parsing_and_validation_never_panic(s in "\\PC{0,400}") {
        if let Ok(job) = serde_json::from_str::<JobSpec>(&s) {
            let _ = job.validate();
        }
    }
}
