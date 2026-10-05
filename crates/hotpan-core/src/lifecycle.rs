//! The transient-node lifecycle every lease walks:
//!
//! `observe → score → promote → provision → execute → attest → return → purge → dissolve`
//!
//! Abnormal exits (node vanished, preempted by battery/thermal protection,
//! lease expiry, rejection) go through `Revoked`, which still ends in
//! `Dissolved`: authority is always dissolved, never left dangling.

use crate::Millis;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Observed,
    Scored,
    Promoted,
    Provisioned,
    Executing,
    Attested,
    Returned,
    Revoked,
    Purged,
    Dissolved,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason", content = "detail")]
pub enum RevokeReason {
    /// The node disappeared (disconnect or missed heartbeats).
    NodeLost,
    /// The node's own protection (battery/thermal) stopped the work.
    Preempted(String),
    /// The lease outlived its expiry.
    Expired,
    /// The node refused the lease.
    Rejected(String),
    /// The result failed verification (bad attestation or envelope).
    BadResult(String),
    /// The task ran and failed on the node.
    TaskFailed(String),
    /// An operator or the control plane withdrew it.
    Withdrawn,
}

impl Phase {
    pub fn is_terminal(self) -> bool {
        self == Phase::Dissolved
    }

    /// Whether the node currently holds live authority under this lease.
    pub fn holds_authority(self) -> bool {
        matches!(self, Phase::Promoted | Phase::Provisioned | Phase::Executing | Phase::Attested)
    }

    pub fn can_advance_to(self, to: Phase) -> bool {
        use Phase::*;
        match (self, to) {
            (Observed, Scored)
            | (Scored, Promoted)
            | (Promoted, Provisioned)
            | (Provisioned, Executing)
            | (Executing, Attested)
            | (Attested, Returned)
            | (Returned, Purged)
            | (Purged, Dissolved) => true,
            // Not selected: nothing was ever granted.
            (Observed | Scored, Dissolved) => true,
            // Abnormal exits from anywhere authority may exist.
            (Promoted | Provisioned | Executing | Attested | Returned, Revoked) => true,
            // A revoked lease is purged if the node is reachable, else dissolved.
            (Revoked, Purged | Dissolved) => true,
            // Node vanished after return but before confirming purge.
            (Returned, Dissolved) => true,
            _ => false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("illegal lifecycle transition {from:?} -> {to:?}")]
pub struct LifecycleError {
    pub from: Phase,
    pub to: Phase,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Lifecycle {
    pub phase: Phase,
    pub history: Vec<(Phase, Millis)>,
    pub revoke_reason: Option<RevokeReason>,
}

impl Lifecycle {
    pub fn new(now: Millis) -> Self {
        Self { phase: Phase::Observed, history: vec![(Phase::Observed, now)], revoke_reason: None }
    }

    pub fn advance(&mut self, to: Phase, now: Millis) -> Result<(), LifecycleError> {
        if !self.phase.can_advance_to(to) {
            return Err(LifecycleError { from: self.phase, to });
        }
        self.phase = to;
        self.history.push((to, now));
        Ok(())
    }

    pub fn revoke(&mut self, reason: RevokeReason, now: Millis) -> Result<(), LifecycleError> {
        self.advance(Phase::Revoked, now)?;
        self.revoke_reason = Some(reason);
        Ok(())
    }

    pub fn phases(&self) -> Vec<Phase> {
        self.history.iter().map(|(p, _)| *p).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Phase::*;

    #[test]
    fn happy_path_is_the_nine_steps() {
        let mut l = Lifecycle::new(0);
        for (i, p) in
            [Scored, Promoted, Provisioned, Executing, Attested, Returned, Purged, Dissolved].into_iter().enumerate()
        {
            l.advance(p, i as u64 + 1).unwrap();
        }
        assert_eq!(
            l.phases(),
            vec![Observed, Scored, Promoted, Provisioned, Executing, Attested, Returned, Purged, Dissolved]
        );
        assert!(l.phase.is_terminal());
    }

    #[test]
    fn cannot_skip_attestation_or_resurrect() {
        let mut l = Lifecycle::new(0);
        l.advance(Scored, 1).unwrap();
        l.advance(Promoted, 2).unwrap();
        l.advance(Provisioned, 3).unwrap();
        l.advance(Executing, 4).unwrap();
        assert!(l.advance(Returned, 5).is_err());
        l.revoke(RevokeReason::NodeLost, 5).unwrap();
        assert!(l.advance(Executing, 6).is_err());
        l.advance(Dissolved, 6).unwrap();
        assert!(l.advance(Observed, 7).is_err());
        assert_eq!(l.revoke_reason, Some(RevokeReason::NodeLost));
    }

    #[test]
    fn authority_only_while_live() {
        assert!(!Observed.holds_authority());
        assert!(Executing.holds_authority());
        assert!(!Revoked.holds_authority());
        assert!(!Dissolved.holds_authority());
    }
}
