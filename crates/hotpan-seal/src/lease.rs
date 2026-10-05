use crate::keys::verify;
use crate::{Keypair, SealError};
use hotpan_core::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One permission a lease confers. A node executes a task only if every
/// permission the task needs appears in the lease's scope list.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", tag = "scope", content = "value")]
pub enum Scope {
    Builtin(String),
    Exec(String),
    Capability(Capability),
}

/// The minimal scope set for a fragment: its task plus its required capabilities.
pub fn scopes_for(f: &FragmentSpec) -> Vec<Scope> {
    let mut s = vec![match &f.task {
        TaskSpec::Builtin(b) => Scope::Builtin(b.name().to_string()),
        TaskSpec::Exec { program, .. } => Scope::Exec(program.clone()),
    }];
    s.extend(f.requires.iter().cloned().map(Scope::Capability));
    s.sort();
    s.dedup();
    s
}

pub fn task_permitted(task: &TaskSpec, scopes: &[Scope]) -> Result<(), String> {
    let needed = match task {
        TaskSpec::Builtin(b) => Scope::Builtin(b.name().to_string()),
        TaskSpec::Exec { program, .. } => Scope::Exec(program.clone()),
    };
    if scopes.contains(&needed) {
        Ok(())
    } else {
        Err(format!("task needs scope {needed:?} which the lease does not grant"))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease_id: LeaseId,
    pub job_id: JobId,
    pub fragment_id: String,
    pub node_id: NodeId,
    pub scopes: Vec<Scope>,
    pub ceiling: ResourceCeiling,
    /// Lets the node apply the same protection rule the scheduler used.
    pub profile: WorkloadProfile,
    pub issued_at: Millis,
    pub expires_at: Millis,
    /// Issuer's signing key (hex).
    pub issuer: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedLease {
    pub grant: LeaseGrant,
    pub signature: String,
}

const LEASE: &[u8] = b"hotpan/lease/v1\0";

impl LeaseGrant {
    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("lease grant serializes")
    }

    pub fn sign(self, issuer: &Keypair) -> SignedLease {
        let mut grant = self;
        grant.issuer = issuer.public().signing;
        let signature = issuer.sign(LEASE, &grant.bytes());
        SignedLease { grant, signature }
    }
}

/// Clock skew tolerated between control plane and node.
const SKEW_MS: u64 = 30_000;

impl SignedLease {
    /// Verify issuer, signature, binding and validity window.
    pub fn verify(&self, expected_issuer: &str, node: NodeId, now: Millis) -> Result<(), SealError> {
        if self.grant.issuer != expected_issuer {
            return Err(SealError::WrongIssuer);
        }
        verify(&self.grant.issuer, LEASE, &self.grant.bytes(), &self.signature)?;
        if self.grant.node_id != node {
            return Err(SealError::WrongNode);
        }
        if now + SKEW_MS < self.grant.issued_at {
            return Err(SealError::NotYetValid);
        }
        if now >= self.grant.expires_at {
            return Err(SealError::Expired(self.grant.expires_at));
        }
        Ok(())
    }
}

/// Revoked lease ids, remembered until their natural expiry.
#[derive(Default, Debug, Clone)]
pub struct RevocationList {
    revoked: BTreeMap<LeaseId, Millis>,
}

impl RevocationList {
    pub fn revoke(&mut self, id: LeaseId, expires_at: Millis) {
        self.revoked.insert(id, expires_at);
    }
    pub fn is_revoked(&self, id: &LeaseId) -> bool {
        self.revoked.contains_key(id)
    }
    /// Drop entries whose lease would have expired anyway.
    pub fn gc(&mut self, now: Millis) {
        self.revoked.retain(|_, exp| *exp + SKEW_MS > now);
    }
    pub fn len(&self) -> usize {
        self.revoked.len()
    }
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn grant(node: NodeId) -> LeaseGrant {
        LeaseGrant {
            lease_id: LeaseId::random(),
            job_id: JobId::random(),
            fragment_id: "f".into(),
            node_id: node,
            scopes: vec![Scope::Builtin("echo".into())],
            ceiling: ResourceCeiling::default(),
            profile: WorkloadProfile::ComputeBound,
            issued_at: 1_000_000,
            expires_at: 1_060_000,
            issuer: String::new(),
        }
    }

    #[test]
    fn lease_verification() {
        let orch = Keypair::generate();
        let node = NodeId::random();
        let l = grant(node).sign(&orch);
        let issuer = orch.public().signing;
        l.verify(&issuer, node, 1_000_001).unwrap();
        assert_eq!(l.verify(&issuer, NodeId::random(), 1_000_001), Err(SealError::WrongNode));
        assert_eq!(l.verify(&issuer, node, 1_060_000), Err(SealError::Expired(1_060_000)));
        assert_eq!(l.verify(&issuer, node, 1), Err(SealError::NotYetValid));
        let other = Keypair::generate();
        assert_eq!(l.verify(&other.public().signing, node, 1_000_001), Err(SealError::WrongIssuer));

        // Tampering with any field breaks the signature.
        let mut t = l.clone();
        t.grant.ceiling.memory_mb *= 100;
        assert_eq!(t.verify(&issuer, node, 1_000_001), Err(SealError::BadSignature));
        let mut t = l.clone();
        t.grant.scopes.push(Scope::Exec("/bin/sh".into()));
        assert_eq!(t.verify(&issuer, node, 1_000_001), Err(SealError::BadSignature));
    }

    #[test]
    fn scopes_are_minimal_and_enforced() {
        let f = FragmentSpec {
            id: "x".into(),
            profile: WorkloadProfile::SensorBound,
            requires: BTreeSet::from([Capability::Camera]),
            locality: None,
            privacy: Privacy::Anywhere,
            min_trust: TrustLevel::Unverified,
            ceiling: ResourceCeiling::default(),
            task: TaskSpec::Exec { program: "/usr/bin/termux-camera-photo".into(), args: vec![], stdin: None },
        };
        let s = scopes_for(&f);
        assert_eq!(s, vec![Scope::Exec("/usr/bin/termux-camera-photo".into()), Scope::Capability(Capability::Camera)]);
        assert!(task_permitted(&f.task, &s).is_ok());
        let sh = TaskSpec::Exec { program: "/bin/sh".into(), args: vec![], stdin: None };
        assert!(task_permitted(&sh, &s).is_err());
    }

    #[test]
    fn revocation_gc() {
        let mut r = RevocationList::default();
        let id = LeaseId::random();
        r.revoke(id, 100);
        assert!(r.is_revoked(&id));
        r.gc(100 + SKEW_MS + 1);
        assert!(r.is_empty());
    }
}
