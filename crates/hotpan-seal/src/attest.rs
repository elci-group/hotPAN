use crate::keys::verify;
use crate::{Keypair, SealError};
use hotpan_core::{LeaseId, NodeId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    /// Signed by the node's ephemeral session key. Proves the result came
    /// from the session that held the lease; does not prove the hardware.
    SessionKey,
}

/// A node's signed statement: "under lease L, for fragment F, I returned
/// exactly the bytes with digest D".
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub lease_id: LeaseId,
    pub fragment_id: String,
    pub node_id: NodeId,
    pub digest: String,
    pub kind: AttestationKind,
    pub signature: String,
}

const ATTEST: &[u8] = b"hotpan/attest/v1\0";

fn statement(lease: LeaseId, fragment: &str, node: NodeId, digest: &str) -> Vec<u8> {
    format!("{lease}\0{fragment}\0{node}\0{digest}").into_bytes()
}

pub fn attest(keys: &Keypair, lease_id: LeaseId, fragment_id: &str, node_id: NodeId, result: &[u8]) -> Attestation {
    let digest = blake3::hash(result).to_hex().to_string();
    let signature = keys.sign(ATTEST, &statement(lease_id, fragment_id, node_id, &digest));
    Attestation {
        lease_id,
        fragment_id: fragment_id.to_string(),
        node_id,
        digest,
        kind: AttestationKind::SessionKey,
        signature,
    }
}

impl Attestation {
    /// Verify against the node's advertised session key, the lease it should
    /// be bound to, and the actual result bytes.
    pub fn verify(
        &self,
        node_signing_key: &str,
        lease_id: LeaseId,
        fragment_id: &str,
        node_id: NodeId,
        result: &[u8],
    ) -> Result<(), SealError> {
        if self.lease_id != lease_id || self.fragment_id != fragment_id || self.node_id != node_id {
            return Err(SealError::AttestationMismatch);
        }
        verify(
            node_signing_key,
            ATTEST,
            &statement(self.lease_id, &self.fragment_id, self.node_id, &self.digest),
            &self.signature,
        )?;
        if blake3::hash(result).to_hex().as_str() != self.digest {
            return Err(SealError::DigestMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_binds_everything() {
        let k = Keypair::generate();
        let pk = k.public().signing;
        let (l, n) = (LeaseId::random(), NodeId::random());
        let a = attest(&k, l, "f", n, b"result");
        a.verify(&pk, l, "f", n, b"result").unwrap();
        assert_eq!(a.verify(&pk, l, "f", n, b"forged"), Err(SealError::DigestMismatch));
        assert_eq!(a.verify(&pk, LeaseId::random(), "f", n, b"result"), Err(SealError::AttestationMismatch));
        assert_eq!(a.verify(&Keypair::generate().public().signing, l, "f", n, b"result"), Err(SealError::BadSignature));
        let mut t = a.clone();
        t.digest = blake3::hash(b"forged").to_hex().to_string();
        assert_eq!(t.verify(&pk, l, "f", n, b"forged"), Err(SealError::BadSignature));
    }
}
