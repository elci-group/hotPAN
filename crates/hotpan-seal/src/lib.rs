//! Ephemeral authority for hotPAN.
//!
//! * [`Keypair`] — an ed25519 signing key plus an x25519 key-exchange key.
//!   Orchestrators keep one; nodes generate a fresh one per session and never
//!   persist it, so a node's authority cannot outlive its session.
//! * [`SignedLease`] — capability-scoped, ceiling-bounded, expiring authority
//!   to run exactly one fragment.
//! * [`Envelope`] — task and result payloads sealed to the recipient
//!   (X25519 + ChaCha20-Poly1305, bound to the lease id).
//! * [`Attestation`] — the node's signature over the digest of what it returned.

#![forbid(unsafe_code)]

mod attest;
mod envelope;
mod keys;
mod lease;

pub use attest::{attest, Attestation, AttestationKind};
pub use envelope::{open, seal, Envelope};
pub use keys::{
    hello_proof, pairing_proof, verify_hello_proof, verify_pairing_proof, verify_welcome_proof, welcome_proof, Keypair,
    PublicKeys,
};
pub use lease::{scopes_for, task_permitted, LeaseGrant, RevocationList, Scope, SignedLease};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SealError {
    #[error("malformed key or signature encoding: {0}")]
    Encoding(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("lease was issued by an unexpected orchestrator")]
    WrongIssuer,
    #[error("lease is bound to a different node")]
    WrongNode,
    #[error("lease expired at {0}")]
    Expired(u64),
    #[error("lease is not yet valid")]
    NotYetValid,
    #[error("lease has been revoked")]
    Revoked,
    #[error("envelope could not be opened")]
    Open,
    #[error("result digest does not match attestation")]
    DigestMismatch,
    #[error("attestation does not match lease")]
    AttestationMismatch,
    #[error("io: {0}")]
    Io(String),
}

pub(crate) fn decode32(s: &str) -> Result<[u8; 32], SealError> {
    let v = hex::decode(s).map_err(|e| SealError::Encoding(e.to_string()))?;
    v.try_into().map_err(|_| SealError::Encoding("expected 32 bytes".into()))
}
